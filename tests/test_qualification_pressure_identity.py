"""Pressure one-off identity and disposal with actual Docker CLI parsing boundaries."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadai.qualification.journal import LABEL, RunJournal, resource_identity, verify_resource
from shadai.qualification.lab import Docker, DockerOperationError, Laboratory
from shadai.qualification.schemas import QualificationError, load_profile

ROOT = Path(__file__).resolve().parents[1]
TEST_NAMES = ('test_required_pressure_and_aof_phase',
              'test_real_redis_oom_before_allocation_and_owned_release_recovers')


class PressureDocker:
    def __init__(self, lab, *, output='#1 build progress\n<ID>\n#2 completed'):
        self.lab, self.output = lab, output
        self.containers, self.calls, self.names = {}, [], {}
        self.corrupt, self.target, self.wait_error, self.after_wait = None, 'seed', None, None

    def inspection(self, mode, name):
        role = 'source' if mode == 'seed' else 'restore'
        return {'Id': ('a' if mode == 'seed' else 'c') * 64, 'Name': '/' + name,
                'Created': '2026-10-06T00:00:00Z', 'Image': 'sha256:' + 'b' * 64,
                'Config': {'Labels': {LABEL + 'run': self.lab.journal.value['run_id'], LABEL + 'role': 'pressure',
                                      'com.docker.compose.project': self.lab.journal.value['projects'][role],
                                      'com.docker.compose.service':
                                          'pressure-test' if mode == 'seed' else 'pressure-assert'}}}

    def runner(self, command, **kwargs):
        assert command[:3] == ['docker', '--context', 'pressure-test-context']
        args = command[3:]
        self.calls.append(tuple(args))
        if args[0] == 'compose':
            if 'up' in args:
                return SimpleNamespace(returncode=0, stdout='restore startup progress', stderr='')
            assert args[7:11] == ['run', '--build', '--no-deps', '-d']
            name = args[args.index('--name') + 1]
            mode = 'assert' if name.endswith('-assert') else 'seed'
            current = self.inspection(mode, name)
            identifier = current['Id']
            if mode == self.target and self.corrupt:
                if self.corrupt in {'Id', 'Name', 'Image', 'Created'}:
                    current[self.corrupt] = '' if self.corrupt == 'Created' else 'invalid'
                else:
                    current['Config']['Labels'][self.corrupt] = 'foreign'
            self.containers[identifier], self.names[name] = current, identifier
            return SimpleNamespace(returncode=0, stdout=self.output.replace('<ID>', identifier), stderr='')
        assert args[0] == 'container'
        operation, identifier = args[1:3]
        if operation == 'inspect':
            identifier = self.names.get(identifier, identifier)
            if identifier not in self.containers:
                return SimpleNamespace(returncode=1, stdout='', stderr='No such container')
            return SimpleNamespace(returncode=0, stdout=json.dumps([self.containers[identifier]]), stderr='')
        assert identifier in self.containers and len(identifier) == 64
        if operation == 'wait':
            assert kwargs['timeout'] == 180
            assert any(record['id'] == identifier for record in self.lab.journal.value['resources'])
            mode = 'seed' if identifier == 'a' * 64 else 'assert'
            if mode == self.target and self.after_wait:
                self.after_wait(self.containers[identifier])
            if mode == self.target and self.wait_error:
                raise self.wait_error
            return SimpleNamespace(returncode=0, stdout='0', stderr='')
        assert operation == 'rm'
        self.containers.pop(identifier)
        return SimpleNamespace(returncode=0, stdout=identifier, stderr='')


@pytest.fixture
def pressure(tmp_path, monkeypatch):
    profile = load_profile(ROOT / 'deploy/qualification/profiles/lab-smoke.json')
    lab = Laboratory(ROOT, tmp_path / 'run', profile, 'pressure-test-context')
    lab.journal = RunJournal.create(lab.directory, profile, lab.config_hash, lab.context)
    monkeypatch.setattr(lab, 'environment', lambda role: {})
    monkeypatch.setattr(lab, 'change', Mock())
    monkeypatch.setattr(lab, 'archive_store', Mock(return_value={'archive': 'owned-cold-clone'}))
    monkeypatch.setattr(lab, 'fresh_restore_volume', Mock())
    monkeypatch.setattr(lab, 'discover', Mock())
    monkeypatch.setattr(lab, 'record', Mock())
    for directory, filename in [('pressure-artifacts', 'pressure-seed.xml'),
                                ('pressure-reports', 'pressure-assert.xml')]:
        folder = lab.directory / directory
        folder.mkdir()
        content = '<testsuite>' + ''.join(f'<testcase name="{name}"/>' for name in TEST_NAMES) + '</testsuite>'
        (folder / filename).write_text(content)
    cli = PressureDocker(lab)
    lab.docker = Docker(lab.context, runner=cli.runner)
    return lab, cli


@pytest.mark.parametrize('output', ['<ID>', '#1 building\n<ID>', '<ID>\n#2 done', 'f' * 64])
def test_both_pressure_phases_use_verified_id_despite_build_stdout(pressure, output):
    lab, cli = pressure
    cli.output = output
    lab.experiment_redis_pressure('synthetic unused URL')
    assert not cli.containers and not lab.journal.value['resources']
    actions = [args for args in cli.calls if args[:2] in {('container', 'wait'), ('container', 'rm')}]
    assert actions == [('container', 'wait', 'a' * 64), ('container', 'rm', 'a' * 64),
                       ('container', 'wait', 'c' * 64), ('container', 'rm', 'c' * 64)]
    evidence = lab.record.call_args.kwargs
    assert evidence['maxmemory_bytes'] == 33554432 and evidence['policy'] == 'noeviction'
    assert evidence['aof_cold_clone'] is True and all(phase['skipped'] == 0 for phase in evidence['phases'])


@pytest.mark.parametrize('mode', ['seed', 'assert'])
@pytest.mark.parametrize('corrupt', [LABEL + 'run', LABEL + 'role', 'com.docker.compose.project',
                                     'com.docker.compose.service', 'Id', 'Name', 'Image', 'Created'])
def test_forged_pressure_identity_is_never_journaled_waited_or_removed(pressure, mode, corrupt):
    lab, cli = pressure
    cli.target, cli.corrupt = mode, corrupt
    with pytest.raises(QualificationError):
        lab.experiment_redis_pressure('unused')
    identifier = ('a' if mode == 'seed' else 'c') * 64
    assert identifier in cli.containers
    assert not any(record['id'] == identifier for record in lab.journal.value['resources'])
    assert not any(args[:2] in {('container', 'wait'), ('container', 'rm')} and args[2] == identifier
                   for args in cli.calls)


@pytest.mark.parametrize('mode', ['seed', 'assert'])
def test_preexisting_name_collision_is_not_adopted_or_deleted(pressure, mode):
    lab, cli = pressure
    role = 'source' if mode == 'seed' else 'restore'
    name = lab.journal.value['projects'][role] + '-pressure-' + mode
    existing = cli.inspection(mode, name)
    existing['Config']['Labels'][LABEL + 'run'] = 'foreign'
    cli.names[name], cli.containers[existing['Id']] = existing['Id'], existing
    with pytest.raises(QualificationError, match='already exists'):
        lab.experiment_redis_pressure('unused')
    assert cli.containers[existing['Id']] == existing
    assert not any(args[0] == 'compose' and 'run' in args and name in args for args in cli.calls)
    assert not any(args[:2] == ('container', 'rm') and args[2] == existing['Id'] for args in cli.calls)


@pytest.mark.parametrize('mode', ['seed', 'assert'])
@pytest.mark.parametrize('error', [DockerOperationError('docker_nonzero', 17), KeyboardInterrupt(), SystemExit(2)])
def test_pressure_wait_error_or_cancellation_cleans_verified_helper(pressure, mode, error):
    lab, cli = pressure
    cli.target, cli.wait_error = mode, error
    with pytest.raises(type(error)) as raised:
        lab.experiment_redis_pressure('unused')
    assert raised.value is error
    assert not cli.containers and not lab.journal.value['resources']
    assert not lab.record.called


@pytest.mark.parametrize('field', ['Name', 'Image', 'labels'])
def test_changed_helper_is_retained_and_cleanup_refusal_preserves_primary(pressure, field):
    lab, cli = pressure
    primary = DockerOperationError('docker_nonzero', 17)
    cli.wait_error = primary
    cli.after_wait = lambda value: value['Config']['Labels'].update({LABEL + 'role': 'foreign'}) if field == 'labels' \
        else value.update({field: 'foreign'})
    with pytest.raises(DockerOperationError) as raised:
        lab.experiment_redis_pressure('unused')
    assert raised.value is primary and primary.__notes__ == [
        'Pressure helper cleanup refused; owned journal record retained']
    assert 'a' * 64 in cli.containers and len(lab.journal.value['resources']) == 1
    assert not any(args[:2] == ('container', 'rm') for args in cli.calls)


def test_cleanup_refusal_after_wait_success_fails_closed(pressure):
    lab, cli = pressure
    cli.after_wait = lambda value: value.update({'Name': '/foreign-name'})
    with pytest.raises(QualificationError, match='name or image changed|Resource was replaced'):
        lab.experiment_redis_pressure('unused')
    assert 'a' * 64 in cli.containers and len(lab.journal.value['resources']) == 1
    assert not lab.record.called and not any(args[:2] == ('container', 'rm') for args in cli.calls)


def admitted_helper(pressure, service):
    lab, cli = pressure
    name = lab.journal.value['projects']['source'] + '-owned-helper'
    current = cli.inspection('seed', name)
    current['State'] = {'Running': False}
    current['Config']['Labels']['com.docker.compose.service'] = service
    role = 'source' if service == 'inspector' else 'pressure'
    current['Config']['Labels'][LABEL + 'role'] = role
    cli.names[name], cli.containers[current['Id']] = current['Id'], current
    record = resource_identity('container', current, lab.journal.value['run_id'], role,
                               lab.journal.value['projects']['source'])
    lab.journal.add_resources([record])
    return lab, cli, current, record


@pytest.mark.parametrize('service', ['inspector', 'pressure-test', 'pressure-assert'])
@pytest.mark.parametrize('field', ['Name', 'Image'])
@pytest.mark.parametrize('resume', [False, True])
def test_changed_helper_proof_blocks_later_clean_and_resumed_cleanup(pressure, service, field, resume):
    lab, cli, current, record = admitted_helper(pressure, service)
    assert record['name'] == current['Name'] and record['image'] == current['Image']
    current[field] = '/foreign-name' if field == 'Name' else 'sha256:' + 'f' * 64
    if resume:
        lab.journal = RunJournal.resume(lab.directory, lab.profile, lab.config_hash, lab.context)
    with pytest.raises(QualificationError, match='replaced or changed'):
        lab.clean(execute=True)
    assert current['Id'] in cli.containers and lab.journal.value['resources'] == [record]
    assert not any(args[:2] in {('container', 'stop'), ('container', 'rm')} for args in cli.calls)


@pytest.mark.parametrize('service', ['inspector', 'pressure-test', 'pressure-assert'])
@pytest.mark.parametrize('resume', [False, True])
def test_unchanged_helper_journal_removes_only_verified_immutable_id(pressure, service, resume):
    lab, cli, current, record = admitted_helper(pressure, service)
    if resume:
        lab.journal = RunJournal.resume(lab.directory, lab.profile, lab.config_hash, lab.context)
        lab.clean(execute=True)
    else:
        lab.remove(record)
    assert not cli.containers and not lab.journal.value['resources']
    assert [args for args in cli.calls if args[:2] == ('container', 'rm')] == [
        ('container', 'rm', current['Id'])]


@pytest.mark.parametrize('service', ['inspector', 'pressure-test', 'pressure-assert'])
@pytest.mark.parametrize('action', ['resume', 'clean', 'remove'])
@pytest.mark.parametrize('present', [False, True])
def test_legacy_helper_journal_without_admission_proof_is_refused(pressure, service, action, present):
    lab, cli, current, record = admitted_helper(pressure, service)
    record.pop('name')
    record.pop('image')
    lab.journal.save()
    if not present:
        cli.containers.pop(current['Id'])
    with pytest.raises(QualificationError, match='missing its exact name/image'):
        if action == 'resume':
            RunJournal.resume(lab.directory, lab.profile, lab.config_hash, lab.context)
        elif action == 'clean':
            lab.clean(execute=True)
        else:
            lab.remove(record)
    assert (current['Id'] in cli.containers) is present and lab.journal.value['resources'] == [record]
    assert not any(args[:2] == ('container', 'rm') for args in cli.calls)


def test_nonhelper_resource_identity_contract_is_unchanged(pressure):
    lab, cli = pressure
    current = cli.inspection('seed', '/synthetic-api')
    current['Config']['Labels']['com.docker.compose.service'] = 'api'
    current['Config']['Labels'][LABEL + 'role'] = 'source'
    record = resource_identity('container', current, lab.journal.value['run_id'], 'source',
                               lab.journal.value['projects']['source'])
    assert 'name' not in record and 'image' not in record
    current.update({'Name': '/other-api-name', 'Image': 'sha256:' + 'f' * 64})
    assert verify_resource(record, current) == record
