"""Bind alert selectors to real exported metrics; promtool proves rule behavior."""

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from prometheus_client.parser import text_string_to_metric_families

from shadai.utils.metrics import operational_metrics
from shadai.utils.operations import STAGES, pipeline_snapshot, unavailable_pipeline

ROOT = Path(__file__).resolve().parents[1]
MONITORING = ROOT / 'deploy/monitoring'


class OperationalRedis:
    async def hgetall(self, key):
        return {'since': '1000', 'last_seen_at': '1598', 'last_poll_at': '1599',
                'last_progress_at': '1590', 'retryable_failures': '6', 'deadlettered': '1'}

    async def xinfo_groups(self, stream):
        group = next(group for group, streams in STAGES.values() if stream in streams)
        return [{'name': group, 'pending': 1, 'lag': 2}]

    async def xlen(self, stream):
        return 12

    async def xpending_range(self, *args):
        return [{'message_id': '1000000-0'}]


async def test_alert_selectors_exist_in_actual_export_and_publication_inventory_matches():
    snapshot = await pipeline_snapshot(OperationalRedis(), now=1600)
    families = list(text_string_to_metric_families(operational_metrics(snapshot).decode()))
    samples = {sample.name: sample for family in families for sample in family.samples}
    rules = yaml.safe_load((MONITORING / 'alerts.yaml').read_text())['groups'][0]['rules']
    for rule in rules:
        names = set(re.findall(r'(shadai_\w+)\{job="open-shadow-ai"\}', rule['expr']))
        assert names <= samples.keys(), f'{rule["alert"]} references unexported metrics: {names - samples.keys()}'
        for name in names:
            assert set(samples[name].labels) <= {'stage', 'stream'}
    publication = next(rule for rule in rules if rule['alert'] == 'ShadaiWorkerPublicationMissing')
    expected_count = int(re.search(r'count by\(job, instance\).*?== (\d+)', publication['expr']).group(1))
    assert expected_count == sum(len(streams) for _, streams in STAGES.values())
    assert len([sample for family in families for sample in family.samples
                if sample.name == 'shadai_worker_state_fresh']) == expected_count


def test_unavailable_snapshot_does_not_publish_queue_zeros_used_by_alerts():
    samples = {sample.name: sample.value
               for family in text_string_to_metric_families(operational_metrics(unavailable_pipeline()).decode())
               for sample in family.samples}
    assert samples == {'shadai_operations_redis_available': 0, 'shadai_operations_deployment_scope': 1}


def test_prometheus_loads_the_read_only_rule_mount_without_public_ports():
    config = yaml.safe_load((MONITORING / 'prometheus.yaml').read_text())
    compose = yaml.safe_load((ROOT / 'docker-compose.monitoring.yml').read_text())
    prometheus = compose['services']['prometheus']
    for mounted_path in config['rule_files']:
        mounts = [value.split(':') for value in prometheus['volumes'] if value.endswith(f':{mounted_path}:ro')]
        assert len(mounts) == 1 and (ROOT / mounts[0][0]).is_file()
    assert set(compose['services']) == {'api', 'prometheus'}
    assert 'ports' not in prometheus and prometheus['networks'] == ['backend']
    assert prometheus['user'] == '65534:65534'
    assert config['scrape_configs'][0]['authorization'] == {
        'type': 'Bearer', 'credentials_file': '/run/secrets/shadai_metrics_token'}


PROMTOOL_CI_CASES = [
    ('compose-integration', ['docker', 'run', '--rm'], 'monitoring', 'alerts.test.yaml', 'prometheus_image'),
    ('production-qualification', ['docker', '--context', 'default', 'run', '--rm'],
     'host-monitoring', 'rules.test.yaml', 'image'),
]


def ci_promtool_command(job, image_variable):
    workflow = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
    run, = [step['run'] for step in workflow['jobs'][job]['steps']
            if '--entrypoint /bin/promtool' in step.get('run', '')]
    assert f'{image_variable}="$(python scripts/verify-image-pins.py --reference prometheus)"' in run
    command, = [shlex.split(line) for line in run.splitlines()
                if line.strip().startswith('docker ') and '--entrypoint /bin/promtool' in line]
    return command


def assert_ci_promtool_scratch(command, prefix, directory, fixture, image_variable):
    assert command[:len(prefix)] == prefix
    assert command.count('--network') == 1 and command[command.index('--network') + 1] == 'none'
    assert '--read-only' in command and not any(value.startswith(('--privileged', '--cap-add')) for value in command)
    assert command.count('--tmpfs') == 1
    target, options = command[command.index('--tmpfs') + 1].split(':', 1)
    assert target == '/tmp' and set(options.split(',')) == {'rw', 'noexec', 'nosuid', 'nodev', 'size=128m'}
    assert command.count('--entrypoint') == 1 and command[command.index('--entrypoint') + 1] == '/bin/promtool'
    assert command.count('--mount') == 1
    assert set(command[command.index('--mount') + 1].split(',')) == {
        'type=bind', f'src=$PWD/deploy/{directory}', f'dst=/workspace/deploy/{directory}', 'readonly'}
    assert command[-4:] == [f'${image_variable}', 'test', 'rules', f'/workspace/deploy/{directory}/tests/{fixture}']


@pytest.mark.parametrize('job,prefix,directory,fixture,image_variable', PROMTOOL_CI_CASES)
def test_ci_promtool_scratch_is_bounded_and_keeps_container_and_rules_private(
        job, prefix, directory, fixture, image_variable):
    reference = yaml.safe_load((ROOT / 'requirements/images.json').read_text())['prometheus']['reference']
    assert reference == ('prom/prometheus:v3.15.0@sha256:'
                         'efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e')
    compose = yaml.safe_load((ROOT / 'docker-compose.monitoring.yml').read_text())
    assert compose['services']['prometheus']['image'] == reference
    command = ci_promtool_command(job, image_variable)
    assert_ci_promtool_scratch(command, prefix, directory, fixture, image_variable)


@pytest.mark.parametrize('job,prefix,directory,fixture,image_variable', PROMTOOL_CI_CASES)
@pytest.mark.parametrize('defect', ['tmpfs_missing', 'tmpfs_permissions', 'tmpfs_unbounded',
                                  'network', 'root_writable', 'rules_writable'])
def test_ci_promtool_scratch_contract_refuses_unsafe_mutations(
        job, prefix, directory, fixture, image_variable, defect):
    command = ci_promtool_command(job, image_variable)
    if defect == 'tmpfs_missing':
        position = command.index('--tmpfs')
        del command[position:position + 2]
    elif defect == 'tmpfs_permissions':
        command[command.index('--tmpfs') + 1] = '/tmp:rw,exec,suid,dev,size=128m'
    elif defect == 'tmpfs_unbounded':
        command[command.index('--tmpfs') + 1] = '/tmp:rw,noexec,nosuid,nodev'
    elif defect == 'network':
        command[command.index('--network') + 1] = 'bridge'
    elif defect == 'root_writable':
        command.remove('--read-only')
    else:
        position = command.index('--mount') + 1
        command[position] = command[position].replace(',readonly', '')
    with pytest.raises(AssertionError):
        assert_ci_promtool_scratch(command, prefix, directory, fixture, image_variable)


def test_promtool_rule_scenarios():
    executable = os.environ.get('PROMTOOL') or shutil.which('promtool')
    if not executable:
        if os.environ.get('SHADAI_REQUIRE_PROMTOOL') == '1':
            pytest.fail('promtool is required; install the deployed Prometheus tool or use its CI container')
        pytest.skip('promtool unavailable; CI must run deploy/monitoring/tests/alerts.test.yaml with its image')
    for arguments in (
        ['check', 'config', '--syntax-only', str(MONITORING / 'prometheus.yaml')],
        ['check', 'rules', '--lint-fatal', str(MONITORING / 'alerts.yaml')],
        ['test', 'rules', str(MONITORING / 'tests/alerts.test.yaml')],
    ):
        result = subprocess.run([executable, *arguments], capture_output=True, text=True, timeout=60, cwd=ROOT)
        assert result.returncode == 0, result.stdout + result.stderr
