"""Exercise scanner orchestration with real inventory gates and bounded fake I/O."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCAN = load('scan-images')
PINS = load('verify-image-pins')
AUDIT = load('audit-dependencies')
COMMIT = 'a' * 40
REPOSITORY = 'example/shadai'
MANIFEST = 'sha256:' + 'b' * 64
CONFIG = 'sha256:' + 'c' * 64


@pytest.fixture
def harness(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    shutil.copytree(ROOT / 'requirements', root / 'requirements')
    shutil.copytree(ROOT / 'deploy/service-builds', root / 'deploy/service-builds')
    archive = tmp_path / 'input.oci.tar'
    archive.write_bytes(b'synthetic external OCI boundary')
    output = tmp_path / 'reports'
    output.mkdir()
    calls = []
    state = SimpleNamespace(component='redis', mutate=None, error=None, drift_at=None, cleanup_error=None)
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    layout = tmp_path / 'private-workspace/layout'
    layout.mkdir(parents=True)

    def inventory():
        purls = ['pkg:apk/alpine/libcrypto3@3.5.9-r0']
        if state.component in {'postgres', 'node-exporter'}:
            purls.append('pkg:golang/stdlib@go1.26.6')
        elif state.component in PINS.APP_IMAGES and state.component != 'frontend':
            environment = AUDIT.default_environment()
            environment.update({'sys_platform': 'linux', 'os_name': 'posix', 'platform_system': 'Linux',
                                'platform_machine': 'amd64', 'python_version': '3.12',
                                'python_full_version': '3.12.15', 'implementation_name': 'cpython',
                                'platform_python_implementation': 'CPython'})
            lock = root / 'requirements' / ('development.txt' if state.component == 'test' else 'runtime.txt')
            purls += [f'pkg:pypi/{name}@{version}'
                      for name, version in AUDIT.expected_python(lock, environment).items()]
        return purls

    def unchanged():
        calls.append('check')
        if calls.count('check') == state.drift_at:
            raise ValueError('synthetic layout drift')
        return {'archive_sha256': archive_hash, 'layout_table_sha256': 'd' * 64, 'helper_sha256': 'e' * 64,
                'source': {'commit': COMMIT, 'repository': REPOSITORY}, 'platform': 'linux/amd64',
                'component': state.component, 'image_manifest': MANIFEST, 'image_config': CONFIG}

    @contextmanager
    def prepared_layout(path, *, platform, scratch_parent, expected_source, expected_component):
        calls.append('prepare')
        assert path == archive and platform == 'linux/amd64'
        assert scratch_parent == root / 'tmp/production-delivery'
        assert expected_source == {'commit': COMMIT, 'repository': REPOSITORY}
        assert expected_component == state.component
        sbom = {'packages': [{'externalRefs': [{'referenceType': 'purl', 'referenceLocator': p}]} for p in inventory()]}
        handle = SimpleNamespace(layout_path=layout, container_input='/input/layout', assert_unchanged=unchanged,
                                 evidence={'archive_sha256': archive_hash, 'image_manifests': [MANIFEST],
                                           'image_configs': {MANIFEST: CONFIG}, 'sboms': {MANIFEST: sbom}})
        try:
            yield handle
        finally:
            calls.append('cleanup')
            if state.cleanup_error:
                raise state.cleanup_error

    def docker(command, **kwargs):
        calls.append('trivy')
        assert command[0:3] == ['docker', 'run', '--rm'] and kwargs == {'check': True}
        assert command[command.index('--input') + 1] == '/input/layout'
        mounts = [command[i + 1] for i, part in enumerate(command) if part == '--mount']
        assert f'type=bind,src={layout.resolve()},dst=/input/layout,readonly' in mounts
        assert not any(str(archive.parent.resolve()) in mount for mount in mounts if 'dst=/input,' in mount)
        assert not (output / f'{state.component}.metadata.json').exists()
        if state.error:
            raise state.error
        packages = []
        for purl in inventory():
            _, name, version = SCAN.package_key(purl)
            packages.append({'Name': name, 'Version': 'go1.26.6' if name == 'stdlib' else version,
                             'Identifier': {'PURL': purl}})
        report = {'SchemaVersion': 2, 'ArtifactType': 'container_image', 'ArtifactName': '/input/layout',
                  'Trivy': {'Version': SCAN.TRIVY_VERSION},
                  'Metadata': {'ImageID': CONFIG, 'ImageConfig': {'os': 'linux', 'architecture': 'amd64'}},
                  'Results': [{'Target': 'synthetic runtime', 'Class': 'os-pkgs', 'Type': 'alpine',
                               'Packages': packages, 'Vulnerabilities': []}]}
        if state.mutate:
            state.mutate(report)
        (output / f'{state.component}.json').write_text(json.dumps(report))

    monkeypatch.setattr(SCAN, 'ROOT', root)
    modules = {'verify-image-pins': PINS, 'audit-dependencies': AUDIT,
               'oci_scan_layout': SimpleNamespace(prepared_layout=prepared_layout)}
    monkeypatch.setattr(SCAN, 'script', lambda name: modules[name])
    monkeypatch.setattr(SCAN.subprocess, 'run', docker)
    monkeypatch.setattr(SCAN.subprocess, 'check_output', lambda command, **kwargs:
                        COMMIT if command[1:3] == ['rev-parse', 'HEAD'] else '')

    def run(component='redis'):
        state.component = component
        monkeypatch.setattr(sys, 'argv', ['scan-images.py', '--input', str(archive), '--image', component,
                                         '--platform', 'linux/amd64', '--source-commit', COMMIT,
                                         '--repository', REPOSITORY, '--output', str(output)])
        SCAN.main()

    return SimpleNamespace(run=run, calls=calls, state=state, output=output, archive_hash=archive_hash)


@pytest.mark.parametrize('component', [*PINS.APP_IMAGES, *PINS.SERVICES])
def test_every_runtime_scans_readonly_layout_and_binds_postcheck_metadata(harness, component):
    harness.run(component)
    assert harness.calls == ['prepare', 'check', 'trivy', 'check', 'cleanup']
    metadata = json.loads((harness.output / f'{component}.metadata.json').read_text())
    assert metadata['subject']['archive_sha256'] == harness.archive_hash
    assert metadata['source_commit'] == COMMIT and metadata['repository'] == REPOSITORY
    assert metadata['oci_layout']['helper_sha256'] == 'e' * 64
    assert metadata['oci_layout']['layout_table_sha256'] == 'd' * 64
    assert metadata['oci_layout']['image_config'] == CONFIG
    assert metadata['command'][-2:] == ['--input', '/input/layout']


@pytest.mark.parametrize('error', [subprocess.CalledProcessError(19, ['synthetic']), KeyboardInterrupt()])
def test_scan_error_or_handled_cancellation_preserves_primary_and_cleans(harness, error):
    harness.state.error = error
    with pytest.raises(type(error)) as raised:
        harness.run()
    assert raised.value is error
    assert harness.calls == ['prepare', 'check', 'trivy', 'cleanup']
    assert not (harness.output / 'redis.metadata.json').exists()


@pytest.mark.parametrize('phase', [1, 2])
def test_pre_or_post_tamper_rejects_without_stale_success_sidecar(harness, phase):
    harness.state.drift_at = phase
    (harness.output / 'redis.json').write_text('{}')
    (harness.output / 'redis.metadata.json').write_text('{"invocation":"old"}')
    with pytest.raises(ValueError, match='layout drift'):
        harness.run()
    assert harness.calls[-1] == 'cleanup'
    assert ('trivy' in harness.calls) is (phase == 2)
    assert not (harness.output / 'redis.metadata.json').exists()


def test_cleanup_refusal_after_scan_cannot_publish_success_metadata(harness):
    harness.state.cleanup_error = ValueError('OCI cleanup refused')
    with pytest.raises(ValueError, match='OCI cleanup refused'):
        harness.run()
    assert harness.calls == ['prepare', 'check', 'trivy', 'check', 'cleanup']
    assert not (harness.output / 'redis.metadata.json').exists()


@pytest.mark.parametrize('component', [*PINS.APP_IMAGES, *PINS.SERVICES])
@pytest.mark.parametrize('mutation', ['artifact', 'config', 'platform'])
def test_report_subject_and_platform_are_strict_for_every_runtime(harness, component, mutation):
    def change(report):
        if mutation == 'artifact':
            report['ArtifactName'] = '/input/input.oci.tar'
        elif mutation == 'config':
            report['Metadata']['ImageID'] = 'sha256:' + 'f' * 64
        else:
            report['Metadata']['ImageConfig']['architecture'] = 'arm64'
    harness.state.mutate = change
    with pytest.raises(ValueError, match='subject mismatch|platform mismatch'):
        harness.run(component)
    assert harness.calls[-1] == 'cleanup'
    assert not (harness.output / f'{component}.metadata.json').exists()


@pytest.mark.parametrize('mutation', ['missing_package', 'purl_mismatch'])
def test_complete_inventory_and_purl_version_are_not_bypassed_by_bridge(harness, mutation):
    def change(report):
        packages = report['Results'][0]['Packages']
        if mutation == 'missing_package':
            packages.pop()
        else:
            packages[0]['Identifier']['PURL'] = 'pkg:apk/alpine/libcrypto3@3.5.0-r0'
    harness.state.mutate = change
    with pytest.raises(ValueError, match='complete|inventory identifier'):
        harness.run()
    assert harness.calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()
