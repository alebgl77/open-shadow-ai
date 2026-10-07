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
COMPONENTS = load('component_scanner')
SOURCE = load('component_source')
PRINCIPAL = load('component_principal')
EVIDENCE = load('verify-scan-evidence')
MODEL_SPEC = importlib.util.spec_from_file_location('component_scan_models', ROOT / 'tests/component_scan_models.py')
MODELS = importlib.util.module_from_spec(MODEL_SPEC)
MODEL_SPEC.loader.exec_module(MODELS)
COMMIT = 'a' * 40
REPOSITORY = 'example/shadai'
MANIFEST = 'sha256:' + 'b' * 64
CONFIG = 'sha256:' + 'c' * 64


@pytest.fixture
def harness(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    shutil.copytree(ROOT / 'requirements', root / 'requirements')
    shutil.copytree(ROOT / 'deploy/service-builds', root / 'deploy/service-builds')
    shutil.copytree(ROOT / 'scripts', root / 'scripts')
    (root / '.github/workflows').mkdir(parents=True)
    shutil.copy2(ROOT / '.github/workflows/ci.yml', root / '.github/workflows/ci.yml')
    shutil.copy2(ROOT / '.dockerignore', root / '.dockerignore')
    archive = tmp_path / 'input.oci.tar'
    archive.write_bytes(b'synthetic external OCI boundary')
    output = tmp_path / 'reports'
    output.mkdir()
    calls = []
    state = SimpleNamespace(component='redis', mutate=None, sbom_mutate=None, error=None, drift_at=None,
                            cleanup_error=None, grype_error=None, grype_cleanup_error=None, grype_mutate=None,
                            grype_calls=[], source_mutate=None, grype_post_error=None, query_effect=None)
    state.principal_mutate = None
    state.principal_missing = False
    state.cleanup_effect = None
    state.raw_query_effect = None
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    layout = tmp_path / 'private-workspace/layout'
    layout.mkdir(parents=True)

    def component_fixture():
        return MODELS.capture(state.component)

    def sbom_inventory():
        if state.component in {'postgres', 'node-exporter', 'redis', 'clickhouse'}:
            return component_fixture()['sbom']
        packages = [{'externalRefs': [{'referenceType': 'purl', 'referenceLocator': p}],
                     'SPDXID': f'SPDXRef-native-{i}', 'versionInfo': SCAN.package_key(p)[2]}
                    for i, p in enumerate(inventory())]
        if state.component == 'clickhouse':
            packages.append({'name': 'sbom', 'SPDXID': COMPONENTS.DOCUMENT_ROOT, 'supplier': 'NOASSERTION',
                             'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False,
                             'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
                             'copyrightText': 'NOASSERTION', 'primaryPackagePurpose': 'FILE'})
        return {'packages': packages, 'files': [], 'relationships': [
            {'spdxElementId': COMPONENTS.DOCUMENT_ROOT, 'relatedSpdxElement': p['SPDXID'],
             'relationshipType': 'CONTAINS'} for p in packages if p['SPDXID'] != COMPONENTS.DOCUMENT_ROOT]}

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
        sbom = sbom_inventory()
        if state.sbom_mutate:
            state.sbom_mutate(sbom)
        state.original_sbom = sbom
        handle = SimpleNamespace(layout_path=layout, container_input='/input/layout', assert_unchanged=unchanged,
                                 evidence={'archive_sha256': archive_hash, 'image_manifests': [MANIFEST],
                                           'image_configs': {MANIFEST: CONFIG}, 'sboms': {MANIFEST: sbom}})
        try:
            yield handle
        finally:
            calls.append('cleanup')
            if state.cleanup_effect:
                state.cleanup_effect()
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
        if state.component in {'postgres', 'node-exporter', 'redis', 'clickhouse'}:
            report = component_fixture()['trivy']
            report['Metadata']['ImageID'] = CONFIG
        else:
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

    def subject_documents(handle, image_manifest):
        result = MODELS.documents(component_fixture(), {'commit': COMMIT, 'repository': REPOSITORY})
        if state.source_mutate:
            state.source_mutate(result)
        return result

    @contextmanager
    def prepared_grype(**kwargs):
        state.grype_calls.append('prepare')
        assert kwargs['platform'] == 'linux/amd64' and kwargs['manifest_path'] == root / \
            'requirements/component-scanner.json'
        receipt = MODELS.runtime_receipt(root)
        runtime = SimpleNamespace(configuration=receipt['configuration'], database_status=receipt['database']['status'])

        def query(identifier, path):
            state.grype_calls.append(identifier)
            assert not (output / f'{state.component}.metadata.json').exists()
            if state.grype_error:
                raise state.grype_error
            control = {'cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*': 'CVE-2021-32675',
                       'pkg:golang/golang.org/x/crypto@0.1.0': 'GO-2023-2402'}
            value = MODELS.query_report(identifier, receipt, advisory=control.get(identifier))
            if state.grype_mutate:
                state.grype_mutate(value, identifier)
            if state.query_effect:
                state.query_effect()
            path.write_text(json.dumps(value))
            if state.raw_query_effect:
                state.raw_query_effect(path)
            return value

        runtime.run_query = query
        def unchanged_runtime():
            if state.grype_post_error:
                raise state.grype_post_error
            return receipt
        runtime.assert_unchanged = unchanged_runtime
        primary = None
        try:
            yield runtime
        except BaseException as error:
            primary = error
            raise
        finally:
            state.grype_calls.append('cleanup')
            assert not (output / f'{state.component}.metadata.json').exists()
            if state.grype_cleanup_error:
                if primary is None:
                    raise state.grype_cleanup_error
                primary.add_note('owned_cleanup_failed')

    monkeypatch.setattr(SCAN, 'ROOT', root)
    modules = {'verify-image-pins': PINS, 'audit-dependencies': AUDIT,
               'oci_scan_layout': SimpleNamespace(prepared_layout=prepared_layout),
               'component_scanner': COMPONENTS, 'grype_runtime': SimpleNamespace(prepared_grype=prepared_grype),
               'component_source': SimpleNamespace(subject_documents=subject_documents, bind=SOURCE.bind,
                                                    bind_clickhouse=SOURCE.bind_clickhouse),
               'component_principal': PRINCIPAL, 'verify-scan-evidence': EVIDENCE}
    monkeypatch.setattr(SCAN, 'script', lambda name: modules[name])
    monkeypatch.setattr(SCAN.subprocess, 'run', docker)
    monkeypatch.setattr(SCAN.subprocess, 'check_output', lambda command, **kwargs:
                        COMMIT if command[1:3] == ['rev-parse', 'HEAD'] else '')
    monkeypatch.setenv('GITHUB_RUN_ID', '37537893022')
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    monkeypatch.setenv('GITHUB_JOB', 'derived-service-builds')

    def run(component='redis'):
        state.component = component
        if component == 'clickhouse' and not state.principal_missing:
            fixture = component_fixture()
            principal = MODELS.principal_receipt(subject={'archive_sha256': archive_hash, 'image_manifest': MANIFEST,
                'image_config': CONFIG, 'platform': 'linux/amd64'}, config=fixture['config'],
                source={'commit': COMMIT, 'repository': REPOSITORY},
                ci={'run_id': '37537893022', 'run_attempt': '1', 'job': 'derived-service-builds'}, root=root)
            if state.principal_mutate:
                state.principal_mutate(principal)
            (output / 'clickhouse.principal-observation.json').write_text(json.dumps(principal))
        monkeypatch.setattr(sys, 'argv', ['scan-images.py', '--input', str(archive), '--image', component,
                                         '--platform', 'linux/amd64', '--source-commit', COMMIT,
                                         '--repository', REPOSITORY, '--output', str(output)])
        SCAN.main()

    return SimpleNamespace(run=run, calls=calls, state=state, output=output, archive_hash=archive_hash, root=root,
                           documents=subject_documents, archive=archive)


@pytest.mark.parametrize('component', [*PINS.APP_IMAGES, *PINS.SERVICES])
def test_every_runtime_scans_readonly_layout_and_binds_postcheck_metadata(harness, component):
    harness.run(component)
    assert harness.calls == ['prepare', 'check', 'trivy', 'check',
                             *(['check'] if component in PINS.SERVICES else []), 'cleanup']
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
    assert harness.calls == ['prepare', 'check', 'trivy', 'check', 'check', 'cleanup']
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
    with pytest.raises(ValueError, match='exact package inventory|inventory identifier'):
        harness.run()
    assert harness.calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


@pytest.mark.parametrize('component,purl,error', [
    ('node-exporter', 'pkg:generic/busybox@1.38.0', 'Malformed component inventory'),
    ('postgres', 'pkg:golang/github.com/tianon/gosu', 'Malformed component inventory'),
])
def test_rejected_actual_sbom_shapes_retain_raw_scan_without_accepted_sidecar(harness, component, purl, error):
    def change(sbom):
        sbom['packages'].append({'externalRefs': [{'referenceType': 'purl', 'referenceLocator': purl}]})
    harness.state.sbom_mutate = change
    (harness.output / f'{component}.metadata.json').write_text('{"invocation":"old"}')
    with pytest.raises(ValueError, match=error):
        harness.run(component)
    assert harness.calls == ['prepare', 'check', 'trivy', 'check', 'cleanup']
    raw = json.loads((harness.output / f'{component}.json').read_text())
    assert raw['Metadata']['ImageID'] == CONFIG
    assert not (harness.output / f'{component}.metadata.json').exists()


def test_incomplete_native_lock_closure_still_rejects_after_retaining_raw_scan(harness):
    def change(sbom):
        sbom['packages'] = [package for package in sbom['packages']
                            if not package['externalRefs'][0]['referenceLocator'].startswith('pkg:pypi/')]
    harness.state.sbom_mutate = change
    with pytest.raises(ValueError, match='complete native runtime hash-lock closure'):
        harness.run('test')
    assert harness.calls == ['prepare', 'check', 'trivy', 'check', 'cleanup']
    assert (harness.output / 'test.json').is_file()
    assert not (harness.output / 'test.metadata.json').exists()


@pytest.mark.parametrize('component,count', [('postgres', 3), ('node-exporter', 4), ('redis', 2), ('clickhouse', 1)])
def test_exact_native_capture_complement_queries_and_original_unknown_are_bound(harness, component, count):
    harness.run(component)
    metadata = json.loads((harness.output / f'{component}.metadata.json').read_bytes())
    complement = metadata['complement']
    assert len(complement['sentinels']) == 2 and len(complement['receipts']) == count
    assert harness.state.grype_calls[0] == 'prepare' and harness.state.grype_calls[-1] == 'cleanup'
    assert len(harness.state.grype_calls) == count + 4
    for claim in complement['components']:
        if claim['observed_unversioned']:
            assert claim['binary_version_claim'] is None
            assert claim['original_package']['versionInfo'] == 'UNKNOWN'
            assert claim['source_proof']['authenticated_provenance'] is False
    assert metadata['verdict'] == 'passed' and metadata['findings'] == []


@pytest.mark.parametrize('mutation', ['echo', 'config', 'db', 'providers', 'ignored', 'sentinel'])
def test_failed_tool_configuration_database_or_control_has_raw_only(harness, mutation):
    def change(report, query):
        if mutation == 'echo':
            report['source']['target'] += '-foreign'
        elif mutation == 'config':
            report['descriptor']['configuration'] = {'only-fixed': True}
        elif mutation == 'db':
            report['descriptor']['db']['status'] = {'valid': False}
        elif mutation == 'providers' and query.startswith('pkg:'):
            report['descriptor']['db']['providers'] = {'changed-provider': {}}
        elif mutation == 'ignored':
            report['ignoredMatches'] = [{'reason': 'hidden'}]
        elif mutation == 'sentinel':
            report['matches'] = []
    harness.state.grype_mutate = change
    (harness.output / 'redis.metadata.json').write_text('{}')
    (harness.output / 'redis.evidence-manifest.json').write_text('{}')
    with pytest.raises(ValueError):
        harness.run()
    assert harness.state.grype_calls[-1] == 'cleanup' and harness.calls[-1] == 'cleanup'
    assert (harness.output / 'redis.json').is_file()
    assert list(harness.output.glob('redis.complement-*/sentinel-0.json'))
    assert not (harness.output / 'redis.metadata.json').exists()
    assert not (harness.output / 'redis.evidence-manifest.json').exists()


@pytest.mark.parametrize('error', [TimeoutError('synthetic bounded deadline'), KeyboardInterrupt()])
def test_tool_timeout_and_cancel_preserve_primary_and_dispose_both_contexts(harness, error):
    harness.state.grype_error = error
    harness.state.grype_cleanup_error = ValueError('owned_cleanup_failed')
    with pytest.raises(type(error)) as raised:
        harness.run()
    assert raised.value is error and raised.value.__notes__ == ['owned_cleanup_failed']
    assert harness.calls[-1] == 'cleanup' and harness.state.grype_calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


def test_successful_scan_with_tool_cleanup_refusal_cannot_publish(harness):
    harness.state.grype_cleanup_error = ValueError('owned_cleanup_failed')
    with pytest.raises(ValueError, match='owned_cleanup_failed'):
        harness.run()
    assert harness.calls[-1] == 'cleanup' and harness.state.grype_calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


@pytest.mark.parametrize('severity', ['High', 'Critical', 'Unknown', None, 'future-value'])
def test_complement_severe_fixable_is_nonzero_with_explicit_failed_bound_metadata(harness, severity):
    def change(report, query):
        if query.endswith(':7.4.11:*:*:*:*:*:*:*'):
            report['matches'] = MODELS.query_report(query, {'configuration': report['descriptor']['configuration'],
                'database': {'status': report['descriptor']['db']['status']}},
                advisory='CVE-public-severe-test', severity=severity, fixed=True)['matches']
    harness.state.grype_mutate = change
    with pytest.raises(SystemExit, match='CVE-public-severe-test'):
        harness.run()
    metadata = json.loads((harness.output / 'redis.metadata.json').read_bytes())
    assert metadata['verdict'] == 'failed' and len(metadata['findings']) == 2
    assert len(metadata['complement']['receipts']) == 2
    assert harness.state.grype_calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.evidence-manifest.json').exists()


@pytest.mark.parametrize('kind', ['medium', 'unfixed'])
def test_medium_and_unfixed_findings_remain_visible_without_failing_coverage(harness, kind):
    def change(report, query):
        if ':7.4.11:' in query:
            report['matches'] = MODELS.query_report(query, {'configuration': report['descriptor']['configuration'],
                'database': {'status': report['descriptor']['db']['status']}}, advisory='CVE-visible-test',
                severity='Medium' if kind == 'medium' else 'Unknown', fixed=kind == 'medium')['matches']
    harness.state.grype_mutate = change
    harness.run()
    paths = list(harness.output.glob('redis.complement-*/query-*.json'))
    assert len(paths) == 2 and all(json.loads(p.read_bytes())['matches'] for p in paths)
    assert json.loads((harness.output / 'redis.metadata.json').read_bytes())['verdict'] == 'passed'


def test_source_graph_refusal_happens_before_any_complement_tool(harness):
    def change(documents):
        predicate = documents['provenance']['statement']['predicate']
        predicate['buildDefinition']['internalParameters']['buildConfig']['llbDefinition'][8]['op']['Op']['file'][
            'actions'][0]['Action']['copy']['dest'] = '/foreign-binary'
    harness.state.source_mutate = change
    with pytest.raises(ValueError, match='dataflow'):
        harness.run('postgres')
    assert harness.state.grype_calls == [] and (harness.output / 'postgres.json').is_file()
    assert not (harness.output / 'postgres.metadata.json').exists()


@pytest.mark.parametrize('mutation', ['spdx', 'source', 'runtime'])
def test_post_query_spdx_source_or_runtime_drift_never_publishes(harness, mutation):
    if mutation == 'runtime':
        harness.state.grype_post_error = ValueError('synthetic frozen database drift')
    else:
        def effect():
            if mutation == 'spdx':
                harness.state.original_sbom['changed'] = True
            else:
                (harness.root / 'requirements/grype.yaml').write_text('{}')
        harness.state.query_effect = effect
    with pytest.raises(ValueError):
        harness.run()
    assert harness.calls[-1] == 'cleanup' and harness.state.grype_calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


@pytest.mark.parametrize('mutation', ['absent', 'collector', 'process', 'run', 'subject', 'rootfs', 'cleanup'])
def test_declared_principal_requires_current_native_receipt_before_any_queries(harness, mutation):
    if mutation == 'absent':
        harness.state.principal_missing = True
    else:
        def change(receipt):
            if mutation in {'collector', 'process'}:
                receipt['collector_sha256' if mutation == 'collector' else 'process_module_sha256'] = '0' * 64
            elif mutation == 'run':
                receipt['ci']['run_id'] = '1'
            elif mutation == 'subject':
                receipt['subject']['image_config'] = 'sha256:' + '0' * 64
            elif mutation == 'rootfs':
                receipt['identity']['rootfs_diff_ids'].reverse()
            else:
                receipt['cleanup']['absence_verified'] = False
        harness.state.principal_mutate = change
    with pytest.raises(FileNotFoundError if mutation == 'absent' else ValueError):
        harness.run('clickhouse')
    assert harness.state.grype_calls == [] and harness.calls[-1] == 'cleanup'
    assert (harness.output / 'clickhouse.json').is_file()
    assert not (harness.output / 'clickhouse.metadata.json').exists()


def test_after_cleanup_raw_report_drift_refuses_metadata(harness):
    harness.state.cleanup_effect = lambda: (harness.output / 'redis.json').write_bytes(b'{}')
    with pytest.raises(ValueError, match='Raw scanner evidence changed'):
        harness.run()
    assert harness.state.grype_calls[-1] == 'cleanup' and harness.calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


def test_raw_query_duplicate_keys_cannot_hide_suppressed_matches(harness):
    def change(path):
        path.write_text(path.read_text().replace('"source":',
            '"ignoredMatches":[{"reason":"hidden"}],"ignoredMatches":[],"source":'))
    harness.state.raw_query_effect = change
    with pytest.raises(ValueError, match='Ambiguous scanner evidence JSON'):
        harness.run()
    assert harness.state.grype_calls[-1] == 'cleanup' and harness.calls[-1] == 'cleanup'
    assert not (harness.output / 'redis.metadata.json').exists()


def test_verified_pending_principal_is_never_used_as_canonical_scanner_evidence(harness):
    harness.run('clickhouse')
    canonical = harness.output / PRINCIPAL.RECEIPT_NAME
    pending = canonical.with_name(canonical.name + '.0123456789abcdef.pending')
    canonical.rename(pending)
    harness.state.principal_missing = True
    harness.state.grype_calls.clear()
    with pytest.raises(FileNotFoundError):
        harness.run('clickhouse')
    assert json.loads(pending.read_bytes())['status'] == 'verified'
    assert not canonical.exists() and harness.state.grype_calls == []
    assert not (harness.output / 'clickhouse.metadata.json').exists()
