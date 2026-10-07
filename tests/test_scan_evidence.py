"""Revalidate captured source subjects and adversarial recorded scanner evidence."""

import copy
import hashlib
import importlib.util
import json
import os
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HARNESS = module(ROOT / "tests/test_image_scan_layout.py", "evidence_scanner_harness")
VERIFY = HARNESS.load("verify-scan-evidence")
MODELS = HARNESS.MODELS


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    harness = HARNESS.harness.__wrapped__(tmp_path, monkeypatch)
    harness.run("postgres")
    state = SimpleNamespace(harness=harness, component="postgres", cleanup_error=None, drift=False)
    original_script = VERIFY.script

    def script(name):
        if name == "component_source":
            return SimpleNamespace(subject_documents=harness.documents, bind=HARNESS.SOURCE.bind,
                                   bind_clickhouse=HARNESS.SOURCE.bind_clickhouse)
        if name == "oci_scan_layout":
            return SimpleNamespace(prepared_layout=prepared_layout)
        return original_script(name)

    def layout():
        metadata = json.loads((harness.output / f"{state.component}.metadata.json").read_bytes())
        fixture = MODELS.capture(state.component) if state.component in {
            "postgres", "node-exporter", "redis", "clickhouse"} else None
        if fixture:
            sbom = fixture["sbom"]
        else:
            # Original harness supplies the full locked Python closure for applications.
            sbom = harness.state.original_sbom
        def unchanged():
            if state.drift:
                raise ValueError("synthetic revalidation drift")
            return metadata["oci_layout"]
        return SimpleNamespace(evidence={"archive_sha256": harness.archive_hash, "image_manifests": [HARNESS.MANIFEST],
            "image_configs": {HARNESS.MANIFEST: HARNESS.CONFIG}, "sboms": {HARNESS.MANIFEST: sbom}},
            assert_unchanged=unchanged)

    @contextmanager
    def prepared_layout(*args, **kwargs):
        assert kwargs["expected_component"] == state.component
        try:
            yield layout()
        finally:
            if state.cleanup_error:
                raise state.cleanup_error

    monkeypatch.setattr(VERIFY, "ROOT", harness.root)
    monkeypatch.setattr(VERIFY, "script", script)

    def load_report(receipt):
        raw = (harness.output / receipt["report_path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt["report_sha256"]:
            raise ValueError("Complementary raw report changed")
        return json.loads(raw)

    def validate(metadata=None):
        metadata = metadata or json.loads((harness.output / f"{state.component}.metadata.json").read_bytes())
        return VERIFY.validate(metadata=metadata,
            report=json.loads((harness.output / f"{state.component}.json").read_bytes()), layout=layout(),
            image=state.component, platform="linux/amd64", root=harness.root, audit_directory=harness.output,
            expected_source={"commit": HARNESS.COMMIT, "repository": HARNESS.REPOSITORY}, pins=HARNESS.PINS,
            service_manifest=json.loads((harness.root / "requirements/service-builds/manifest.json").read_bytes()),
            load_report=load_report)

    def run():
        output = harness.output / f"{state.component}.evidence-manifest.json"
        monkeypatch.setattr(sys, "argv", ["verify-scan-evidence.py", "--input", str(harness.archive), "--audit",
            str(harness.output), "--image", state.component, "--platform", "linux/amd64", "--source-commit",
            HARNESS.COMMIT, "--repository", HARNESS.REPOSITORY, "--output", str(output)])
        VERIFY.main()
        return output

    state.validate, state.run = validate, run
    state.metadata = lambda: json.loads((harness.output / f"{state.component}.metadata.json").read_bytes())
    return state


@pytest.mark.parametrize("component,count", [("postgres", 2), ("node-exporter", 2), ("redis", 1), ("clickhouse", 1)])
def test_current_captured_subject_and_every_original_component_revalidate(evidence, component, count):
    evidence.component = component
    evidence.harness.run(component)
    bound = evidence.validate()
    assert len(bound["components"]) == count
    for claim in bound["components"]:
        if claim["observed_unversioned"]:
            assert claim["original_package"]["versionInfo"] == "UNKNOWN"
            assert claim["binary_version_claim"] is None
            assert claim["source_proof"]["authenticated_provenance"] is False


@pytest.mark.parametrize("mutation", ["verdict", "findings", "dirty", "archive", "manifest", "config", "platform",
    "commit", "repository", "source", "scanner", "native", "pin", "recipe", "component", "spdx", "count"])
def test_recorded_subject_source_inventory_and_assignment_tamper_refuse(evidence, mutation):
    metadata = evidence.metadata()
    if mutation == "verdict":
        metadata["verdict"] = "failed"
    elif mutation == "findings":
        metadata["findings"] = ["CVE-visible"]
    elif mutation == "dirty":
        metadata["source_dirty"] = True
    elif mutation in {"archive", "manifest", "config"}:
        metadata["subject"][{"archive": "archive_sha256", "manifest": "image_manifest", "config": "image_config"}[
            mutation]] = "0" * 64
    elif mutation in {"platform", "repository"}:
        metadata[mutation] += "-foreign"
    elif mutation == "commit":
        metadata["source_commit"] = "0" * 40
    elif mutation == "source":
        metadata["source_fingerprints"]["scripts/component_source.py"] = "0" * 64
    elif mutation == "scanner":
        metadata["scanner_script_sha256"] = "0" * 64
    elif mutation == "native":
        metadata["expected_packages"].pop()
    elif mutation == "pin":
        metadata["scanner"] += "foreign"
    elif mutation == "recipe":
        metadata["service_recipe"]["version"] = "foreign"
    elif mutation == "component":
        metadata["complement"]["components"][0]["source_proof"]["source_commit"] = "0" * 40
    elif mutation == "spdx":
        metadata["complement"]["spdx_sha256"] = "0" * 64
    elif mutation == "count":
        metadata["complement"]["software_package_count"] -= 1
    with pytest.raises(ValueError):
        evidence.validate(metadata)


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate", "query", "subject", "platform", "commit",
    "repository", "sbom", "provenance", "proof", "runtime", "raw"])
def test_complement_query_coverage_and_every_binding_are_exact(evidence, mutation):
    metadata = evidence.metadata()
    receipts = metadata["complement"]["receipts"]
    if mutation == "missing":
        receipts.pop()
    elif mutation == "extra":
        receipts.append(copy.deepcopy(receipts[0]))
    elif mutation == "duplicate":
        receipts[1]["report_path"] = receipts[0]["report_path"]
    elif mutation == "query":
        receipts[0]["query"] += "foreign"
    elif mutation == "subject":
        receipts[0]["subject"]["archive_sha256"] = "0" * 64
    elif mutation in {"platform", "repository"}:
        receipts[0][mutation] += "foreign"
    elif mutation == "commit":
        receipts[0]["source_commit"] = "0" * 40
    else:
        key = {"sbom": "sbom_blob", "provenance": "provenance_blob", "proof": "source_proof_sha256",
               "runtime": "runtime_receipt_sha256", "raw": "report_sha256"}[mutation]
        receipts[0][key] = "0" * 64
    with pytest.raises(ValueError):
        evidence.validate(metadata)


@pytest.mark.parametrize("mutation", ["absent", "query", "ids", "match", "hash", "ignored", "providers"])
def test_recorded_real_tool_sentinels_cannot_be_missing_or_substituted(evidence, mutation):
    metadata = evidence.metadata()
    sentinels = metadata["complement"]["sentinels"]
    if mutation == "absent":
        sentinels.pop()
    elif mutation == "query":
        sentinels[0]["query"] += "foreign"
    elif mutation == "ids":
        sentinels[0]["required_advisories"] = []
    elif mutation == "hash":
        sentinels[0]["report_sha256"] = "0" * 64
    else:
        path = evidence.harness.output / sentinels[0]["report_path"]
        raw = json.loads(path.read_bytes())
        if mutation == "match":
            raw["matches"] = []
        elif mutation == "ignored":
            raw["ignoredMatches"] = [{"reason": "hidden"}]
        else:
            raw["descriptor"]["db"]["providers"] = {"foreign-provider": {}}
        path.write_text(json.dumps(raw))
        sentinels[0]["report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        evidence.validate(metadata)


@pytest.mark.parametrize("mutation", ["version", "commit", "archive", "manifest", "module", "template", "rendered",
    "filter", "platform", "db_missing", "db_stale", "db_future", "db_invalid", "db_source", "db_path", "db_schema",
    "db_table", "db_digest", "db_extra", "db_fetched_future"])
def test_tool_effective_configuration_and_exact_fresh_database_receipt_refuse(evidence, mutation):
    receipt = evidence.metadata()["complement"]["runtime"]
    now = datetime.now(UTC)
    if mutation in {"version", "commit", "archive"}:
        key = {"version": "version", "commit": "release_commit", "archive": "archive_sha256"}[mutation]
        receipt["tool"][key] = "bad"
    elif mutation in {"manifest", "module", "template", "rendered"}:
        key = {"manifest": "manifest_sha256", "module": "runtime_module_sha256",
               "template": "config_template_sha256", "rendered": "config_sha256"}[mutation]
        receipt[key] = "0" * 64
    elif mutation == "filter":
        receipt["configuration"]["ignore"] = [{"vulnerability": "CVE-hidden"}]
    elif mutation == "platform":
        receipt["configuration"]["platform"] = "linux/arm64"
    elif mutation == "db_missing":
        receipt["database"].pop("status")
    elif mutation in {"db_stale", "db_future"}:
        receipt["database"]["status"]["built"] = (now + timedelta(hours=1) if mutation == "db_future" else
                                                    now - timedelta(hours=25)).isoformat()
    elif mutation in {"db_invalid", "db_source", "db_path", "db_schema"}:
        key = {"db_invalid": "valid", "db_source": "from", "db_path": "path", "db_schema": "schemaVersion"}[mutation]
        receipt["database"]["status"][key] = False if mutation == "db_invalid" else "foreign"
    elif mutation == "db_table":
        receipt["database"]["files"].pop("6/vulnerability.db")
    elif mutation == "db_digest":
        receipt["database"]["digest"] = "0" * 64
    elif mutation == "db_extra":
        receipt["database"]["files"]["../foreign"] = "0" * 64
    else:
        receipt["database"]["fetched_at"] = (now + timedelta(hours=1)).isoformat()
    with pytest.raises(ValueError):
        VERIFY.validate_runtime(receipt, root=evidence.harness.root, platform="linux/amd64",
            source_hashes=HARNESS.SCAN.source_fingerprints(evidence.harness.root, True), now=now)


@pytest.mark.parametrize("component", ["api", "worker", "collector", "test", "frontend"])
def test_application_native_and_python_lock_contract_stays_exact(evidence, component):
    evidence.component = component
    evidence.harness.run(component)
    assert evidence.validate()["components"] == []
    metadata = evidence.metadata()
    metadata["expected_packages"].pop()
    with pytest.raises(ValueError, match="package inventory"):
        evidence.validate(metadata)


def test_cli_manifest_binds_all_read_raw_files_and_source_only_after_cleanup(evidence):
    path = evidence.run()
    manifest = json.loads(path.read_bytes())
    assert manifest["verdict"] == "passed" and manifest["verification_kind"] == "revalidated_recorded_scan_evidence"
    assert len(manifest["files"]) == 7  # native report + metadata + two controls + three assigned queries
    for name, fingerprint in manifest["files"].items():
        assert hashlib.sha256((evidence.harness.output / name).read_bytes()).hexdigest() == fingerprint


@pytest.mark.parametrize("kind", ["cleanup", "drift", "raw", "unsafe", "stale"])
def test_cli_refusal_removes_stale_accepted_evidence_manifest(evidence, kind):
    path = evidence.harness.output / "postgres.evidence-manifest.json"
    path.write_text('{"verdict":"passed","old":true}')
    if kind == "cleanup":
        evidence.cleanup_error = ValueError("owned_cleanup_failed")
    elif kind == "drift":
        evidence.drift = True
    elif kind == "raw":
        (evidence.harness.output / "postgres.json").write_text('{}')
    else:
        metadata = evidence.metadata()
        if kind == "unsafe":
            metadata["complement"]["sentinels"][0]["report_path"] = "../foreign.json"
        else:
            metadata["complement"]["runtime"]["database"]["status"]["built"] = \
                (datetime.now(UTC) - timedelta(hours=25)).isoformat()
        (evidence.harness.output / "postgres.metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        evidence.run()
    assert not path.exists()


def test_signer_rejects_valid_principal_bytes_under_pending_filename(evidence):
    evidence.component = "clickhouse"
    evidence.harness.run("clickhouse")
    metadata = evidence.metadata()
    principal = metadata["complement"]["principal_observation"]
    canonical = evidence.harness.output / principal["report_path"]
    pending = canonical.with_name(canonical.name + ".0123456789abcdef.pending")
    canonical.rename(pending)
    principal["report_path"] = pending.name
    # The bytes/hash remain fully valid; filename, not JSON status, is decisive.
    assert hashlib.sha256(pending.read_bytes()).hexdigest() == principal["report_sha256"]
    assert json.loads(pending.read_bytes())["status"] == "verified"
    with pytest.raises(ValueError, match="absent or ambiguous"):
        evidence.validate(metadata)
    assert not (evidence.harness.output / "clickhouse.evidence-manifest.json").exists()


@pytest.mark.parametrize("component", ["postgres", "node-exporter", "clickhouse"])
def test_rehashed_numeric_graph_alias_still_refuses_source_replay(evidence, component):
    evidence.component = component
    evidence.harness.run(component)
    metadata = evidence.metadata()
    def change(documents):
        graph = documents["provenance"]["statement"]["predicate"]["buildDefinition"]["internalParameters"][
            "buildConfig"]["llbDefinition"]
        if component == "clickhouse":
            graph[3]["op"]["Op"]["exec"]["mounts"][1]["readonly"] = 1
        else:
            graph[2]["op"]["Op"]["file"]["actions"][0]["input"] = False
        metadata["complement"]["components"][0]["source_proof"]["build_graph_sha256"] = hashlib.sha256(
            json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    evidence.harness.state.source_mutate = change
    with pytest.raises(ValueError, match="dataflow"):
        evidence.validate(metadata)
    assert not (evidence.harness.output / f"{component}.evidence-manifest.json").exists()


def test_evidence_regular_read_is_binary_on_windows_and_bounded(tmp_path, monkeypatch):
    path = tmp_path / "raw.json"
    data = b"real\r\n\x1aunchanged"
    path.write_bytes(data)
    assert VERIFY.read(path) == data
    monkeypatch.setattr(VERIFY, "LIMIT", len(data) - 1)
    with pytest.raises(ValueError, match="bounded regular"):
        VERIFY.read(path)


@pytest.mark.parametrize("data", [b'{"source":{},"source":{}}', b'{"matches":NaN}', b'{"matches":Infinity}'])
def test_evidence_json_rejects_duplicates_and_nonfinite_fields(data):
    with pytest.raises(ValueError):
        VERIFY.decode(data)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink refusal; Windows regular/replacement guards run separately")
def test_evidence_regular_read_refuses_symbolic_link(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"unchanged")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="regular"):
        VERIFY.read(link)


@pytest.mark.parametrize("mutation", ["absent", "hash", "path", "embedded", "process", "collector", "run",
                                      "rootfs", "declared-query", "missing-query", "source-proof"])
def test_signed_evidence_declared_principal_and_its_query_cannot_be_substituted(evidence, mutation):
    evidence.component = "clickhouse"
    evidence.harness.run("clickhouse")
    metadata = evidence.metadata()
    complement = metadata["complement"]
    principal = complement["principal_observation"]
    if mutation == "absent":
        complement.pop("principal_observation")
    elif mutation == "hash":
        principal["report_sha256"] = "0" * 64
    elif mutation == "path":
        principal["report_path"] = "foreign.json"
    elif mutation == "embedded":
        principal["receipt"]["cleanup"]["container_removed"] = False
    elif mutation in {"process", "collector", "run", "rootfs"}:
        raw_path = evidence.harness.output / principal["report_path"]
        raw = json.loads(raw_path.read_bytes())
        if mutation in {"process", "collector"}:
            raw["process_module_sha256" if mutation == "process" else "collector_sha256"] = "0" * 64
        elif mutation == "run":
            raw["ci"]["run_attempt"] = "99"
        else:
            raw["identity"]["rootfs_diff_ids"].reverse()
        raw_path.write_text(json.dumps(raw))
        principal["receipt"] = raw
        principal["report_sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    elif mutation == "declared-query":
        complement["receipts"][0]["query"] = HARNESS.PRINCIPAL.QUERY.replace("25.8.33.6", "25.8.33.5")
    elif mutation == "missing-query":
        complement["receipts"] = []
    else:
        complement["components"][0]["source_proof"]["publisher_base"] = "unbound"
    with pytest.raises(ValueError):
        evidence.validate(metadata)


def test_signing_manifest_requires_cli_receipt_and_native_job_identity(evidence, monkeypatch):
    evidence.component = "clickhouse"
    evidence.harness.run("clickhouse")
    monkeypatch.setenv("GITHUB_JOB", "signed-image-evidence")
    path = evidence.run()
    manifest = json.loads(path.read_bytes())
    assert "clickhouse.principal-observation.json" in manifest["files"]
    assert len(manifest["files"]) == 6  # Native + metadata + native CLI + two controls + one declared query.
    assert manifest["verdict"] == "passed"
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    with pytest.raises(ValueError):
        evidence.run()
    assert not path.exists()
