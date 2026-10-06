"""Delivery gates fail closed on source drift, incomplete reports and broken attestations."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LOCK = load("lock-dependencies")
IMAGES = load("verify-image-pins")
AUDIT = load("audit-dependencies")
SCAN = load("scan-images")
OCI = load("verify-oci-evidence")
GH = load("download-gh-verifier")


@pytest.fixture
def delivery_tree(tmp_path):
    for source in ("pyproject.toml", "agent/pyproject.toml", "scripts/verify-image-pins.py",
                   "deploy/qualification/compose.yaml"):
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, target)
    shutil.copytree(ROOT / "requirements", tmp_path / "requirements")
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    shutil.copytree(ROOT / "deploy/service-builds", tmp_path / "deploy/service-builds")
    (tmp_path / "frontend").mkdir()
    shutil.copyfile(ROOT / "frontend/Dockerfile", tmp_path / "frontend/Dockerfile")
    for path in ROOT.glob("docker-compose*.yml"):
        shutil.copyfile(path, tmp_path / path.name)
    return tmp_path


def test_committed_locks_and_images_are_complete(delivery_tree):
    LOCK.check(delivery_tree)
    IMAGES.check_references(delivery_tree)


def test_test_image_contains_modules_required_during_integration_collection():
    dockerfile = (ROOT / "docker/Dockerfile.test").read_text(encoding="utf-8")
    assert "COPY tests/ tests/" in dockerfile and "COPY scripts/ scripts/" in dockerfile
    imported = ["lock-dependencies", "verify-image-pins", "audit-dependencies", "scan-images",
                "verify-oci-evidence", "download-gh-verifier"]
    assert all((ROOT / "scripts" / f"{name}.py").is_file() for name in imported)


def test_test_image_scripts_support_pytest_integration_collection(tmp_path):
    (tmp_path / "tests").mkdir()
    shutil.copyfile(ROOT / "tests/test_production_delivery.py", tmp_path / "tests/test_production_delivery.py")
    dockerfile = (ROOT / "docker/Dockerfile.test").read_text(encoding="utf-8")
    if "COPY scripts/ scripts/" in dockerfile:
        shutil.copytree(ROOT / "scripts", tmp_path / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    result = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", "integration",
                             "-p", "no:cacheprovider", str(tmp_path / "tests/test_production_delivery.py")],
                            cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 5 and "error" not in result.stdout.lower(), result.stdout + result.stderr


@pytest.mark.parametrize("source,before,after", [
    ("pyproject.toml", '"fastapi>=0.121.0"', '"fastapi>=0.142.0"'),
    ("pyproject.toml", 'requires-python = ">=3.12"', 'requires-python = ">=3.13"'),
    ("agent/pyproject.toml", '"docker>=7.1.0"', '"docker>=7.3.0"'),
    ("agent/pyproject.toml", '"setuptools==84.0.0"', '"setuptools==84.0.1"'),
    ("requirements/tools.in", "uv==0.11.16", "uv==0.11.17"),
    ("requirements/build.in", "wheel==0.48.0", "wheel==0.48.1"),
])
def test_dependency_and_build_metadata_drift_fails(delivery_tree, source, before, after):
    path = delivery_tree / source
    path.write_text(path.read_text(encoding="utf-8").replace(before, after), encoding="utf-8")
    with pytest.raises(ValueError, match="metadata drift"):
        LOCK.check(delivery_tree)


def test_unrelated_lint_configuration_does_not_change_resolution(delivery_tree):
    path = delivery_tree / "pyproject.toml"
    updated = path.read_text(encoding="utf-8").replace("line-length = 120", "line-length = 121")
    path.write_text(updated, encoding="utf-8")
    LOCK.check(delivery_tree)


@pytest.mark.parametrize("requirement", [
    "package>=1.0", "package==1.0", "package @ https://example.test/p.whl",
    "shadai==0.2.0", "shadai-agent==0.1.0", "--index-url https://example.test/simple",
    "package==1.0 --hash=sha256:" + "g" * 64,
    "package==1.0 --hash=sha256:" + "a" * 63,
    "package==1.0 --hash=sha256:" + "a" * 64 + " \\",
])
def test_incomplete_and_unsafe_locks_are_rejected(tmp_path, requirement):
    path = tmp_path / "requirements.txt"
    path.write_text(requirement + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        LOCK.validate_lock(path)


def test_lock_bytes_tampering_fails(delivery_tree):
    path = delivery_tree / "requirements/runtime.txt"
    path.write_bytes(path.read_bytes() + b"# changed\n")
    with pytest.raises(ValueError, match="content drift"):
        LOCK.check(delivery_tree)


def test_failed_resolution_does_not_modify_existing_locks(delivery_tree, monkeypatch):
    def snapshot():
        directory = delivery_tree / "requirements"
        return {path.relative_to(directory).as_posix(): path.read_bytes()
                for path in sorted(directory.rglob("*")) if path.is_file() and not path.is_symlink()}

    before = snapshot()
    monkeypatch.setattr(LOCK, "ROOT", delivery_tree)
    monkeypatch.setattr(LOCK.subprocess, "check_output", lambda *args, **kwargs: "uv 0.11.16")

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic registry outage")

    monkeypatch.setattr(LOCK.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="registry outage"):
        LOCK.generate("uv", verify=False, upgrade=[], constraints=None)
    assert before == snapshot()


def test_every_lock_compile_disables_ambient_configuration(delivery_tree, monkeypatch):
    commands = []
    monkeypatch.setattr(LOCK, "ROOT", delivery_tree)
    monkeypatch.setattr(LOCK.subprocess, "check_output", lambda *args, **kwargs: "uv 0.11.16")
    monkeypatch.setenv("UV_INDEX_URL", "https://untrusted.example.test/simple")
    monkeypatch.setenv("PIP_EXTRA_INDEX_URL", "https://untrusted.example.test/simple")

    def compile_lock(command, **kwargs):
        commands.append(command)
        assert "--no-config" in command and "--no-python-downloads" in command
        assert command[command.index("--default-index") + 1] == "https://pypi.org/simple"
        assert not any(key.startswith(("UV_", "PIP_")) for key in kwargs["env"])

    monkeypatch.setattr(LOCK.subprocess, "run", compile_lock)
    LOCK.generate("uv", verify=True, upgrade=[], constraints=None)
    assert len(commands) == len(LOCK.LOCKS)


def test_actual_uv_ignores_an_ambient_registry_configuration(tmp_path):
    uv = os.environ.get("SHADAI_DELIVERY_UV") or shutil.which("uv")
    if not uv:
        pytest.skip("Pinned uv unavailable for the ambient configuration engine test")
    version = subprocess.check_output([uv, "--version"], text=True).split()[1]
    if version != LOCK.UV_VERSION:
        pytest.skip(f"Ambient configuration engine test requires uv {LOCK.UV_VERSION}")
    settings = tmp_path / "config/uv"
    settings.mkdir(parents=True)
    (settings / "uv.toml").write_text('extra-index-url = ["https://[invalid"]\n', encoding="utf-8")
    requirements = tmp_path / "empty.in"
    requirements.write_text("", encoding="utf-8")
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("UV_", "PIP_"))}
    environment.update({"APPDATA": str(settings.parent), "XDG_CONFIG_HOME": str(settings.parent),
                        "TMP": str(tmp_path), "TEMP": str(tmp_path), "TMPDIR": str(tmp_path)})
    command = [uv, "pip", "compile", str(requirements), "--offline", "--no-python-downloads",
               "--python", sys.executable, "--cache-dir", str(tmp_path / "cache"),
               "--default-index", "https://pypi.org/simple", "--no-header", "--no-annotate"]
    inherited = subprocess.run(command, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    assert inherited.returncode != 0 and "https://[invalid" in inherited.stderr
    isolated = subprocess.run([*command, "--no-config"], cwd=tmp_path, env=environment,
                              capture_output=True, text=True, timeout=30)
    assert isolated.returncode == 0, isolated.stdout + isolated.stderr


def test_mutable_or_unrecorded_image_fails(delivery_tree):
    (delivery_tree / "docker/Dockerfile.api").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mutable base"):
        IMAGES.check_references(delivery_tree)


@pytest.mark.parametrize("severity,fixed,blocked", [
    ("low", True, False), ("moderate", True, False), ("high", True, True),
    ("critical", True, True), ("unknown", True, True), ("critical", False, False),
])
def test_python_gate_retains_unfixed_and_blocks_fixable_severe(severity, fixed, blocked):
    report = {"dependencies": [{"name": "synthetic", "version": "1.0", "vulns": [
        {"id": "GHSA-aaaa-bbbb-cccc", "fix_versions": ["1.1"] if fixed else []}]}]}
    assert bool(AUDIT.gate_python(report, lambda vulnerability: severity)) is blocked
    assert report["dependencies"][0]["vulns"]


@pytest.mark.parametrize("severity,fixed,blocked", [
    ("HIGH", "1.1", True), ("CRITICAL", "1.1", True),
    ("MEDIUM", "1.1", False), ("CRITICAL", "", False), (None, "1.1", True), ("UNKNOWN", "1.1", True),
])
def test_image_gate_preserves_full_report(severity, fixed, blocked):
    report = trivy_report()
    report["Results"][0]["Vulnerabilities"] = [
        {"VulnerabilityID": "CVE-synthetic", "PkgName": "synthetic", "Severity": severity, "FixedVersion": fixed}]
    assert bool(SCAN.gate(report)) is blocked
    assert report["Results"][0]["Vulnerabilities"]


def test_empty_scanner_output_is_not_a_pass():
    with pytest.raises(ValueError, match="no results"):
        SCAN.gate({})


def oci_archive(path, *, missing=None, wrong_subject=False, tamper=False, unlinked=False,
                legacy=False, nested=False, omit_blob=None, wrong_size=False, config_arch="amd64",
                package_inventory=None, duplicate=False, unsafe=None, depth=0):
    blobs = {}

    def blob(value, media):
        data = json.dumps(value).encode() if isinstance(value, dict) else value
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(data)}

    layer_data = io.BytesIO()
    with tarfile.open(fileobj=layer_data, mode="w") as layer_archive:
        member = tarfile.TarInfo("synthetic-file")
        member.size = 4
        layer_archive.addfile(member, io.BytesIO(b"data"))
    image_layer = blob(layer_data.getvalue(), "application/vnd.oci.image.layer.v1.tar")
    image_config = blob({"architecture": config_arch, "os": "linux", "rootfs": {
        "type": "layers", "diff_ids": [image_layer["digest"]]}}, "application/vnd.oci.image.config.v1+json")
    image = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                  "config": image_config, "layers": [image_layer]}, "application/vnd.oci.image.manifest.v1+json")
    image_digest = image["digest"][7:]
    layers = []
    for kind in ("sbom", "provenance"):
        if kind == missing:
            continue
        packages = package_inventory or [{"name": "synthetic", "versionInfo": "1.0", "externalRefs": [
            {"referenceType": "purl", "referenceLocator": "pkg:deb/debian/synthetic@1.0?arch=amd64"}]}]
        statement = {"_type": "https://in-toto.io/Statement/v0.1",
                     "predicateType": "https://spdx.dev/Document" if kind == "sbom" else
                     "https://slsa.dev/provenance/v0.2",
                     "predicate": {"spdxVersion": "SPDX-2.3", "packages": packages} if kind == "sbom" else
                     {"buildType": "https://mobyproject.org/buildkit@v1", "builder": {"id": "synthetic-buildkit"}},
                     "subject": [{"name": "_", "digest": {"sha256": "0" * 64 if wrong_subject else image_digest}}]}
        layers.append(blob(statement, "application/vnd.in-toto+json"))
    attestation_config = blob({"architecture": "unknown", "os": "unknown", "rootfs": {
        "type": "layers", "diff_ids": [] if unlinked else [layer["digest"] for layer in layers]}},
        "application/vnd.oci.image.config.v1+json") if legacy else blob({}, "application/vnd.oci.empty.v1+json")
    attestation_data = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": attestation_config, "layers": [] if unlinked else layers}
    if not legacy:
        attestation_data.update({"artifactType": "application/vnd.docker.attestation.manifest.v1+json",
                                 "subject": image})
    attestation = blob(attestation_data, "application/vnd.oci.image.manifest.v1+json")
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
        {**image, "platform": {"os": "linux", "architecture": "amd64"}},
        {**attestation, "platform": {"os": "unknown", "architecture": "unknown"},
         "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                         "vnd.docker.reference.digest": image["digest"]}}]}
    if wrong_size:
        index["manifests"][0]["size"] += 1
    for _ in range(depth + int(nested)):
        index = {"schemaVersion": 2, "manifests": [blob(index, "application/vnd.oci.image.index.v1+json")]}
    if omit_blob:
        omitted = {"image": image, "config": image_config, "layer": image_layer,
                   "attestation_config": attestation_config, "nested": index["manifests"][0]}[omit_blob]
        del blobs[omitted["digest"][7:]]
    with tarfile.open(path, "w") as archive:
        members = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": json.dumps(index).encode(),
                   **{"blobs/sha256/" + name: value for name, value in blobs.items()}}
        if tamper:
            members["blobs/sha256/" + image_digest] = b"tampered"
        for name, data in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if duplicate:
            member = tarfile.TarInfo("index.json")
            member.size = len(members["index.json"])
            archive.addfile(member, io.BytesIO(members["index.json"]))
        if unsafe:
            member = tarfile.TarInfo(unsafe)
            member.size = 0
            archive.addfile(member, io.BytesIO())


def test_verified_evidence_is_bound_to_the_image(tmp_path):
    path = tmp_path / "image.tar"
    oci_archive(path)
    assert OCI.verify(path)["verified"] == ["blob-sha256", "oci-graph", "native-platform",
                                            "spdx-sbom", "slsa-provenance"]


@pytest.mark.parametrize("options", [
    {"missing": "sbom"}, {"missing": "provenance"}, {"wrong_subject": True}, {"tamper": True}, {"unlinked": True},
])
def test_missing_wrong_subject_or_corrupt_evidence_fails(tmp_path, options):
    path = tmp_path / "image.tar"
    oci_archive(path, **options)
    with pytest.raises(ValueError):
        OCI.verify(path)


@pytest.mark.parametrize("legacy,nested", [(False, False), (True, False), (False, True), (True, True)])
def test_valid_buildkit_artifact_and_legacy_layouts_pass(tmp_path, legacy, nested):
    path = tmp_path / "image.tar"
    oci_archive(path, legacy=legacy, nested=nested)
    result = OCI.verify(path, include_sbom=True)
    assert len(result["image_manifests"]) == len(result["image_configs"]) == len(result["sboms"]) == 1
    assert result["platform"] == "linux/amd64"


@pytest.mark.parametrize("options", [
    {"omit_blob": "image"}, {"omit_blob": "config"}, {"omit_blob": "layer"},
    {"omit_blob": "attestation_config"}, {"omit_blob": "nested", "nested": True},
    {"wrong_size": True}, {"config_arch": "arm64"}, {"duplicate": True},
    {"unsafe": "../escaped"}, {"unsafe": "/absolute"}, {"depth": 18},
])
def test_incomplete_or_unsafe_oci_graph_cannot_establish_evidence(tmp_path, options):
    path = tmp_path / "image.tar"
    oci_archive(path, **options)
    with pytest.raises(ValueError):
        OCI.verify(path)


def test_native_image_platform_is_required(tmp_path):
    path = tmp_path / "image.tar"
    oci_archive(path)
    with pytest.raises(ValueError, match="platform mismatch"):
        OCI.verify(path, platform="linux/arm64")


def test_oci_metadata_read_is_bounded_while_layers_are_streamed(tmp_path, monkeypatch):
    path = tmp_path / "image.tar"
    oci_archive(path)
    monkeypatch.setattr(OCI, "MAX_JSON", 32)
    with pytest.raises(ValueError, match="oversized"):
        OCI.verify(path)


def test_oci_descriptor_and_member_count_are_bounded(tmp_path, monkeypatch):
    path = tmp_path / "image.tar"
    oci_archive(path)
    monkeypatch.setattr(OCI, "MAX_DESCRIPTORS", 1)
    with pytest.raises(ValueError, match="Unbounded"):
        OCI.verify(path)
    monkeypatch.setattr(OCI, "MAX_MEMBERS", 1)
    with pytest.raises(ValueError, match="Unsafe"):
        OCI.verify(path)


def trivy_report():
    return {"SchemaVersion": 2, "Trivy": {"Version": "0.75.0"},
            "ArtifactName": "/input/runtime.oci.tar", "ArtifactType": "container_image",
            "Metadata": {"ImageID": "sha256:" + "a" * 64,
                         "ImageConfig": {"os": "linux", "architecture": "amd64"},
                         "RepoDigests": ["synthetic@sha256:" + "b" * 64]},
            "Results": [{"Target": "synthetic (debian 13)", "Class": "os-pkgs", "Type": "debian",
                         "Packages": [{"Name": "synthetic", "Version": "1.0", "Identifier": {
                             "PURL": "pkg:deb/debian/synthetic@1.0?arch=amd64&distro=debian-13"}}]}]}


def test_complete_subject_and_package_inventory_passes():
    assert SCAN.gate(trivy_report(), expected={("deb", "synthetic", "1.0")}, image_id="sha256:" + "a" * 64,
                     artifact="/input/runtime.oci.tar", platform="linux/amd64",
                     reference="docker.io/library/synthetic:1.0@sha256:" + "b" * 64) == []


def test_pinned_trivy_cyclonedx_schema_subject_and_inventory():
    # Schema follows Trivy 0.75.0 sbom/io/encode.go and sbom/cyclonedx/marshal.go.
    reference = "synthetic:1.0@sha256:" + "b" * 64
    report = {"bomFormat": "CycloneDX", "specVersion": "1.7", "metadata": {"component": {
        "type": "container", "name": reference, "properties": [
            {"name": "aquasecurity:trivy:ImageID", "value": "sha256:" + "a" * 64}]}},
        "components": [{"type": "library", "name": "synthetic", "version": "1.0",
                        "purl": "pkg:deb/debian/synthetic@1.0?arch=amd64"}]}
    assert SCAN.cyclone_inventory(report, reference=reference) == ({("deb", "synthetic", "1.0")}, "sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="subject mismatch"):
        SCAN.cyclone_inventory(report, reference="other:1.0@sha256:" + "c" * 64)
    report["components"] = [{"type": "library", "name": "stdlib", "version": "go1.26.0",
                             "purl": "pkg:golang/stdlib@go1.26.0"}]
    assert SCAN.cyclone_inventory(report, reference=reference)[0] == {("golang", "stdlib", "v1.26.0")}
    report["components"] = []
    with pytest.raises(ValueError, match="empty"):
        SCAN.cyclone_inventory(report, reference=reference)


@pytest.mark.parametrize("mutation", ["empty", "missing_inventory", "duplicate_target", "duplicate_package",
                                     "missing_package", "wrong_version", "wrong_image", "wrong_artifact",
                                     "wrong_platform", "wrong_reference", "wrong_schema", "wrong_scanner"])
def test_trivy_empty_partial_duplicate_or_wrong_subject_fails(mutation):
    report = trivy_report()
    if mutation == "empty":
        report["Results"] = []
    elif mutation == "missing_inventory":
        del report["Results"][0]["Packages"]
    elif mutation == "duplicate_target":
        report["Results"].append(copy.deepcopy(report["Results"][0]))
    elif mutation == "duplicate_package":
        report["Results"][0]["Packages"] *= 2
    elif mutation == "missing_package":
        report["Results"][0]["Packages"] = []
    elif mutation == "wrong_version":
        report["Results"][0]["Packages"][0]["Identifier"]["PURL"] = "pkg:deb/debian/synthetic@2.0"
    elif mutation == "wrong_image":
        report["Metadata"]["ImageID"] = "sha256:" + "f" * 64
    elif mutation == "wrong_artifact":
        report["ArtifactName"] = "/input/old.tar"
    elif mutation == "wrong_platform":
        report["Metadata"]["ImageConfig"]["architecture"] = "arm64"
    elif mutation == "wrong_reference":
        report["Metadata"]["RepoDigests"] = ["synthetic@sha256:" + "f" * 64]
    elif mutation == "wrong_schema":
        report["SchemaVersion"] = 1
    else:
        report["Trivy"]["Version"] = "0.1.0"
    with pytest.raises(ValueError):
        SCAN.gate(report, expected={("deb", "synthetic", "1.0")}, image_id="sha256:" + "a" * 64,
                  artifact="/input/runtime.oci.tar", platform="linux/amd64",
                  reference="synthetic@sha256:" + "b" * 64)


@pytest.mark.parametrize("report", [
    {}, {"dependencies": []}, {"dependencies": [{"name": "synthetic", "skip_reason": "outage"}]},
])
def test_empty_and_skipped_python_coverage_fails(report):
    with pytest.raises(ValueError):
        AUDIT.gate_python(report, expected={"synthetic": "1.0"})


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "wrong_version", "malformed_vulnerability"])
def test_python_exact_coverage_rejects_omissions_duplicates_and_wrong_versions(mutation):
    report = {"dependencies": [{"name": "synthetic", "version": "1.0", "vulns": []},
                                {"name": "another", "version": "2.0", "vulns": []}]}
    if mutation == "missing":
        report["dependencies"].pop()
    elif mutation == "duplicate":
        report["dependencies"].append(copy.deepcopy(report["dependencies"][0]))
    elif mutation == "wrong_version":
        report["dependencies"][0]["version"] = "0.9"
    else:
        report["dependencies"][0]["vulns"] = [{"id": "advisory-without-fix-data"}]
    with pytest.raises(ValueError):
        AUDIT.gate_python(report, expected={"synthetic": "1.0", "another": "2.0"})


@pytest.mark.parametrize("severity_lookup", [None, lambda _: None, lambda _: "unexpected"])
def test_fixable_unknown_python_severity_cannot_pass(severity_lookup):
    report = {"dependencies": [{"name": "synthetic", "version": "1.0", "vulns": [
        {"id": "GHSA-aaaa-bbbb-cccc", "fix_versions": ["1.1"]}]}]}
    assert AUDIT.gate_python(report, severity_lookup, expected={"synthetic": "1.0"})


def test_native_platform_markers_preserve_applicable_dependencies():
    windows = AUDIT.default_environment()
    windows.update({"sys_platform": "win32", "os_name": "nt", "platform_system": "Windows"})
    linux = {**windows, "sys_platform": "linux", "os_name": "posix", "platform_system": "Linux"}
    assert "pywin32" in AUDIT.expected_python(ROOT / "requirements/agent.txt", windows)
    assert "pywin32" not in AUDIT.expected_python(ROOT / "requirements/agent.txt", linux)
    assert "uvloop" in AUDIT.expected_python(ROOT / "requirements/runtime.txt", linux)
    assert "uvloop" not in AUDIT.expected_python(ROOT / "requirements/runtime.txt", windows)


def test_audit_rejects_stale_lock_manifest(delivery_tree):
    lock = delivery_tree / "requirements/runtime.txt"
    lock.write_bytes(lock.read_bytes() + b"# changed\n")
    with pytest.raises(ValueError, match="drift"):
        AUDIT.expected_python(lock)


def test_audit_cli_cannot_reuse_an_old_complete_report(tmp_path, monkeypatch):
    output = tmp_path / "reports"
    output.mkdir()
    report = output / "python-runtime.json"
    report.write_text(json.dumps({"dependencies": [{"name": name, "version": version, "vulns": []}
                                                   for name, version in AUDIT.expected_python(
                                                       ROOT / "requirements/runtime.txt").items()]}), encoding="utf-8")
    sidecar = report.with_suffix(".metadata.json")
    sidecar.write_text('{"invocation":"old"}', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["audit-dependencies.py", "--output", str(output)])
    monkeypatch.setattr(AUDIT.subprocess, "run", lambda *args, **kwargs: SimpleResult(0))
    monkeypatch.setattr(AUDIT, "source_identity", lambda commit, repository: ("a" * 40, "owner/repository"))
    with pytest.raises(RuntimeError, match="Dependency scan failed"):
        AUDIT.main()
    assert not report.exists() and not sidecar.exists()


class SimpleResult:
    def __init__(self, returncode):
        self.returncode = returncode


def test_source_commit_identity_cannot_name_another_checkout(monkeypatch):
    monkeypatch.setattr(AUDIT.subprocess, "check_output", lambda *args, **kwargs: "a" * 40)
    with pytest.raises(ValueError, match="exact source commit"):
        AUDIT.source_identity("b" * 40, "owner/repository")
    assert AUDIT.source_identity("a" * 40, "owner/repository") == ("a" * 40, "owner/repository")


def test_bound_report_metadata_records_dirty_local_code_and_input(tmp_path, monkeypatch):
    report = tmp_path / "report.json"
    report.write_text('{"dependencies": []}', encoding="utf-8")
    lock = ROOT / "requirements/runtime.txt"
    monkeypatch.setattr(AUDIT.subprocess, "check_output", lambda *args, **kwargs: " M scripts/audit-dependencies.py")
    AUDIT.write_metadata(report, subject=lock, invocation="new-invocation", command=["pip-audit"], scanner="synthetic",
                         environment=AUDIT.default_environment(), source_commit="a" * 40, repository="owner/repository",
                         expected=AUDIT.expected_python(lock))
    metadata = json.loads(report.with_suffix(".metadata.json").read_text(encoding="utf-8"))
    assert metadata["source_dirty"] is True and metadata["invocation"] == "new-invocation"
    assert metadata["input_sha256"] == hashlib.sha256(lock.read_bytes()).hexdigest()
    assert metadata["report_sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()


@pytest.mark.parametrize("name", ["runtime", "agent", "development", "build", "tools"])
def test_saved_actual_pip_audit_reports_cover_native_hash_locks(name):
    path = ROOT / "tmp/production-delivery/advisories-final" / f"python-{name}.json"
    if not path.exists():
        pytest.skip("Local retained scanner report is not in this checkout")
    report = json.loads(path.read_text(encoding="utf-8"))
    # Retained reports used tool-env/pyvenv.cfg: Windows CPython 3.13.15.
    environment = AUDIT.default_environment()
    environment.update({"sys_platform": "win32", "os_name": "nt", "platform_system": "Windows",
                        "python_version": "3.13", "python_full_version": "3.13.15",
                        "implementation_name": "cpython", "platform_python_implementation": "CPython"})
    AUDIT.validate_python(report, AUDIT.expected_python(ROOT / "requirements" / f"{name}.txt", environment))


def test_spdx_inventory_accepts_encoded_epochs_and_normalizes_python_names():
    sbom = {"packages": [{"externalRefs": [{"referenceType": "purl", "referenceLocator": value}]} for value in
                         ("pkg:deb/debian/openssl@1%3A3.5.0-1?arch=amd64", "pkg:pypi/typing_extensions@4.16.0")]}
    assert SCAN.spdx_inventory(sbom) == {("deb", "openssl", "1:3.5.0-1"), ("pypi", "typing-extensions", "4.16.0")}
    assert SCAN.package_key("pkg:deb/debian/openssl@3.5.0-1?epoch=1&arch=arm64") == ("deb", "openssl", "1:3.5.0-1")


def test_package_report_fields_cannot_disagree_with_inventory_purl():
    report = trivy_report()
    report["Results"][0]["Packages"][0]["Version"] = "9.0"
    with pytest.raises(ValueError, match="name/version"):
        SCAN.gate(report)


def test_actual_retained_npm_reports_have_complete_lock_counts():
    total = len(json.loads((ROOT / "frontend/package-lock.json").read_text(encoding="utf-8"))["packages"]) - 1
    for name in ("frontend-all", "frontend-runtime"):
        path = ROOT / "tmp/production-delivery/frontend-advisories" / f"{name}.json"
        if not path.exists():
            pytest.skip("Local retained npm audit report unavailable")
        report = json.loads(path.read_text(encoding="utf-8"))
        assert AUDIT.gate_npm(report) == []
        assert report["metadata"]["dependencies"]["total"] == total


def test_frontend_inventory_does_not_claim_minified_browser_bundle_npm_coverage():
    sbom = {"packages": [{"externalRefs": [{"referenceType": "purl", "referenceLocator": value}]} for value in
                         ("pkg:apk/alpine/nginx@1.30.5-r0", "pkg:npm/react@18.3.1")]}
    assert SCAN.spdx_inventory(sbom, frontend=True) == {("apk", "nginx", "1.30.5-r0")}


def test_pressure_configuration_is_required_only_when_selected():
    spec = importlib.util.spec_from_file_location("sso_pressure_test", ROOT / "tests/test_sso_pressure_integration.py")
    pressure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pressure)
    with pytest.raises(pytest.skip.Exception):
        pressure.pressure_settings({})
    with pytest.raises(pytest.fail.Exception, match="missing"):
        pressure.pressure_settings({"SHADAI_REQUIRE_REDIS_PRESSURE": "1"})
    environment = {"SHADAI_REDIS_PRESSURE_HOST": "labredis-pressure", "SHADAI_REDIS_PRESSURE_PORT": "6379",
                   "SHADAI_REDIS_PRESSURE_PASSWORD_FILE": "/run/secrets/redis_pressure_password",
                   "SHADAI_REDIS_PRESSURE_LAB": "1"}
    assert pressure.pressure_settings(environment)[:2] == ("labredis-pressure", 6379)
    with pytest.raises(pytest.fail.Exception, match="isolated"):
        pressure.pressure_settings({**environment, "SHADAI_REDIS_PRESSURE_HOST": "normal-redis"})
    with pytest.raises(pytest.fail.Exception, match="healthy AOF"):
        pressure.verify_pressure_policy({"maxmemory": "1", "maxmemory-policy": "noeviction", "appendonly": "yes"},
                                        {"aof_enabled": 1, "aof_last_write_status": "ok"})
    pressure.verify_pressure_policy({"maxmemory": str(32 * 1024 * 1024), "maxmemory-policy": "noeviction",
                                     "appendonly": "yes"}, {"aof_enabled": 1, "aof_last_write_status": "ok"})
    assert "config_set" not in (ROOT / "tests/test_sso_admission_integration.py").read_text(encoding="utf-8")


def test_image_export_names_one_commit_component_without_registry_publication():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["image-security"]
    build, = [step for step in job["steps"] if step.get("uses", "").startswith("docker/build-push-action@")]
    options = build["with"]
    assert options["outputs"] == "type=oci,dest=artifacts/runtime.oci.tar"
    assert options["provenance"] == "mode=max"
    assert options["sbom"] == "generator=${{ steps.tools.outputs.sbom }}"
    assert options["platforms"] == "${{ steps.tools.outputs.platform }}"
    assert options.get("push", False) is False and options.get("load", False) is False
    tag, = options["tags"].splitlines()
    names = set()
    for image in job["strategy"]["matrix"]["image"]:
        for commit in ("a" * 40, "b" * 40):
            name = tag.replace("${{ github.repository }}", "owner/repository").replace(
                "${{ matrix.image }}", image).replace("${{ github.sha }}", commit)
            assert name == f"ghcr.io/owner/repository/{image}:{commit}"
            names.add(name)
    assert len(names) == 2 * len(job["strategy"]["matrix"]["image"])


def test_signing_permissions_and_exact_archive_contract():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    signed = jobs["signed-image-evidence"]
    assert signed["if"] == "github.event_name == 'push'"
    assert signed["permissions"] == {"contents": "read", "actions": "read",
                                     "id-token": "write", "attestations": "write"}
    assert set(signed["needs"]) == set(jobs) - {"signed-image-evidence"}
    for name, job in jobs.items():
        if name != "signed-image-evidence":
            assert not {"id-token", "attestations"} & set(job.get("permissions", {}))
            assert "if" not in job
        for step in job["steps"]:
            if "uses" in step:
                commit = step["uses"].rsplit("@", 1)[1]
                assert len(commit) == 40 and set(commit) <= set("0123456789abcdef")
    signing, = [step for step in signed["steps"] if step.get("id") == "attest"]
    assert signing["uses"] == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    assert signing["with"] == {"subject-path": "artifacts/runtime.oci.tar", "push-to-registry": False,
                               "create-storage-record": False}
    verification, = [step["run"] for step in signed["steps"] if "GH_TOKEN" in step.get("env", {})]
    for flag in ("--repo", "--signer-workflow", "--source-ref", "--source-digest", "--deny-self-hosted-runners",
                 '--bundle "$ATTESTATION_BUNDLE"'):
        assert flag in verification
    assert "continue-on-error" not in json.dumps(workflow)


def verifier_release_fixture(tmp_path, *, symlink=False):
    release = io.BytesIO()
    with tarfile.open(fileobj=release, mode="w:gz") as archive:
        member = tarfile.TarInfo("gh-test/bin/gh")
        if symlink:
            member.type = tarfile.SYMTYPE
            member.linkname = "/untrusted"
            archive.addfile(member)
        else:
            member.size = 6
            archive.addfile(member, io.BytesIO(b"binary"))
    metadata = {"version": "2.102.0", "url": "https://github.com/cli/cli/releases/download/v2.102.0/test.tar.gz",
                "member": "gh-test/bin/gh", "sha256": hashlib.sha256(release.getvalue()).hexdigest()}
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements/github-cli.json").write_text(json.dumps(metadata), encoding="utf-8")
    return release.getvalue()


def test_verifier_extracts_only_hash_checked_regular_binary(tmp_path, monkeypatch):
    release = verifier_release_fixture(tmp_path)
    monkeypatch.setattr(GH, "ROOT", tmp_path)
    destination = tmp_path / "verifier"
    GH.install(destination, opener=lambda *args, **kwargs: io.BytesIO(release))
    assert list(destination.rglob("*")) == [destination / "bin", destination / "bin/gh"]
    assert (destination / "bin/gh").read_bytes() == b"binary"
    with pytest.raises(ValueError, match="must be new"):
        GH.install(destination)


@pytest.mark.parametrize("symlink,corrupt", [(True, False), (False, True)])
def test_invalid_verifier_release_cannot_leave_executable(tmp_path, monkeypatch, symlink, corrupt):
    release = verifier_release_fixture(tmp_path, symlink=symlink)
    monkeypatch.setattr(GH, "ROOT", tmp_path)
    if corrupt:
        release += b"unexpected bytes"
    destination = tmp_path / "verifier"
    with pytest.raises(ValueError):
        GH.install(destination, opener=lambda *args, **kwargs: io.BytesIO(release))
    assert not destination.exists()
