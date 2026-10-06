"""Maintained runtime inputs and mandatory coverage fail closed on drift."""

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PINS = load("verify-image-pins")
SCAN = load("scan-images")


@pytest.fixture
def service_tree(tmp_path):
    for directory in ("requirements", "docker", "deploy/service-builds"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    for filename in ("frontend/Dockerfile", "deploy/qualification/compose.yaml"):
        target = tmp_path / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / filename, target)
    for path in ROOT.glob("docker-compose*.yml"):
        shutil.copyfile(path, tmp_path / path.name)
    return tmp_path


def edit_manifest(root, function):
    path = root / "requirements/service-builds/manifest.json"
    manifest = json.loads(path.read_text())
    function(manifest)
    path.write_text(json.dumps(manifest))


def test_actual_recipes_inventory_and_deployed_roles_are_complete(service_tree):
    PINS.check_references(service_tree)
    images = PINS.inventory(service_tree)
    assert {name for name, value in images.items() if value["role"] == "derived-runtime"} == set(PINS.SERVICES)
    assert {name for name, value in images.items() if value["role"] == "runtime"} == {"prometheus"}
    assert all("@sha256:" in value["reference"] for value in images.values() if value["role"] == "build-only")


@pytest.mark.parametrize("mutation", ["missing_service", "missing_base", "unknown_name", "wrong_role", "missing_role",
                                      "bad_digest", "changed_functional_version"])
def test_inventory_cannot_omit_or_reclassify_a_runtime(mutation):
    images = copy.deepcopy(PINS.inventory())
    if mutation == "missing_service":
        del images["postgres"]
    elif mutation == "missing_base":
        del images["postgres-base"]
    elif mutation == "unknown_name":
        images["unknown"] = images["postgres"]
    elif mutation == "wrong_role":
        images["postgres"]["role"] = "build-only"
    elif mutation == "missing_role":
        del images["node-exporter"]["role"]
    elif mutation == "bad_digest":
        images["redis-base"]["reference"] = "redis:7.4.11-alpine3.21@sha256:" + "z" * 64
    else:
        images["redis-base"]["reference"] = "redis:8.0.0-alpine3.21@sha256:" + "a" * 64
    with pytest.raises(ValueError):
        PINS.validate_inventory(images)


@pytest.mark.parametrize("mutation", ["missing_service", "missing_input", "missing_architecture",
                                      "wrong_apk_architecture",
                                      "wrong_apk_hash", "wrong_apk_signature", "wrong_source_hash", "wrong_source_host",
                                      "floating_toolchain", "wrong_runtime_tag", "boolean_schema", "wrong_prefix"])
def test_maintained_manifest_requires_exact_bound_inputs(service_tree, mutation):
    def mutate(manifest):
        if mutation == "missing_service":
            del manifest["services"]["redis"]
        elif mutation == "missing_input":
            manifest["files"].pop("requirements/service-builds/gosu/go.sum")
        elif mutation == "missing_architecture":
            del manifest["packages"]["clickhouse"]["aarch64"]
        elif mutation == "wrong_apk_architecture":
            manifest["packages"]["redis"]["aarch64"][0]["architecture"] = "x86_64"
        elif mutation == "wrong_apk_hash":
            manifest["packages"]["redis"]["aarch64"][0]["sha256"] = "a" * 64
        elif mutation == "wrong_apk_signature":
            manifest["packages"]["clickhouse"]["x86_64"][0]["signature_members"] = []
        elif mutation == "wrong_source_hash":
            manifest["components"]["gosu"]["source_sha256"] = "b" * 64
        elif mutation == "wrong_source_host":
            manifest["components"]["gosu"]["source_url"] = "https://example.invalid/source.tar.gz"
        elif mutation == "floating_toolchain":
            manifest["toolchain"]["gotoolchain"] = "auto"
        elif mutation == "wrong_runtime_tag":
            manifest["services"]["postgres"]["runtime_tag"] = "shadai/postgres:latest"
        elif mutation == "boolean_schema":
            manifest["schema"] = True
        else:
            manifest["components"]["gosu"]["archive_prefix"] = "unexpected-source"
    edit_manifest(service_tree, mutate)
    with pytest.raises(ValueError):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


def test_recipe_bytes_tampering_is_detected(service_tree):
    path = service_tree / "deploy/service-builds/Dockerfile.redis"
    path.write_bytes(path.read_bytes().replace(b"--no-network", b"--allow-untrusted"))
    with pytest.raises(ValueError, match="hash mismatch"):
        PINS.check_references(service_tree)


@pytest.mark.parametrize("replacement", ["build_only", "wrong_recipe", "missing_build_policy"])
def test_compose_cannot_deploy_a_base_or_unbound_local_tag(service_tree, replacement):
    path = service_tree / "docker-compose.yml"
    content = path.read_text()
    images = PINS.inventory(service_tree)
    if replacement == "build_only":
        content = content.replace(images["redis"]["reference"], images["redis-base"]["reference"])
    elif replacement == "wrong_recipe":
        content = content.replace("dockerfile: deploy/service-builds/Dockerfile.redis",
                                  "dockerfile: docker/Dockerfile.api")
    else:
        content = content.replace("    pull_policy: build\n", "")
    path.write_text(content)
    with pytest.raises(ValueError):
        PINS.check_references(service_tree)


def test_release_sources_and_only_approved_module_difference():
    directory = ROOT / "requirements/service-builds/node-exporter"
    before = (directory / "upstream.go.mod").read_text()
    after = (directory / "go.mod").read_text()
    assert after == before.replace("golang.org/x/crypto v0.54.0", "golang.org/x/crypto v0.55.0").replace(
        "golang.org/x/text v0.40.0", "golang.org/x/text v0.41.0")
    added_sums = set((directory / "go.sum").read_text().splitlines()) - \
        set((directory / "upstream.go.sum").read_text().splitlines())
    assert len(added_sums) == 4
    assert all(line.startswith(("golang.org/x/crypto v0.55.0", "golang.org/x/text v0.41.0")) for line in added_sums)
    gosu = ROOT / "requirements/service-builds/gosu"
    assert (gosu / "go.mod").read_bytes() == (gosu / "upstream.go.mod").read_bytes()
    assert (gosu / "go.sum").read_bytes() == (gosu / "upstream.go.sum").read_bytes()


def test_runtime_recipes_keep_native_authentication_and_compiler_guards():
    for service in PINS.SERVICES:
        recipe = (ROOT / f"deploy/service-builds/Dockerfile.{service}").read_text()
        assert "--allow-untrusted" not in recipe and "apk upgrade" not in recipe
        if service in {"redis", "clickhouse"}:
            assert "apk add --no-network" in recipe
            assert "ARG TARGETARCH" in recipe and "amd64) arch=x86_64" in recipe and "arm64) arch=aarch64" in recipe
            assert "sha256sum -c -" in recipe and "apk info -e" in recipe
            version = "3.3.7-r2" if service == "redis" else "3.5.9-r0"
            assert f"apk info -e 'libcrypto3={version}' 'libssl3={version}'" in recipe
            assert "--exists" not in recipe
        else:
            for guard in ("GOTOOLCHAIN=local", "GOSUMDB=sum.golang.org", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0",
                          "go mod verify", "go list -m all | cmp", "go build -trimpath -buildvcs=false"):
                assert guard in recipe
            assert "USER " not in recipe  # The exact official runtime user/entrypoint is inherited.


@pytest.mark.parametrize("version", ["go1.26.6", "1.26.6", "v1.26.6"])
def test_go_standard_library_inventory_uses_one_semantic_version(version):
    assert SCAN.package_key(f"pkg:golang/stdlib@{version}") == ("golang", "stdlib", "v1.26.6")


def test_service_sbom_retains_entire_go_and_os_inventory():
    purls = ["pkg:apk/alpine/libcrypto3@3.5.9-r0", "pkg:golang/stdlib@go1.26.6",
             "pkg:golang/golang.org/x/crypto@v0.55.0"]
    sbom = {"packages": [{"externalRefs": [{"referenceType": "purl", "referenceLocator": p}]} for p in purls]}
    assert SCAN.spdx_inventory(sbom, service=True) == {SCAN.package_key(p) for p in purls}
    sbom["packages"].append({"externalRefs": [{"referenceType": "purl",
                                              "referenceLocator": "pkg:npm/unexpected@1.0.0"}]})
    with pytest.raises(ValueError, match="Unsupported"):
        SCAN.spdx_inventory(sbom, service=True)


def test_build_only_names_cannot_be_scanned_as_pretend_runtime(tmp_path):
    output = tmp_path / "output"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/scan-images.py"), "--input", "absent.oci.tar",
                             "--image", "postgres-base", "--platform", "linux/amd64", "--output", str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and not output.exists()


def test_every_derived_runtime_architecture_is_gated_and_then_signed():
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    job = jobs["derived-service-builds"]
    matrix = job["strategy"]["matrix"]
    assert set(matrix["service"]) == set(PINS.SERVICES)
    assert set(matrix["os"]) == {"ubuntu-latest", "ubuntu-24.04-arm"}
    assert job["strategy"]["fail-fast"] is False and "if" not in job
    build, = [step["with"] for step in job["steps"] if step.get("uses", "").startswith("docker/build-push-action@")]
    assert build["outputs"] == "type=oci,dest=artifacts/runtime.oci.tar"
    assert build["provenance"] == "mode=max" and "generator=" in build["sbom"]
    assert build.get("push", False) is False
    scanner, = [step["run"] for step in job["steps"] if "scripts/scan-images.py" in step.get("run", "")]
    assert "verify-oci-evidence.py" in scanner and "--image '${{ matrix.service }}'" in scanner
    signed = jobs["signed-image-evidence"]
    assert "derived-service-builds" in signed["needs"]
    assert set(signed["strategy"]["matrix"]["image"]) == set(PINS.APP_IMAGES) | set(PINS.SERVICES)
    assert signed["if"] == "github.event_name == 'push'"
    assert not any(step.get("continue-on-error") for step in job["steps"])
