"""Maintained runtime inputs and mandatory coverage fail closed on drift."""

import copy
import hashlib
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


@pytest.mark.parametrize("service", ["postgres", "clickhouse", "redis"])
@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_zlib_native_matrix_is_exact_and_other_patch_versions_are_retained(service, arch):
    manifest = PINS.check_service_builds(ROOT, PINS.inventory())
    entries = manifest["packages"][service][arch]
    zlib, = [entry for entry in entries if entry["package"] == "zlib"]
    assert zlib["version"] == "1.3.2-r1" and type(zlib["bytes"]) is int
    branch = "v3.21" if service == "redis" else "v3.24"
    assert zlib["url"] == f"https://dl-cdn.alpinelinux.org/alpine/{branch}/main/{arch}/zlib-1.3.2-r1.apk"
    assert {entry["package"] for entry in entries} == (
        {"zlib"} if service == "postgres" else {"libcrypto3", "libssl3", "zlib"})
    for entry in entries:
        if entry["package"] != "zlib":
            assert entry["version"] == ("3.3.7-r2" if service == "redis" else "3.5.9-r0")


@pytest.mark.parametrize("duplicate", ["schema", "apk-field", "service", "architecture", "opaque"])
def test_raw_service_manifest_rejects_duplicate_object_keys_at_any_depth(service_tree, duplicate):
    path = service_tree / "requirements/service-builds/manifest.json"
    manifest = json.loads(path.read_text())
    if duplicate == "schema":
        target, key, first = manifest, "schema", 0
    elif duplicate == "apk-field":
        target, key, first = manifest["packages"]["postgres"]["x86_64"][0], "version", "0.0.0-r0"
    elif duplicate == "service":
        target, key, first = manifest["services"], "redis", {}
    elif duplicate == "architecture":
        target, key, first = manifest["packages"]["postgres"], "x86_64", []
    else:
        manifest["opaque"] = {"nested": {"version": "opaque"}}
        target, key, first = manifest["opaque"]["nested"], "version", "discarded"
    raw = json.dumps(manifest, separators=(",", ":"))
    original = json.dumps(target, separators=(",", ":"))
    replacement = "{" + json.dumps(key) + ":" + json.dumps(first) + "," + original[1:]
    assert original in raw
    raw = raw.replace(original, replacement, 1)
    assert json.loads(raw) == manifest  # Ordinary decoding hides the duplicate's first value.
    path.write_text(raw)
    with pytest.raises(ValueError, match="Duplicate maintained service manifest key"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


def test_service_manifest_preserves_valid_data_and_case_distinct_opaque_keys(service_tree):
    path = service_tree / "requirements/service-builds/manifest.json"
    manifest = json.loads(path.read_text())
    manifest["opaque"] = {"nested": {"Version": "upper", "version": "lower"}}
    path.write_text(json.dumps(manifest))
    assert PINS.check_service_builds(service_tree, PINS.inventory(service_tree)) == manifest


@pytest.mark.parametrize("service", ["postgres", "clickhouse", "redis"])
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "extra-key", "version", "branch",
    "hash", "signature", "signature-type", "architecture", "bytes", "bool-bytes", "float-bytes",
    "missing-architecture", "unexpected-architecture", "missing-service", "unknown-service"])
def test_zlib_publisher_matrix_refuses_missing_extra_or_typed_alias_entries(service_tree, service, mutation):
    def mutate(manifest):
        packages = manifest["packages"]
        entries = packages[service]["aarch64"]
        entry = next(value for value in entries if value["package"] == "zlib")
        if mutation == "missing":
            entries.remove(entry)
        elif mutation == "duplicate":
            entries.append(copy.deepcopy(entry))
        elif mutation == "unknown":
            entry["package"] = "zlib-dev"
        elif mutation == "extra-key":
            entry["allow_untrusted"] = False
        elif mutation == "version":
            entry["version"] = "1.3.2-r0"
        elif mutation == "branch":
            entry["url"] = entry["url"].replace("v3.21" if service == "redis" else "v3.24", "v3.22")
        elif mutation == "hash":
            entry["sha256"] = "a" * 64
        elif mutation == "signature":
            entry["signature_members"] = [".SIGN.RSA.foreign.rsa.pub"]
        elif mutation == "signature-type":
            entry["signature_members"] = {"name": entry["signature_members"][0]}
        elif mutation == "architecture":
            entry["architecture"] = "x86_64"
        elif mutation in {"bytes", "bool-bytes", "float-bytes"}:
            entry["bytes"] = {"bytes": entry["bytes"] + 1, "bool-bytes": True,
                              "float-bytes": float(entry["bytes"])}[mutation]
        elif mutation == "missing-architecture":
            del packages[service]["x86_64"]
        elif mutation == "unexpected-architecture":
            packages[service]["armv7"] = copy.deepcopy(entries)
        elif mutation == "missing-service":
            del packages[service]
        else:
            packages["unknown"] = copy.deepcopy(packages[service])
    edit_manifest(service_tree, mutate)
    with pytest.raises(ValueError):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("service", ["postgres", "clickhouse", "redis"])
@pytest.mark.parametrize("mutation", ["online", "untrusted", "upgrade", "missing-zlib", "stale-version", "write-mount"])
def test_refreshed_hash_cannot_authorize_an_unsafe_apk_install(service_tree, service, mutation):
    name = f"deploy/service-builds/Dockerfile.{service}"
    path = service_tree / name
    recipe = path.read_text()
    changes = {"online": ("apk add --no-network", "apk add"),
               "untrusted": ("apk add --no-network", "apk add --no-network --allow-untrusted"),
               "upgrade": ("apk add --no-network", "apk upgrade --no-network"),
               "missing-zlib": (" /packages/zlib.apk \\\n", " \\\n"),
               "stale-version": ("'zlib=1.3.2-r1'", "'zlib=1.3.2-r0'"),
               "write-mount": ("target=/packages,ro", "target=/packages,rw")}
    before, after = changes[mutation]
    assert before in recipe
    path.write_text(recipe.replace(before, after))
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="offline signature/version checks"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


def test_zlib_hash_cannot_be_replaced_by_rehashing_recipe_and_manifest(service_tree):
    path = service_tree / "deploy/service-builds/Dockerfile.postgres"
    old = "63aeea03c15a2f9018f81805cfc8aa926bdf5cd68921f22149c2fbb5d0ee9f47"
    path.write_bytes(path.read_bytes().replace(old.encode(), b"a" * 64))
    def mutate(manifest):
        manifest["packages"]["postgres"]["x86_64"][0]["sha256"] = "a" * 64
        manifest["files"]["deploy/service-builds/Dockerfile.postgres"] = hashlib.sha256(path.read_bytes()).hexdigest()
    edit_manifest(service_tree, mutate)
    with pytest.raises(ValueError, match="publisher"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("mutation", ["packages", "architectures", "entries", "entry", "key", "string",
                                      "size", "signatures", "signature"])
def test_apk_matrix_rejects_nonbuiltin_containers_and_scalar_subclasses(monkeypatch, mutation):
    class Mapping(dict):
        pass

    class Sequence(list):
        pass

    class Text(str):
        pass

    class Number(int):
        pass

    images = PINS.inventory()
    manifest = json.loads((ROOT / "requirements/service-builds/manifest.json").read_bytes())
    architectures = manifest["packages"]["postgres"]
    entries = architectures["x86_64"]
    entry = entries[0]
    if mutation == "packages":
        manifest["packages"] = Mapping(manifest["packages"])
    elif mutation == "architectures":
        manifest["packages"]["postgres"] = Mapping(architectures)
    elif mutation == "entries":
        architectures["x86_64"] = Sequence(entries)
    elif mutation == "entry":
        entries[0] = Mapping(entry)
    elif mutation == "key":
        entry[Text("bytes")] = entry.pop("bytes")
    elif mutation == "string":
        entry["package"] = Text(entry["package"])
    elif mutation == "size":
        entry["bytes"] = Number(entry["bytes"])
    elif mutation == "signatures":
        entry["signature_members"] = Sequence(entry["signature_members"])
    else:
        entry["signature_members"][0] = Text(entry["signature_members"][0])
    def loads(raw, *, object_pairs_hook):
        assert object_pairs_hook is PINS._unique_service_manifest_object
        return manifest

    monkeypatch.setattr(PINS.json, "loads", loads)
    with pytest.raises(ValueError):
        PINS.check_service_builds(ROOT, images)


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
    assert after == before.replace("go 1.25.0\n", "go 1.26.0\n").replace(
        "golang.org/x/crypto v0.54.0", "golang.org/x/crypto v0.56.0").replace(
        "golang.org/x/text v0.40.0", "golang.org/x/text v0.41.0")
    added_sums = set((directory / "go.sum").read_text().splitlines()) - \
        set((directory / "upstream.go.sum").read_text().splitlines())
    assert len(added_sums) == 6
    assert all(line.startswith(("golang.org/x/crypto v0.55.0", "golang.org/x/crypto v0.56.0",
                                "golang.org/x/text v0.41.0")) for line in added_sums)
    gosu = ROOT / "requirements/service-builds/gosu"
    assert (gosu / "go.mod").read_text() == (gosu / "upstream.go.mod").read_text().replace(
        "go 1.20\n", "go 1.25.0\n").replace("golang.org/x/sys v0.1.0", "golang.org/x/sys v0.44.0")
    gosu_sums = set((gosu / "go.sum").read_text().splitlines()) - \
        set((gosu / "upstream.go.sum").read_text().splitlines())
    assert len(gosu_sums) == 2 and all(line.startswith("golang.org/x/sys v0.44.0") for line in gosu_sums)


@pytest.mark.parametrize("component,before,after", [
    ("gosu", "golang.org/x/sys v0.44.0", "golang.org/x/sys v0.1.0"),
    ("gosu", "golang.org/x/sys v0.44.0", "golang.org/x/sys v0.45.0"),
    ("gosu", "github.com/moby/sys/user v0.1.0", "github.com/moby/sys/user v0.2.0"),
    ("node-exporter", "golang.org/x/crypto v0.56.0", "golang.org/x/crypto v0.55.0"),
    ("node-exporter", "golang.org/x/text v0.41.0", "golang.org/x/text v0.42.0"),
    ("node-exporter", "go 1.26.0", "go 1.25.0"),
])
def test_refreshed_hash_cannot_authorize_stale_or_unapproved_go_delta(service_tree, component, before, after):
    import hashlib

    name = f"requirements/service-builds/{component}/go.mod"
    path = service_tree / name
    value = path.read_text().replace(before, after)
    path.write_text(value)
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="approved targeted dependency updates"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


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
        if service == "postgres":
            assert 'case "$(apk --print-arch)" in' in recipe and "ARG TARGETARCH" not in recipe
            assert "apk add --no-network /packages/zlib.apk" in recipe and "apk info -e 'zlib=1.3.2-r1'" in recipe
            assert "--mount=type=bind,from=build,source=/packages,target=/packages,ro" in recipe
            assert 'gosu --version | grep -F "1.19 (go1.26.6 " && test "$(gosu nobody id -u)" = 65534' in recipe


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
    archive, local = [step for step in job["steps"] if step.get("uses", "").startswith("docker/build-push-action@")]
    build = archive["with"]
    assert "if" not in archive and build["load"] is False
    assert build["outputs"] == "type=oci,dest=artifacts/runtime.oci.tar"
    assert build["provenance"] == "mode=max" and "generator=" in build["sbom"]
    assert build.get("push", False) is False
    assert local["if"] == "matrix.service == 'clickhouse'" and local["timeout-minutes"] == 5
    assert local["uses"] == archive["uses"] and job["steps"].index(local) == job["steps"].index(archive) + 1
    shared = {key: build[key] for key in ("builder", "context", "file", "tags", "push", "platforms")}
    assert local["with"] == {**shared, "load": True, "provenance": False, "sbom": False}
    scanner, = [step["run"] for step in job["steps"] if "scripts/scan-images.py" in step.get("run", "")]
    assert "verify-oci-evidence.py" in scanner and "--image '${{ matrix.service }}'" in scanner
    signed = jobs["signed-image-evidence"]
    assert "derived-service-builds" in signed["needs"]
    assert set(signed["strategy"]["matrix"]["image"]) == set(PINS.APP_IMAGES) | set(PINS.SERVICES)
    assert signed["if"] == "github.event_name == 'push'"
    assert not any(step.get("continue-on-error") for step in job["steps"])



def test_test_image_removes_complete_installer_after_locked_install_and_runtime_smoke():
    recipe = (ROOT / 'docker/Dockerfile.test').read_text()
    steps = [
        'requirements/build.txt', 'requirements/development.txt',
        'pip install --no-cache-dir --no-deps --no-build-isolation . ./agent',
        'python -m pip check', 'import pytest, shadai, shadai_agent.main',
        'python -m pip uninstall --yes pip', "shutil.rmtree('/usr/local/lib/python3.12/ensurepip')",
        "find_spec('pip') is None", "find_spec('ensurepip') is None",
        "Path('/usr/local/lib/python3.12/ensurepip').exists()",
        "Path('/usr/local/lib/python3.12').rglob('pip-*.whl')",
        "Path('/usr/local/lib/python3.12/site-packages').glob('pip*')",
        "Path('/usr/local/bin').glob('pip*')", 'useradd', 'USER 10001:10001',
    ]
    offsets = [recipe.index(step) for step in steps]
    assert offsets == sorted(offsets)
    assert recipe.count('import pytest, shadai, shadai_agent.main') == 2
    assert 'bom.cdx.json' not in recipe  # Remove the installer rather than an advisory manifest.
    assert 'ENTRYPOINT ["python", "/app/entrypoint.py"]' in recipe
    assert 'CMD ["python", "-m", "pytest"' in recipe
    for name in ('api', 'worker', 'collector'):
        assert 'pip uninstall' not in (ROOT / f'docker/Dockerfile.{name}').read_text()
