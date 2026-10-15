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


def load_models():
    spec = importlib.util.spec_from_file_location("component_scan_models", ROOT / "tests/component_scan_models.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


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
    # No externally pulled runtime remains: every deployed service image is built from a reviewed recipe.
    assert not any(value["role"] == "runtime" for value in images.values()) and "runtime" not in PINS.ROLES.values()
    assert all("@sha256:" in value["reference"] for value in images.values() if value["role"] == "build-only")
    assert images["prometheus-base"] == {"role": "build-only", "reference": "prom/prometheus:v3.15.0@sha256:"
                                         "efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e"}
    assert images["prometheus"] == {"role": "derived-runtime", "reference": "shadai/prometheus:3.15.0-maintained.3",
                                    "dockerfile": "deploy/service-builds/Dockerfile.prometheus"}


@pytest.mark.parametrize("mutation", ["missing_service", "missing_base", "unknown_name", "wrong_role", "missing_role",
                                      "bad_digest", "changed_functional_version", "external_runtime",
                                      "prometheus_base_deployed", "prometheus_other_release"])
def test_inventory_cannot_omit_or_reclassify_a_runtime(mutation):
    images = copy.deepcopy(PINS.inventory())
    if mutation == "external_runtime":
        images["prometheus"] = {"role": "runtime", "reference": images["prometheus-base"]["reference"]}
    elif mutation == "prometheus_base_deployed":
        images["prometheus-base"]["role"] = "derived-runtime"
    elif mutation == "prometheus_other_release":
        images["prometheus-base"]["reference"] = "prom/prometheus:v3.16.0@sha256:" + "a" * 64
    elif mutation == "missing_service":
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
                                      "floating_toolchain", "wrong_runtime_tag", "boolean_schema", "wrong_prefix",
                                      "archive_extra_field", "zip_untyped", "zip_wrong_kind", "zip_wrong_h1",
                                      "zip_wrong_module_version", "zip_wrong_hash", "zip_wrong_url", "zip_wrong_prefix",
                                      "zip_other_commit", "zip_missing_ui", "ui_wrong_url", "ui_wrong_hash",
                                      "ui_bool_bytes", "ui_extra_field", "prometheus_version_drift",
                                      "prometheus_missing_notice"])
def test_maintained_manifest_requires_exact_bound_inputs(service_tree, mutation):
    def mutate(manifest):
        prometheus = manifest["components"]["prometheus"]
        if mutation == "missing_service":
            del manifest["services"]["redis"]
        elif mutation == "archive_extra_field":
            manifest["components"]["gosu"]["source_kind"] = "github-archive"
        elif mutation == "zip_untyped":
            del prometheus["source_kind"]
        elif mutation == "zip_wrong_kind":
            prometheus["source_kind"] = "github-archive"
        elif mutation == "zip_wrong_h1":
            prometheus["zip_h1"] = "h1:" + "A" * 43 + "="
        elif mutation == "zip_wrong_module_version":
            prometheus["module_version"] = "v0.316.0"
        elif mutation == "zip_wrong_hash":
            prometheus["source_sha256"] = "c" * 64
        elif mutation == "zip_wrong_url":
            prometheus["source_url"] = "https://codeload.github.com/prometheus/prometheus/tar.gz/" + \
                prometheus["commit"]
        elif mutation == "zip_wrong_prefix":
            prometheus["archive_prefix"] = "prometheus-" + prometheus["commit"]
        elif mutation == "zip_other_commit":
            prometheus["commit"] = "d" * 40
        elif mutation == "zip_missing_ui":
            del prometheus["web_ui"]
        elif mutation == "ui_wrong_url":
            prometheus["web_ui"]["url"] = prometheus["web_ui"]["url"].replace("3.15.0.tar.gz", "3.16.0.tar.gz")
        elif mutation == "ui_wrong_hash":
            prometheus["web_ui"]["sha256"] = "e" * 64
        elif mutation == "ui_bool_bytes":
            prometheus["web_ui"]["bytes"] = True
        elif mutation == "ui_extra_field":
            prometheus["web_ui"]["allow_unverified"] = False
        elif mutation == "prometheus_version_drift":
            manifest["services"]["prometheus"]["functional_version"] = "3.15.1"
        elif mutation == "prometheus_missing_notice":
            del manifest["files"]["requirements/service-builds/prometheus/NOTICE"]
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
        "golang.org/x/sys v0.47.0", "golang.org/x/sys v0.48.0").replace(
        "golang.org/x/crypto v0.54.0", "golang.org/x/crypto v0.57.0").replace(
        "golang.org/x/net v0.57.0", "golang.org/x/net v0.60.0").replace(
        "golang.org/x/sync v0.22.0", "golang.org/x/sync v0.23.0").replace(
        "golang.org/x/text v0.40.0", "golang.org/x/text v0.42.0")
    maintained_sums = set((directory / "go.sum").read_text().splitlines())
    upstream_sums = set((directory / "upstream.go.sum").read_text().splitlines())
    added_sums = maintained_sums - upstream_sums
    assert len(added_sums) == 10
    assert all(line.startswith(("golang.org/x/crypto v0.57.0", "golang.org/x/net v0.60.0",
                                "golang.org/x/sync v0.23.0", "golang.org/x/sys v0.48.0",
                                "golang.org/x/text v0.42.0")) for line in added_sums)
    removed_sums = upstream_sums - maintained_sums  # Only the superseded publisher versions leave the tidy graph.
    assert len(removed_sums) == 10
    assert all(line.startswith(("golang.org/x/crypto v0.54.0", "golang.org/x/net v0.57.0",
                                "golang.org/x/sync v0.22.0", "golang.org/x/sys v0.47.0",
                                "golang.org/x/text v0.40.0")) for line in removed_sums)
    gosu = ROOT / "requirements/service-builds/gosu"
    assert (gosu / "go.mod").read_text() == (gosu / "upstream.go.mod").read_text().replace(
        "go 1.20\n", "go 1.25.0\n").replace(
        "github.com/moby/sys/user v0.1.0\n", "github.com/moby/sys/user v0.4.1\n").replace(
        "golang.org/x/sys v0.1.0", "golang.org/x/sys v0.44.0")
    gosu_sums = set((gosu / "go.sum").read_text().splitlines()) - \
        set((gosu / "upstream.go.sum").read_text().splitlines())
    assert gosu_sums == {
        "github.com/moby/sys/user v0.4.1 h1:RgjRlaDKi/Xmyrz4t8lyzXT6v2ooFeO/7xtchmhVWE0=",
        "github.com/moby/sys/user v0.4.1/go.mod h1:E9QsW5WRe1kUAf7kW8hXKwu1uhsZEAdPLYHYSDudF4Y=",
        "golang.org/x/sys v0.44.0 h1:ildZl3J4uzeKP07r2F++Op7E9B29JRUy+a27EibtBTQ=",
        "golang.org/x/sys v0.44.0/go.mod h1:4GL1E5IUh+htKOUEOaiffhrAeqysfVGipDYzABqnCmw=",
    }
    assert (gosu / "modules.txt").read_text().splitlines() == [
        "github.com/tianon/gosu", "github.com/moby/sys/user v0.4.1", "golang.org/x/sys v0.44.0"]
    prometheus = ROOT / "requirements/service-builds/prometheus"
    upstream = (prometheus / "upstream.go.mod").read_text()
    assert "go 1.26.0\n" in upstream and "toolchain" not in upstream
    assert (prometheus / "go.mod").read_text() == upstream.replace(
        "golang.org/x/sync v0.22.0", "golang.org/x/sync v0.23.0").replace(
        "golang.org/x/sys v0.47.0", "golang.org/x/sys v0.48.0").replace(
        "golang.org/x/text v0.41.0", "golang.org/x/text v0.42.0").replace(
        "golang.org/x/crypto v0.56.0", "golang.org/x/crypto v0.57.0").replace(
        "golang.org/x/net v0.58.0", "golang.org/x/net v0.60.0").replace(
        "golang.org/x/term v0.45.0", "golang.org/x/term v0.46.0")
    added = set((prometheus / "go.sum").read_text().splitlines()) - \
        set((prometheus / "upstream.go.sum").read_text().splitlines())
    removed = set((prometheus / "upstream.go.sum").read_text().splitlines()) - \
        set((prometheus / "go.sum").read_text().splitlines())
    assert len(added) == 12 and all(line.startswith((
        "golang.org/x/crypto v0.57.0", "golang.org/x/net v0.60.0", "golang.org/x/sync v0.23.0",
        "golang.org/x/sys v0.48.0", "golang.org/x/term v0.46.0", "golang.org/x/text v0.42.0")) for line in added)
    assert len(removed) == 12 and all(line.startswith((
        "golang.org/x/crypto v0.56.0", "golang.org/x/net v0.58.0", "golang.org/x/sync v0.22.0",
        "golang.org/x/sys v0.47.0", "golang.org/x/term v0.45.0", "golang.org/x/text v0.41.0")) for line in removed)
    modules = (prometheus / "modules.txt").read_text().splitlines()
    assert modules[0] == "github.com/prometheus/prometheus"
    assert {"golang.org/x/net v0.60.0", "golang.org/x/crypto v0.57.0", "golang.org/x/sys v0.48.0",
            "golang.org/x/text v0.42.0", "golang.org/x/term v0.46.0", "golang.org/x/sync v0.23.0"} <= set(modules)
    assert not any(line.startswith(("golang.org/x/net v0.58.0", "golang.org/x/crypto v0.56.0")) for line in modules)
    assert (prometheus / "LICENSE").read_text().startswith("                                 Apache License")
    assert "Prometheus" in (prometheus / "NOTICE").read_text()


@pytest.mark.parametrize("component,before,after", [
    ("gosu", "golang.org/x/sys v0.44.0", "golang.org/x/sys v0.1.0"),
    ("gosu", "golang.org/x/sys v0.44.0", "golang.org/x/sys v0.45.0"),
    ("gosu", "github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.1.0"),
    ("gosu", "github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.2.0"),
    ("gosu", "github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.4.0"),
    ("gosu", "github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.4.2"),
    ("gosu", "github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.4.10"),
    ("node-exporter", "golang.org/x/crypto v0.57.0", "golang.org/x/crypto v0.56.0"),
    ("node-exporter", "golang.org/x/net v0.60.0", "golang.org/x/net v0.57.0"),
    ("node-exporter", "golang.org/x/sys v0.48.0", "golang.org/x/sys v0.49.0"),
    ("node-exporter", "golang.org/x/text v0.42.0", "golang.org/x/text v0.43.0"),
    ("node-exporter", "go 1.26.0", "go 1.25.0"),
    ("prometheus", "golang.org/x/net v0.60.0", "golang.org/x/net v0.58.0"),
    ("prometheus", "golang.org/x/net v0.60.0", "golang.org/x/net v0.61.0"),
    ("prometheus", "golang.org/x/crypto v0.57.0", "golang.org/x/crypto v0.56.0"),
    ("prometheus", "golang.org/x/term v0.46.0", "golang.org/x/term v0.45.0"),
    ("prometheus", "go 1.26.0", "go 1.27.0"),
    ("prometheus", "github.com/prometheus/common v0.71.0", "github.com/prometheus/common v0.71.1"),
])
def test_refreshed_hash_cannot_authorize_stale_or_unapproved_go_delta(service_tree, component, before, after):
    import hashlib

    name = f"requirements/service-builds/{component}/go.mod"
    path = service_tree / name
    value = path.read_text()
    assert before in value
    value = value.replace(before, after)
    path.write_text(value)
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="approved targeted dependency updates"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("filename", ["go.mod", "go.sum", "modules.txt"])
def test_gosu_module_closure_tampering_is_detected(service_tree, filename):
    path = service_tree / "requirements/service-builds/gosu" / filename
    value = path.read_text()
    assert "github.com/moby/sys/user v0.4.1" in value
    path.write_text(value.replace("github.com/moby/sys/user v0.4.1", "github.com/moby/sys/user v0.4.0"))
    with pytest.raises(ValueError, match="input hash mismatch"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("revision", [2, 4, True, "3"])
def test_global_recipe_revision_cannot_drift(service_tree, revision):
    edit_manifest(service_tree, lambda manifest: manifest.update(recipe_version=revision))
    with pytest.raises(ValueError, match="unknown maintained service manifest"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("service", PINS.SERVICES)
def test_refreshed_hash_cannot_authorize_a_stale_recipe_label(service_tree, service):
    name = f"deploy/service-builds/Dockerfile.{service}"
    path = service_tree / name
    value = path.read_text()
    assert 'io.shadai.maintenance.recipe="3"' in value
    path.write_text(value.replace('io.shadai.maintenance.recipe="3"', 'io.shadai.maintenance.recipe="2"'))
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="approved global revision"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))


@pytest.mark.parametrize("mutation", ["comment", "run", "continued-run", "env", "other-label", "missing-label",
                                      "later-unquoted", "later-single-quoted", "later-quoted-key",
                                      "duplicate-approved", "same-instruction-override"])
def test_rehashed_recipe_label_decoys_and_overrides_are_rejected(service_tree, mutation):
    name = "deploy/service-builds/Dockerfile.clickhouse"
    path = service_tree / name
    value = path.read_text()
    label = "io.shadai.maintenance.recipe"
    if mutation in {"comment", "run", "continued-run", "env", "other-label", "missing-label"}:
        value = value.replace(f'{label}="3"', f"{label}=2")
        decoys = {"comment": f'# {label}="3"\n', "run": f'RUN echo \'{label}="3"\'\n',
                  "continued-run": f'RUN echo \\\n  {label}="3"\n',
                  "env": f'ENV NOTE=\'{label}="3"\'\n', "other-label": f'LABEL note=\'{label}="3"\'\n',
                  "missing-label": f'# {label}="3"\n'}
        value += decoys[mutation]
        if mutation == "missing-label":
            value = value.replace(f"{label}=2", "io.shadai.other=2")
    elif mutation == "same-instruction-override":
        value = value.replace(f'{label}="3"', f'{label}="3" {label}=2')
    else:
        overrides = {"later-unquoted": f"{label}=2", "later-single-quoted": f"{label}='2'",
                     "later-quoted-key": f'"{label}"=2', "duplicate-approved": f"{label}=3"}
        value += "LABEL " + overrides[mutation] + "\n"
    path.write_text(value)
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="approved global revision"):
        PINS.check_service_builds(service_tree, PINS.inventory(service_tree))
    with pytest.raises(ValueError, match="approved global revision"):
        PINS.check_references(service_tree)


@pytest.mark.parametrize("assignment", [
    "io.shadai.maintenance.recipe=3", '"io.shadai.maintenance.recipe"="3"',
    "'io.shadai.maintenance.recipe'='3'", "io.shadai.maintenance.recipe='3'",
    "io.shadai.maintenance.recipe=\\3", "io.shadai.maintenance.recipe=\\\n3",
    "io.shadai.maintenance.\\\nrecipe=3", "io.shadai.maintenance.recipe=\\\n# ignored comment \\\n3",
])
def test_rehashed_recipe_accepts_actual_quoted_unquoted_and_continued_labels(service_tree, assignment):
    name = "deploy/service-builds/Dockerfile.clickhouse"
    path = service_tree / name
    value = path.read_text().replace('LABEL io.shadai.maintenance.recipe="3"', "  lAbEl\t" + assignment)
    path.write_text(value)
    edit_manifest(service_tree, lambda manifest: manifest["files"].update(
        {name: hashlib.sha256(path.read_bytes()).hexdigest()}))
    PINS.check_service_builds(service_tree, PINS.inventory(service_tree))
    PINS.check_references(service_tree)


@pytest.mark.parametrize("recipe", [
    'LABEL io.shadai.maintenance.recipe="3"\n', "LABEL io.shadai.maintenance.recipe 3\n",
    "# escape=\\\nLABEL io.shadai.maintenance.recipe=3\n",
    "# comment\n# escape=`\nLABEL io.shadai.maintenance.recipe=\\\n3\n",
    '\ufeff# escape=\\\nLABEL note=#inline-hash io.shadai.maintenance.recipe="3"\n',
])
def test_recipe_label_parser_accepts_literal_revision_forms(recipe):
    assert PINS.maintenance_recipe_labels(recipe) == ["3"]


@pytest.mark.parametrize("recipe", [
    'LABEL io.shadai.maintenance.recipe="3\n', "LABEL\n", "LABEL only-key\n", "LABEL =3\n",
    "LABEL io.shadai.maintenance.recipe=3 broken\n", 'LABEL "${KEY}"=3\n',
    "LABEL io.shadai.maintenance.recipe=3\\\n", "RUN <<EOF\nLABEL io.shadai.maintenance.recipe=3\nEOF\n",
    "ONBUILD RUN <<EOF\nLABEL io.shadai.maintenance.recipe=3\nEOF\n",
    "# escape=`\nLABEL io.shadai.maintenance.recipe=3\n",
    "\v# escape=`\nLABEL io.shadai.maintenance.recipe=3\n",
    'LABEL note=x\u00a0io.shadai.maintenance.recipe="3"\n',
    "# escape=!\nLABEL io.shadai.maintenance.recipe=3\n",
    "# escape=\\\n# escape=\\\nLABEL io.shadai.maintenance.recipe=3\n",
])
def test_recipe_label_parser_refuses_malformed_dynamic_or_unsupported_syntax(recipe):
    with pytest.raises(ValueError, match="maintained recipe"):
        PINS.maintenance_recipe_labels(recipe)


def test_recipe_label_parser_ignores_physical_line_and_escaped_escape_decoys():
    label = "io.shadai.maintenance.recipe"
    assert PINS.maintenance_recipe_labels(f'RUN echo x\vLABEL {label}="3"\n') == []
    escaped = "RUN echo " + "\\" * 3 + f"\nLABEL {label}=2\n"
    assert PINS.maintenance_recipe_labels(escaped) == ["2"]


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
        if service == "prometheus":
            # Publisher module zip authenticated by the Go checksum database, pinned by SHA256, prebuilt UI
            # pinned by SHA256, upstream build tags and both binaries smoke-tested in the final runtime.
            manifest = json.loads((ROOT / "requirements/service-builds/manifest.json").read_text())
            component = manifest["components"]["prometheus"]
            for guard in ("go mod download -json github.com/prometheus/prometheus@v0.315.0",
                          "grep -F '\"Sum\": \"" + component["zip_h1"] + "\",'",
                          "grep -F '\"Hash\": \"" + component["commit"] + "\",'",
                          component["source_sha256"] + "  /go/pkg/mod/cache/download/github.com/prometheus/prometheus"
                          "/@v/v0.315.0.zip' | sha256sum -c -",
                          "unzip -q /go/pkg/mod/cache/download/github.com/prometheus/prometheus/@v/v0.315.0.zip",
                          "wget -O /tmp/web-ui.tar.gz " + component["web_ui"]["url"],
                          component["web_ui"]["sha256"] + "  /tmp/web-ui.tar.gz' | sha256sum -c -",
                          "cp embed.go.tmpl embed.go", "gzip -c", "sort -z | xargs -0 echo //go:embed >> embed.go",
                          "echo var EmbedFS embed.FS >> embed.go",
                          "-tags netgo,builtinassets", "version.Version=3.15.0-shadai.3",
                          "version.Revision=" + component["commit"], "-o /out/prometheus ./cmd/prometheus",
                          "-o /out/promtool ./cmd/promtool", "COPY --from=build /out/prometheus /out/promtool /bin/",
                          "COPY --from=build /src/LICENSE /src/NOTICE /usr/local/share/licenses/shadai/prometheus/",
                          'io.shadai.maintenance.version="v3.15.0-shadai.3"',
                          "RUN /bin/prometheus --version && /bin/promtool --version"):
                assert guard in recipe, guard
            assert recipe.count("go build ") == 2 and "gzip -n" not in recipe  # busybox gzip has no -n flag.
            assert "codeload.github.com" not in recipe and "GOFLAGS=-mod=mod" not in recipe
        if service == "postgres":
            assert 'case "$(apk --print-arch)" in' in recipe and "ARG TARGETARCH" not in recipe
            assert "apk add --no-network /packages/zlib.apk" in recipe and "apk info -e 'zlib=1.3.2-r1'" in recipe
            assert "--mount=type=bind,from=build,source=/packages,target=/packages,ro" in recipe
            assert 'gosu --version | grep -F "1.19 (go1.26.9 " && test "$(gosu nobody id -u)" = 65534' in recipe


@pytest.mark.parametrize("version", ["go1.26.9", "1.26.9", "v1.26.9"])
def test_go_standard_library_inventory_uses_one_semantic_version(version):
    assert SCAN.package_key(f"pkg:golang/stdlib@{version}") == ("golang", "stdlib", "v1.26.9")


def test_service_sbom_retains_entire_go_and_os_inventory():
    purls = ["pkg:apk/alpine/libcrypto3@3.5.9-r0", "pkg:golang/stdlib@go1.26.9",
             "pkg:golang/golang.org/x/crypto@v0.55.0"]
    sbom = {"packages": [{"externalRefs": [{"referenceType": "purl", "referenceLocator": p}]} for p in purls]}
    sbom["packages"][1]["name"] = "stdlib"
    sbom["packages"][2]["name"] = "golang.org/x/crypto"
    assert SCAN.spdx_inventory(sbom, service=True) == {SCAN.package_key(p) for p in purls}
    sbom["packages"].append({"externalRefs": [{"referenceType": "purl",
                                              "referenceLocator": "pkg:npm/unexpected@1.0.0"}]})
    with pytest.raises(ValueError, match="Unsupported"):
        SCAN.spdx_inventory(sbom, service=True)


def test_reference_only_infrastructure_scan_no_longer_exists(tmp_path):
    output = tmp_path / "output"
    result = subprocess.run([sys.executable, str(ROOT / "scripts/scan-images.py"), "--infrastructure",
                             "--platform", "linux/amd64", "--output", str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2 and not output.exists()
    assert "the following arguments are required: --input, --image" in result.stderr
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert "infrastructure-security" not in workflow["jobs"]
    assert "infrastructure" not in json.dumps(workflow["jobs"]["signed-image-evidence"]["needs"])
    assert "--infrastructure" not in (ROOT / ".github/workflows/ci.yml").read_text()


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


def test_go_purl_queries_carry_the_manifest_module_versions_of_the_reviewed_sources():
    # Go advisory ranges are keyed by module version: github.com/prometheus/prometheus v0.315.0 is release 3.15.0,
    # so a purl at 3.15.0 would compare above every affected range and never match; gosu and node_exporter
    # release numbers equal their module versions. CPE queries keep the release number that NVD CPEs use.
    scanner = load("component_scanner")
    components = json.loads((ROOT / "requirements/service-builds/manifest.json").read_bytes())["components"]
    assert set(scanner.MODULE_VERSIONS) == set(scanner.RELEASES) == set(components)
    assert scanner.MODULE_VERSIONS["prometheus"] == components["prometheus"]["module_version"] == "v0.315.0"
    assert scanner.RELEASES["prometheus"] == components["prometheus"]["tag"].removeprefix("v") == "3.15.0"
    for name in ("gosu", "node-exporter"):
        assert scanner.MODULE_VERSIONS[name] == scanner.RELEASES[name] == components[name]["tag"].removeprefix("v")
    partition = scanner.partition(load_models().capture("prometheus")["sbom"], service="prometheus",
                                  package_key=SCAN.package_key)
    for claim in partition["components"]:
        if claim["observed_unversioned"]:
            assert claim["queries"][0] == "pkg:golang/github.com/prometheus/prometheus@v0.315.0"
            assert claim["queries"][1] == "cpe:2.3:a:prometheus:prometheus:3.15.0:*:*:*:*:*:*:*"
