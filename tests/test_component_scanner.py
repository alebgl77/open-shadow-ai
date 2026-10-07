"""Native captured observations and adversarial complementary coverage contracts."""

import base64
import copy
import errno
import importlib.util
import itertools
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/component-scanner"


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load("scan-images")
components = load("component_scanner")
source = load("component_source")


def capture(service="postgres", arch="amd64"):
    return json.loads((FIXTURES / f"{service}-{arch}.json").read_text(encoding="utf-8"))


def plan(fixture):
    return components.partition(fixture["sbom"], service=fixture["capture"]["service"], package_key=scan.package_key)


@pytest.mark.parametrize("service,count", [("postgres", 3), ("node-exporter", 4), ("redis", 2)])
@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_actual_native_six_captures_preserve_observations_and_exact_native_inventory(service, count, arch):
    fixture = capture(service, arch)
    original = copy.deepcopy(fixture)
    partition = plan(fixture)
    assert sum(len(claim["queries"]) for claim in partition["components"]) == count
    for claim in partition["components"]:
        assert claim["original_package"] in fixture["sbom"]["packages"]
        assert claim["original_binary_file"] in fixture["sbom"]["files"]
        if claim["observed_unversioned"]:
            assert claim["original_package"]["versionInfo"] == "UNKNOWN"
            assert claim["binary_version_claim"] is None
            assert "@v" not in claim["queries"][0] and "shadai" not in claim["queries"][0]
    findings = scan.gate(fixture["trivy"], expected=partition["native"], complement=partition,
                         image_id=fixture["capture"]["image_config"], artifact="/input/layout",
                         platform=f"linux/{arch}")
    assert isinstance(findings, list)
    assert fixture == original


def test_exact_nine_query_plan():
    queries = [query for service in ("postgres", "node-exporter", "redis")
               for claim in plan(capture(service))["components"] for query in claim["queries"]]
    assert queries == [
        "pkg:golang/github.com/tianon/gosu@1.19", "cpe:2.3:a:tianon:gosu:1.19:*:*:*:*:*:*:*",
        "cpe:2.3:a:postgresql:postgresql:16.15:*:*:*:*:*:*:*",
        "cpe:2.3:a:busybox:busybox:1.38.0:*:*:*:*:*:*:*",
        "pkg:golang/github.com/prometheus/node_exporter@1.12.1",
        "cpe:2.3:a:prometheus:node-exporter:1.12.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:prometheus:node_exporter:1.12.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:redislabs:redis:7.4.11:*:*:*:*:*:*:*",
        "cpe:2.3:a:redis:redis:7.4.11:*:*:*:*:*:*:*",
    ]


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "version", "path", "purl", "cpe", "file", "checksum",
                                     "disconnected", "unknown", "identityless", "unsupported"])
def test_partition_refuses_incomplete_ambiguous_or_changed_captured_identity(mutation):
    fixture = capture()
    sbom = fixture["sbom"]
    claim = plan(fixture)["components"][0]
    package = next(p for p in sbom["packages"] if p["SPDXID"] == claim["spdx_id"])
    if mutation == "missing":
        sbom["packages"].remove(package)
    elif mutation == "duplicate":
        sbom["packages"].append(copy.deepcopy(package))
    elif mutation == "version":
        package["versionInfo"] = "1.19"
    elif mutation == "path":
        package["sourceInfo"] += "/wrong"
    elif mutation == "purl":
        package["externalRefs"][0]["referenceLocator"] += "@1.19"
    elif mutation == "cpe":
        package["externalRefs"][1]["referenceLocator"] += ":wrong"
    elif mutation == "file":
        next(f for f in sbom["files"] if f["fileName"] == "usr/local/bin/gosu")["fileName"] = "wrong"
    elif mutation == "checksum":
        next(f for f in sbom["files"] if f["fileName"] == "usr/local/bin/gosu")["checksums"] = []
    elif mutation == "disconnected":
        sbom["relationships"] = [r for r in sbom["relationships"] if not (
            r.get("relatedSpdxElement") == package["SPDXID"] and r["relationshipType"] == "CONTAINS")]
    else:
        p = copy.deepcopy(package)
        p["SPDXID"] += "-foreign"
        p["name"] = "foreign"
        p["externalRefs"] = [] if mutation == "identityless" else [
            {"referenceType": "purl", "referenceLocator": "pkg:npm/foreign@1.0" if mutation == "unsupported"
             else "pkg:golang/foreign"}]
        sbom["packages"].append(p)
        sbom["relationships"].append({"spdxElementId": components.DOCUMENT_ROOT,
                                      "relatedSpdxElement": p["SPDXID"], "relationshipType": "CONTAINS"})
    with pytest.raises(ValueError):
        plan(fixture)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "path", "root", "id", "purl", "layer"])
def test_trivy_unknown_exception_is_only_the_exact_original_main_module(mutation):
    fixture = capture()
    partition = plan(fixture)
    result = next(r for r in fixture["trivy"]["Results"] if r["Type"] == "gobinary")
    package = result["Packages"][0]
    if mutation == "missing":
        result["Packages"].remove(package)
    elif mutation == "duplicate":
        result["Packages"].append(copy.deepcopy(package))
    elif mutation == "path":
        result["Target"] += "/wrong"
    elif mutation == "root":
        package["Relationship"] = "direct"
    elif mutation == "id":
        package["ID"] += "@1.19"
    elif mutation == "purl":
        package["Identifier"]["PURL"] += "@1.19"
    elif mutation == "layer":
        package["Layer"]["Digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        scan.gate(fixture["trivy"], expected=partition["native"], complement=partition)


def source_inputs(fixture, directory):
    for name, text in fixture["source_inputs"].items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())


def bind(fixture, directory):
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    return source.bind(predicate, service=fixture["capture"]["service"],
                       platform="linux/" + fixture["capture"]["architecture"], selected_manifest=fixture["manifest"],
                       root=directory, service_manifest=fixture["service_manifest"],
                       expected_source={"repository": "alebgl77/open-shadow-ai", "commit": fixture["capture"]["merge"]})


@pytest.mark.parametrize("service", ["postgres", "node-exporter"])
@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_actual_historical_native_full_graph_and_terminal_anchor(service, arch, tmp_path):
    fixture = capture(service, arch)
    source_inputs(fixture, tmp_path)
    proof = bind(fixture, tmp_path)
    assert proof["binary_version_claim"] is None
    assert proof["authenticated_provenance"] is False
    assert proof["recipe_sha256"] == fixture["service_manifest"]["files"][proof["recipe"]]


@pytest.mark.parametrize("service", ["postgres", "node-exporter"])
def test_actual_old_source_cannot_project_current_recipe(service):
    fixture = capture(service)
    fixture["service_manifest"] = json.loads((ROOT / "requirements/service-builds/manifest.json").read_text())
    with pytest.raises(ValueError, match="stale or different"):
        bind(fixture, ROOT)


@pytest.mark.parametrize("service", ["postgres", "node-exporter"])
def test_actual_captured_native_recipe_and_locks_bind_matching_source_rootfs(service, tmp_path):
    fixture = capture(service, "current-amd64")
    source_inputs(fixture, tmp_path)
    proof = bind(fixture, tmp_path)
    partition = plan(fixture)
    documents = {"manifest": fixture["manifest"], "provenance": fixture["provenance"][0]}
    components.bind_components(partition, documents=documents, service=service, platform="linux/amd64", root=tmp_path,
                               service_manifest=fixture["service_manifest"], binder=source.bind,
                               expected_source={"commit": fixture["capture"]["merge"],
                                                "repository": "alebgl77/open-shadow-ai"})
    assert proof["binary_version_claim"] is None
    assert scan.gate(fixture["trivy"], expected=partition["native"], complement=partition,
                     image_id=fixture["capture"]["image_config"], platform="linux/amd64") == []
    for claim in partition["components"]:
        assert claim["source_proof_sha256"] == components.digest(claim["source_proof"])


def zlib_pg_model():
    """Synthetic updated graph over historical layer descriptors; not a native rebuild capture."""
    fixture = capture("postgres", "current-amd64")
    recipe = (ROOT / "deploy/service-builds/Dockerfile.postgres").read_bytes()
    fixture["service_manifest"] = json.loads((ROOT / "requirements/service-builds/manifest.json").read_bytes())
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    metadata = predicate["runDetails"]["metadata"]["buildkit_metadata"]
    metadata["source"]["infos"][0]["data"] = base64.b64encode(recipe).decode()
    runs = [line[4:] for line in recipe.decode().replace("\\\n", "").splitlines() if line.startswith("RUN ")]
    graph = predicate["buildDefinition"]["internalParameters"]["buildConfig"]["llbDefinition"]
    graph[3]["op"]["Op"]["exec"]["meta"]["args"][-1] = runs[0]
    graph[12]["op"]["Op"]["exec"]["meta"]["args"][-1] = runs[2].split(None, 1)[1]
    graph[12]["inputs"].append("step7:0")
    graph[12]["op"]["Op"]["exec"]["mounts"].append(
        {"dest": "/packages", "input": 1, "output": -1, "readonly": True, "selector": "/packages"})
    return fixture


def test_updated_postgres_zlib_graph_has_exact_readonly_build_edge_and_unchanged_gosu_smoke():
    fixture = zlib_pg_model()
    proof = bind(fixture, ROOT)
    graph = fixture["provenance"][0]["statement"]["predicate"]["buildDefinition"]["internalParameters"][
        "buildConfig"]["llbDefinition"]
    assert len(graph) == 14 and graph[12]["inputs"] == ["step11:0", "step7:0"]
    assert graph[12]["op"]["Op"]["exec"]["meta"]["env"] == source.PG_ENV
    assert graph[3]["op"]["Op"]["exec"]["meta"]["env"] == source.GO_ENV
    assert proof["rootfs_output"] == "step12:0" and proof["binary_version_claim"] is None


@pytest.mark.parametrize("mutation", ["missing-edge", "wrong-edge", "missing-mount", "write-mount", "selector",
    "input-bool", "input-float", "output-float", "readonly-int", "extra-mount", "command", "env", "source"])
def test_postgres_zlib_graph_refuses_missing_or_changed_package_flow(mutation):
    fixture = zlib_pg_model()
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    graph = predicate["buildDefinition"]["internalParameters"]["buildConfig"]["llbDefinition"]
    final = graph[12]["op"]["Op"]["exec"]
    mount = final["mounts"][1]
    if mutation == "missing-edge":
        graph[12]["inputs"].pop()
    elif mutation == "wrong-edge":
        graph[12]["inputs"][1] = "step3:0"
    elif mutation == "missing-mount":
        final["mounts"].pop()
    elif mutation == "write-mount":
        mount["readonly"] = False
    elif mutation == "selector":
        mount["selector"] = "/foreign"
    elif mutation in {"input-bool", "input-float"}:
        mount["input"] = True if mutation == "input-bool" else 1.0
    elif mutation == "output-float":
        mount["output"] = -1.0
    elif mutation == "readonly-int":
        mount["readonly"] = 1
    elif mutation == "extra-mount":
        final["mounts"].append({"dest": "/foreign"})
    elif mutation == "command":
        final["meta"]["args"][-1] = final["meta"]["args"][-1].replace("--no-network", "--allow-untrusted")
    elif mutation == "env":
        final["meta"]["env"].append("UNREVIEWED=1")
    else:
        predicate["runDetails"]["metadata"]["buildkit_metadata"]["source"]["infos"][0]["data"] = ""
    with pytest.raises(ValueError):
        bind(fixture, ROOT)


def test_pre_zlib_postgres_capture_cannot_bind_the_updated_checkout():
    fixture = capture("postgres", "current-amd64")
    fixture["service_manifest"] = json.loads((ROOT / "requirements/service-builds/manifest.json").read_bytes())
    with pytest.raises(ValueError, match="stale or different"):
        bind(fixture, ROOT)


@pytest.mark.parametrize("mutation", ["decoy", "port", "output", "copy", "command", "environment", "mount",
                                     "terminal", "stack", "media", "ambiguous", "recipe", "source", "module",
                                     "prefix", "copy-stack", "copy-ambiguous", "extra-request", "extra-source",
                                     "node-identities"])
def test_source_projection_refuses_decoys_wrong_dataflow_or_subject(mutation, tmp_path):
    fixture = capture()
    source_inputs(fixture, tmp_path)
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    graph = predicate["buildDefinition"]["internalParameters"]["buildConfig"]["llbDefinition"]
    metadata = predicate["runDetails"]["metadata"]["buildkit_metadata"]
    if mutation == "decoy":
        graph.append(copy.deepcopy(graph[7]))
    elif mutation == "port":
        graph[8]["inputs"][1] = "step3:0"
    elif mutation == "output":
        graph[8]["op"]["Op"]["file"]["actions"][0]["output"] = -1
    elif mutation == "copy":
        graph[8]["op"]["Op"]["file"]["actions"][0]["Action"]["copy"]["src"] = "/out/foreign"
    elif mutation == "command":
        graph[7]["op"]["Op"]["exec"]["meta"]["args"][-1] += " && true"
    elif mutation == "environment":
        graph[7]["op"]["Op"]["exec"]["meta"]["env"].append("GOFLAGS=-mod=mod")
    elif mutation == "mount":
        graph[7]["op"]["Op"]["exec"]["mounts"].append({"dest": "/out"})
    elif mutation == "terminal":
        graph[-1]["inputs"] = ["step8:0"]
    elif mutation == "stack":
        metadata["layers"]["step12:0"][0][-1]["size"] += 1
    elif mutation == "media":
        metadata["layers"]["step12:0"][0][0]["mediaType"] = "application/foreign"
    elif mutation == "ambiguous":
        metadata["layers"]["step12:0"].append(copy.deepcopy(metadata["layers"]["step12:0"][0]))
    elif mutation == "recipe":
        metadata["source"]["infos"][0]["data"] = ""
    elif mutation == "source":
        metadata["vcs"]["revision"] = "0" * 40
    elif mutation == "module":
        (tmp_path / "requirements/service-builds/gosu/go.mod").write_text("foreign")
    elif mutation == "prefix":
        metadata["layers"]["step8:0"][0][0]["digest"] = "sha256:" + "0" * 64
    elif mutation == "copy-stack":
        metadata["layers"]["step9:0"][0].pop()
    elif mutation == "copy-ambiguous":
        metadata["layers"]["step8:0"].append(copy.deepcopy(metadata["layers"]["step8:0"][0]))
    elif mutation == "extra-request":
        predicate["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]["override"] = "foreign"
    elif mutation == "extra-source":
        metadata["source"]["infos"].append(copy.deepcopy(metadata["source"]["infos"][0]))
    elif mutation == "node-identities":
        mapping = predicate["buildDefinition"]["internalParameters"]["buildConfig"]["digestMapping"]
        mapping[next(iter(mapping))] = "step13"
    with pytest.raises(ValueError):
        bind(fixture, tmp_path)


def report(query, *, severity="High", fixed=True):
    if query.startswith("pkg:"):
        name, _, version = query[11:].rpartition("@")
        artifact = {"id": "literal-id", "name": name, "version": version, "purl": query, "cpes": []}
    else:
        artifact = {"id": "literal-id", "name": query.split(":")[4], "version": query.split(":")[5],
                    "purl": "", "cpes": [query]}
    return {"source": {"type": "purl" if query.startswith("pkg:") else "cpe", "target": query},
            "descriptor": {"name": "grype", "version": "0.120.1", "configuration": {},
                           "db": {"status": {}, "providers": {"public-model": {}}}},
            "matches": [{"artifact": artifact, "vulnerability": {"id": "CVE-public-test", "severity": severity,
                         "fix": {"versions": ["9.9.9"] if fixed else [], "state": "fixed" if fixed else "not-fixed"}}}]}


@pytest.mark.parametrize("query", ["pkg:golang/github.com/tianon/gosu@1.19",
                                 "cpe:2.3:a:postgresql:postgresql:16.15:*:*:*:*:*:*:*"])
@pytest.mark.parametrize("severity,blocks", [("High", True), ("Critical", True), ("Unknown", True), (None, True),
                                            ("future-value", True), ("Medium", False), ("Low", False)])
def test_both_query_types_gate_all_severe_fixable_findings_and_keep_medium(query, severity, blocks):
    value = report(query, severity=severity)
    original = copy.deepcopy(value)
    assert bool(components.validate_report(value, query=query, configuration={}, database_status={})) == blocks
    value["matches"][0]["vulnerability"]["fix"]["versions"] = []
    assert components.validate_report(value, query=query, configuration={}, database_status={}) == []
    value["matches"][0]["vulnerability"]["fix"]["versions"] = ["9.9.9"]
    assert value == original


@pytest.mark.parametrize("mutation", ["tool", "config", "db", "echo", "ignored", "missing", "name", "version",
                                     "purl", "duplicate", "fix"])
def test_complement_report_refuses_unbound_or_filtered_results(mutation):
    query = "pkg:golang/github.com/tianon/gosu@1.19"
    value = report(query)
    if mutation == "tool":
        value["descriptor"]["version"] = "0.120.0"
    elif mutation in {"config", "db"}:
        value["descriptor"]["configuration" if mutation == "config" else "db"] = {"changed": True}
    elif mutation == "echo":
        value["source"]["target"] += "0"
    elif mutation == "ignored":
        value["ignoredMatches"] = [{"reason": "hidden"}]
    elif mutation == "missing":
        value.pop("matches")
    elif mutation in {"name", "version", "purl"}:
        value["matches"][0]["artifact"][mutation] += "foreign"
    elif mutation == "duplicate":
        value["matches"].append(copy.deepcopy(value["matches"][0]))
    elif mutation == "fix":
        value["matches"][0]["vulnerability"]["fix"] = {}
    with pytest.raises(ValueError):
        components.validate_report(value, query=query, configuration={}, database_status={})


# These are synthetic exception-boundary tests, not native tool/DB observations.
errno_runtime = load("grype_runtime")


def filesystem_exception_diagnostic_value(detail=None):
    return {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
            "stage": "grype_prepare", "error_type": "GrypeRuntimeError", "code": "filesystem",
            "secondary": ["owned_cleanup_failed"], "prepare_phase": "update", "filesystem_reason": "syscall",
            "filesystem_exception": detail or {"family": "os_error", "errno": "not_found"}}


def filesystem_exception_diagnostic_error(detail=None):
    error = errno_runtime.GrypeRuntimeError("filesystem", filesystem_reason="syscall")
    error.prepare_phase = "update"
    error.filesystem_exception = detail or {"family": "os_error", "errno": "not_found"}
    error.add_note("owned_cleanup_failed")
    return error


def filesystem_exception_diagnostic_trace():
    trace = components.FailureDiagnostic()
    trace.grype_error_type = errno_runtime.GrypeRuntimeError
    trace.at("grype_prepare")
    return trace


@pytest.mark.parametrize("family,category", [
    *(('os_error', category) for category in sorted(components.FAILURE_FILESYSTEM_ERRNOS)),
    ("tar_error", "unavailable"), ("unavailable", "unavailable"),
])
def test_filesystem_exception_diagnostic_accepts_only_fixed_pairs(family, category):
    value = filesystem_exception_diagnostic_value({"family": family, "errno": category})
    before = json.dumps(value, sort_keys=True)
    components.validate_failure_diagnostic(value)
    assert json.dumps(value, sort_keys=True) == before


@pytest.mark.parametrize("defect", ["missing-family", "missing-errno", "extra", "family-unknown",
    "errno-unknown", "family-bool", "errno-int", "tar-errno", "unavailable-errno", "null", "list"])
def test_filesystem_exception_diagnostic_rejects_malformed_nested_value(defect):
    detail = {"family": "os_error", "errno": "not_found"}
    if defect.startswith("missing-"):
        detail.pop(defect.removeprefix("missing-"))
    elif defect == "extra":
        detail["filename"] = "secret-canary"
    elif defect in {"family-unknown", "errno-unknown"}:
        detail[defect.split("-")[0]] = "secret-canary"
    elif defect == "family-bool":
        detail["family"] = True
    elif defect == "errno-int":
        detail["errno"] = 2
    elif defect.endswith("-errno"):
        detail["family"] = defect.removesuffix("-errno")
    else:
        detail = None if defect == "null" else []
    value = filesystem_exception_diagnostic_value()
    value["filesystem_exception"] = detail
    with pytest.raises(ValueError):
        components.validate_failure_diagnostic(value)


@pytest.mark.parametrize("defect", ["stage", "error_type", "code", "reason", "missing-reason",
                                    "missing-phase", "phase-null"])
def test_filesystem_exception_diagnostic_requires_preparation_syscall_context(defect, tmp_path):
    value = filesystem_exception_diagnostic_value()
    if defect == "stage":
        value.pop("prepare_phase")
        value["stage"] = "component_query"
    elif defect == "error_type":
        value.pop("prepare_phase")
        value.pop("filesystem_reason")
        value["error_type"] = "OSError"
    elif defect == "code":
        value.pop("filesystem_reason")
        value["code"] = "database"
    elif defect == "reason":
        value["filesystem_reason"] = "tree_nonregular"
    elif defect.startswith("missing-"):
        value.pop("filesystem_reason" if defect == "missing-reason" else "prepare_phase")
    else:
        value["prepare_phase"] = None
    with pytest.raises(ValueError):
        components.validate_failure_diagnostic(value)
    # The failure-only emitter omits an ineligible optional detail. It does not
    # discard or fabricate the already-valid primary summary.
    if defect == "phase-null":
        value.pop("prepare_phase")
    previous = {key: item for key, item in value.items() if key != "filesystem_exception"}
    components.validate_failure_diagnostic(previous)
    trace = filesystem_exception_diagnostic_trace()
    trace.first = {key: item for key, item in value.items()
                   if key not in {"schema", "kind", "status", "accepted", "secondary"}}
    trace.secondary.add("owned_cleanup_failed")
    trace.emit(tmp_path, ValueError("secret-canary"))
    path, = tmp_path.glob("*.failure.json")
    assert path.read_bytes() == (json.dumps(previous, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("order", list(itertools.permutations(("filesystem_exception", "stage", "prepare_phase",
                                                             "filesystem_reason"))))
@pytest.mark.parametrize("poison_field", ["stage", "error_type", "code", "prepare_phase", "filesystem_reason",
                                         "family", "errno"])
def test_filesystem_exception_diagnostic_all_keyorders_validate_types_before_context(order, poison_field):
    calls = []

    class Poison(str):
        def __eq__(self, other):
            calls.append("eq")
            raise AssertionError("private callback")

        def __hash__(self):
            calls.append("hash")
            raise AssertionError("private callback")

    value = filesystem_exception_diagnostic_value()
    target = value["filesystem_exception"] if poison_field in {"family", "errno"} else value
    target[poison_field] = Poison("secret-canary")
    ordered = {key: value[key] for key in order}
    ordered.update({key: item for key, item in value.items() if key not in order})
    with pytest.raises(ValueError):
        components.validate_failure_diagnostic(ordered)
    assert calls == []


@pytest.mark.parametrize("defect", ["dict-subclass", "string-key", "family-subclass", "errno-subclass"])
def test_filesystem_exception_diagnostic_poison_detail_is_omitted_without_callbacks(defect, tmp_path):
    calls = []

    class PoisonString(str):
        def __eq__(self, other):
            calls.append("eq")
            raise AssertionError("private callback")

        __hash__ = str.__hash__

    class PoisonDict(dict):
        def keys(self):
            calls.append("keys")
            raise AssertionError("private callback")

        def __iter__(self):
            calls.append("iter")
            raise AssertionError("private callback")

    detail = {"family": "os_error", "errno": "not_found"}
    if defect == "dict-subclass":
        detail = PoisonDict(detail)
    elif defect == "string-key":
        detail = {PoisonString("family"): "os_error", "errno": "not_found"}
    else:
        detail[defect.removesuffix("-subclass")] = PoisonString("secret-canary")
    trace = filesystem_exception_diagnostic_trace()
    trace.first = {key: item for key, item in filesystem_exception_diagnostic_value(detail).items()
                   if key not in {"schema", "kind", "status", "accepted", "secondary"}}
    trace.emit(tmp_path, filesystem_exception_diagnostic_error())
    path, = tmp_path.glob("*.failure.json")
    value = json.loads(path.read_bytes())
    assert "filesystem_exception" not in value and calls == []
    assert value["stage"] == "grype_prepare" and value["code"] == "filesystem"


def test_filesystem_exception_diagnostic_context_snapshot_survives_cleanup_and_never_exports_private_fields(
        tmp_path, monkeypatch):
    primary = FileNotFoundError("secret-message-canary")
    primary.errno = errno.ENOENT
    primary.filename = "secret-filename-canary"
    primary.winerror = "secret-winerror-canary"
    calls = []

    class Model:
        prepare_phase = "update"

        def prepare(self):
            calls.append("prepare")
            raise primary

        def cleanup(self):
            calls.append("cleanup")
            primary.errno = errno.EACCES

    monkeypatch.setattr(errno_runtime, "Runtime", lambda *args: Model())
    trace = filesystem_exception_diagnostic_trace()
    with pytest.raises(errno_runtime.GrypeRuntimeError) as raised:
        with trace.context(errno_runtime.prepared_grype(scratch_parent=tmp_path, manifest_path=tmp_path,
                                                       config_path=tmp_path, platform="linux/amd64")):
            pytest.fail("preparation refusal must not yield")
    assert raised.value.args == ("filesystem",) and calls == ["prepare", "cleanup"]
    assert trace.first["filesystem_exception"] == {"family": "os_error", "errno": "not_found"}
    raised.value.filesystem_exception["errno"] = "permission"
    trace.emit(tmp_path, raised.value)
    path, = tmp_path.glob("*.failure.json")
    raw = path.read_bytes()
    assert b"secret-" not in raw and len(raw) <= 2048
    assert json.loads(raw)["filesystem_exception"] == {"family": "os_error", "errno": "not_found"}


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_filesystem_exception_diagnostic_context_preserves_cancellation_identity_and_cleanup(
        tmp_path, monkeypatch, kind):
    primary = kind("secret-canary")
    calls = []

    class Model:
        prepare_phase = "update"

        def prepare(self):
            calls.append("prepare")
            raise primary

        def cleanup(self):
            calls.append("cleanup")

    monkeypatch.setattr(errno_runtime, "Runtime", lambda *args: Model())
    trace = filesystem_exception_diagnostic_trace()
    with pytest.raises(kind) as raised:
        with trace.context(errno_runtime.prepared_grype(scratch_parent=tmp_path, manifest_path=tmp_path,
                                                       config_path=tmp_path, platform="linux/amd64")):
            pytest.fail("cancellation must not yield")
    assert raised.value is primary and calls == ["prepare", "cleanup"]
    trace.emit(tmp_path, primary)
    path, = tmp_path.glob("*.failure.json")
    assert "filesystem_exception" not in json.loads(path.read_bytes())


@pytest.mark.parametrize("stage,phase", [("grype_prepare", None), ("component_query", None),
                                        ("component_query", "update")])
def test_filesystem_exception_diagnostic_capture_does_not_fabricate_eligible_context(stage, phase, tmp_path):
    error = filesystem_exception_diagnostic_error()
    error.prepare_phase = phase
    trace = filesystem_exception_diagnostic_trace()
    trace.at(stage)
    trace.emit(tmp_path, error)
    path, = tmp_path.glob("*.failure.json")
    value = json.loads(path.read_bytes())
    assert "filesystem_exception" not in value and "prepare_phase" not in value
    assert value["filesystem_reason"] == "syscall" and value["secondary"] == ["owned_cleanup_failed"]


def test_filesystem_exception_diagnostic_budget_omits_only_detail_preserving_primary_and_secondary(
        tmp_path, monkeypatch):
    original = json.dumps

    def budget_model(value, *args, **kwargs):
        rendered = original(value, *args, **kwargs)
        return rendered + " " * 2048 if "filesystem_exception" in value else rendered

    monkeypatch.setattr(components.json, "dumps", budget_model)
    trace = filesystem_exception_diagnostic_trace()
    trace.emit(tmp_path, filesystem_exception_diagnostic_error())
    path, = tmp_path.glob("*.failure.json")
    raw = path.read_bytes()
    previous = filesystem_exception_diagnostic_value()
    previous.pop("filesystem_exception")
    assert raw == (original(previous, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert len(raw) <= 2048


def test_filesystem_exception_diagnostic_context_with_untrusted_attribute_container_keeps_original_and_cleanup(
        tmp_path):
    from contextlib import contextmanager

    calls = []

    class PoisonAttributes(dict):
        def get(self, key, *args):
            if key == "__notes__":
                return []
            calls.append(key)
            raise AssertionError("private callback")

    primary = filesystem_exception_diagnostic_error()
    primary.__dict__ = PoisonAttributes(primary.__dict__)

    @contextmanager
    def context():
        try:
            yield None
        finally:
            calls.append("cleanup")

    trace = filesystem_exception_diagnostic_trace()
    with pytest.raises(errno_runtime.GrypeRuntimeError) as raised:
        with trace.context(context()):
            raise primary
    assert raised.value is primary and calls == ["cleanup"]
    assert trace.first == {"stage": "grype_prepare", "error_type": "GrypeRuntimeError", "code": "filesystem"}


def test_filesystem_exception_diagnostic_real_context_after_yield_omits_detail_and_preserves_conversion(
        tmp_path, monkeypatch):
    primary = FileNotFoundError("secret-canary")
    primary.errno = errno.ENOENT
    calls = []

    class Model:
        prepare_phase = None

        def prepare(self):
            calls.append("prepare")

        def cleanup(self):
            calls.append("cleanup")

    monkeypatch.setattr(errno_runtime, "Runtime", lambda *args: Model())
    trace = filesystem_exception_diagnostic_trace()
    with pytest.raises(errno_runtime.GrypeRuntimeError) as raised:
        with trace.context(errno_runtime.prepared_grype(scratch_parent=tmp_path, manifest_path=tmp_path,
                                                       config_path=tmp_path, platform="linux/amd64")):
            raise primary
    assert raised.value.args == ("filesystem",) and raised.value.prepare_phase is None
    assert calls == ["prepare", "cleanup"]
    trace.emit(tmp_path, raised.value)
    path, = tmp_path.glob("*.failure.json")
    value = json.loads(path.read_bytes())
    assert value["error_type"] == "FileNotFoundError"
    assert "filesystem_exception" not in value and "prepare_phase" not in value
