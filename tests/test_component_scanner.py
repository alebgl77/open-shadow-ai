"""Native captured observations and adversarial complementary coverage contracts."""

import copy
import importlib.util
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
def test_actual_fresh_native_current_recipe_and_locks_bind_selected_rootfs(service):
    fixture = capture(service, "current-amd64")
    proof = bind(fixture, ROOT)
    partition = plan(fixture)
    documents = {"manifest": fixture["manifest"], "provenance": fixture["provenance"][0]}
    components.bind_components(partition, documents=documents, service=service, platform="linux/amd64", root=ROOT,
                               service_manifest=fixture["service_manifest"], binder=source.bind,
                               expected_source={"commit": fixture["capture"]["merge"],
                                                "repository": "alebgl77/open-shadow-ai"})
    assert proof["binary_version_claim"] is None
    assert scan.gate(fixture["trivy"], expected=partition["native"], complement=partition,
                     image_id=fixture["capture"]["image_config"], platform="linux/amd64") == []
    for claim in partition["components"]:
        assert claim["source_proof_sha256"] == components.digest(claim["source_proof"])


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
