"""Actual absent ClickHouse inventory plus synthetic native-observer boundary receipts."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PRINCIPAL, SOURCE, COMPONENTS, SCAN = [load(name) for name in (
    "component_principal", "component_source", "component_scanner", "scan-images")]


def capture():
    return json.loads((ROOT / "tests/fixtures/component-scanner/clickhouse-current-amd64.json").read_bytes())


def inputs(fixture):
    return {"subject": {"archive_sha256": fixture["capture"]["archive_sha256"],
                        "image_manifest": fixture["capture"]["image_manifest"],
                        "image_config": fixture["capture"]["image_config"], "platform": "linux/amd64"},
            "config": fixture["config"], "expected_source": {"commit": fixture["capture"]["merge"],
                "repository": "alebgl77/open-shadow-ai"},
            "expected_ci": {"run_id": "37537893022", "run_attempt": "1", "job": "derived-service-builds"},
            "collector_sha256": "d" * 64, "process_module_sha256": "e" * 64}


def receipt(arguments):
    subject = arguments["subject"]
    return {"schema": 1, "kind": "clickhouse-cli-version", "status": "verified",
            "invocation": "5814ea0d-a32d-47aa-b82e-d1c6c97e7f03", "ci": arguments["expected_ci"],
            "source": arguments["expected_source"], "subject": subject,
            "collector_sha256": arguments["collector_sha256"], "command_contract": "clickhouse-server-version-v1",
            "process_module_sha256": arguments["process_module_sha256"],
            "observation": {"binary": "/usr/bin/clickhouse", "argv": ["server", "--version"], "version": "25.8.33.6",
                "reported_build_kind": "official build", "stdout_bytes": len(PRINCIPAL.STDOUT),
                "stdout_sha256": hashlib.sha256(PRINCIPAL.STDOUT).hexdigest(), "stderr_bytes": 0,
                "stderr_sha256": hashlib.sha256(b"").hexdigest(), "docker_cli_exit_code": 0,
                "container_exit_code": 0},
            "identity": {"image_id_before": subject["image_config"], "image_id_after": subject["image_config"],
                "container_image_before": subject["image_config"], "container_image_after": subject["image_config"],
                "env_matches_image": True,
                "rootfs_diff_ids": arguments["config"]["rootfs"]["diff_ids"]},
            "cleanup": {"container_removed": True, "absence_verified": True},
            "authentication": {"builder_provenance": "unverified", "publisher_signature": "unverified"}}


def matching_source_inputs(fixture, directory):
    for name, text in fixture["source_inputs"].items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
    images = directory / "requirements/images.json"
    images.parent.mkdir(parents=True, exist_ok=True)
    images.write_bytes((ROOT / "requirements/images.json").read_bytes())


def bind(fixture, directory):
    arguments = inputs(fixture)
    return SOURCE.bind_clickhouse(fixture["provenance"][0]["statement"]["predicate"], platform="linux/amd64",
        selected_manifest=fixture["manifest"], root=directory, service_manifest=fixture["service_manifest"],
        expected_source=arguments["expected_source"], expected_ci=arguments["expected_ci"])


def test_actual_absent_principal_stays_absent_and_declaration_has_separate_cli_version(tmp_path):
    fixture = capture()
    matching_source_inputs(fixture, tmp_path)
    original = copy.deepcopy(fixture["sbom"])
    plan = COMPONENTS.partition(fixture["sbom"], service="clickhouse", package_key=SCAN.package_key)
    assert len(original["packages"]) == 22 and len(plan["native"]) == 21 and plan["components"] == []
    assert SCAN.gate(fixture["trivy"], expected=plan["native"], complement=plan,
                     image_id=fixture["capture"]["image_config"], platform="linux/amd64") == []
    arguments = inputs(fixture)
    value = receipt(arguments)
    assert PRINCIPAL.validate_receipt(value, **arguments) == value
    COMPONENTS.declare_clickhouse(plan, receipt=value, receipt_sha256="e" * 64, source_proof=bind(fixture, tmp_path))
    claim, = plan["components"]
    assert claim["original_spdx_ids"] == [] and claim["original_package"] is None
    assert claim["original_inventory_observation"] == "absent" and claim["binary_version_claim"] is None
    assert claim["observed_cli_version"] == claim["declared_version"] == "25.8.33.6"
    assert claim["queries"] == [PRINCIPAL.QUERY]
    assert claim["source_proof"]["authenticated_provenance"] is False
    assert fixture["sbom"] == original


@pytest.mark.parametrize("section,key", [("root", "schema"), ("root", "kind"), ("root", "status"),
    ("root", "invocation"), ("root", "collector_sha256"), ("root", "process_module_sha256"),
    ("root", "command_contract"),
    ("ci", "run_id"), ("ci", "run_attempt"), ("ci", "job"), ("source", "commit"), ("source", "repository"),
    ("subject", "archive_sha256"), ("subject", "image_manifest"), ("subject", "image_config"), ("subject", "platform"),
    ("observation", "binary"), ("observation", "argv"), ("observation", "version"),
    ("observation", "reported_build_kind"), ("observation", "stdout_bytes"), ("observation", "stdout_sha256"),
    ("observation", "stderr_bytes"), ("observation", "stderr_sha256"), ("observation", "docker_cli_exit_code"),
    ("observation", "container_exit_code"), ("identity", "image_id_before"), ("identity", "image_id_after"),
    ("identity", "container_image_before"), ("identity", "container_image_after"), ("identity", "rootfs_diff_ids"),
    ("identity", "env_matches_image"),
    ("cleanup", "container_removed"), ("cleanup", "absence_verified"),
    ("authentication", "builder_provenance"), ("authentication", "publisher_signature")])
def test_every_native_observation_identity_and_cleanup_field_is_exact(section, key):
    arguments = inputs(capture())
    value = copy.deepcopy(receipt(arguments))
    target = value if section == "root" else value[section]
    target[key] = "foreign"
    with pytest.raises(ValueError):
        PRINCIPAL.validate_receipt(value, **arguments)


@pytest.mark.parametrize("mutation", ["extra", "nested-extra", "missing", "bool-schema", "bool-exit", "bool-bytes"])
def test_receipt_schema_refuses_extra_fields_missing_fields_and_bool_integer_aliases(mutation):
    arguments = inputs(capture())
    value = copy.deepcopy(receipt(arguments))
    if mutation == "extra":
        value["unchecked"] = "secret"
    elif mutation == "nested-extra":
        value["identity"]["name"] = "unchecked"
    elif mutation == "missing":
        value.pop("cleanup")
    elif mutation == "bool-schema":
        value["schema"] = True
    elif mutation == "bool-exit":
        value["observation"]["container_exit_code"] = False
    else:
        value["observation"]["stderr_bytes"] = False
    with pytest.raises(ValueError):
        PRINCIPAL.validate_receipt(value, **arguments)


@pytest.mark.parametrize("mutation", ["missing", "zero", "negative", "wrong-job", "leading-zero", "bool"])
def test_required_native_ci_identity_cannot_be_missing_or_caller_json(mutation):
    environment = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "derived-service-builds"}
    if mutation == "missing":
        environment.pop("GITHUB_RUN_ID")
    elif mutation == "wrong-job":
        environment["GITHUB_JOB"] = "caller-json"
    else:
        environment["GITHUB_RUN_ATTEMPT"] = {
            "zero": "0", "negative": "-1", "leading-zero": "01", "bool": True}[mutation]
    with pytest.raises(ValueError):
        PRINCIPAL.ci_identity(environment)


def test_signer_identity_reuses_same_run_and_native_build_job_without_pretending_to_be_builder():
    environment = {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "signed-image-evidence"}
    assert PRINCIPAL.ci_identity(environment, signing=True) == {
        "run_id": "123", "run_attempt": "1", "job": "derived-service-builds"}
    with pytest.raises(ValueError):
        PRINCIPAL.ci_identity(environment)


@pytest.mark.parametrize("mutation", ["decoy", "port", "mount", "write-mount", "command", "environment", "terminal",
    "platform", "base", "base-dependency", "layer-digest", "layer-size", "layer-order", "layer-media", "base-stack",
    "ambiguous", "recipe", "ci-run", "ci-job"])
def test_actual_five_node_graph_and_final_subject_binding_refuse_every_changed_boundary(mutation, tmp_path):
    fixture = capture()
    matching_source_inputs(fixture, tmp_path)
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    internal = predicate["buildDefinition"]["internalParameters"]
    graph = internal["buildConfig"]["llbDefinition"]
    metadata = predicate["runDetails"]["metadata"]["buildkit_metadata"]
    if mutation == "decoy":
        graph.append(copy.deepcopy(graph[2]))
    elif mutation == "port":
        graph[3]["inputs"][1] = "step1:0"
    elif mutation in {"mount", "write-mount"}:
        graph[3]["op"]["Op"]["exec"]["mounts"][1]["selector" if mutation == "mount" else "readonly"] = \
            "/foreign" if mutation == "mount" else False
    elif mutation == "command":
        graph[3]["op"]["Op"]["exec"]["meta"]["args"][-1] += " && true"
    elif mutation == "environment":
        graph[3]["op"]["Op"]["exec"]["meta"]["env"].append("UNREVIEWED=true")
    elif mutation == "terminal":
        graph[4]["inputs"] = ["step0:0"]
    elif mutation == "platform":
        graph[0]["op"]["platform"]["Architecture"] = "arm64"
    elif mutation == "base":
        graph[0]["op"]["Op"]["source"]["identifier"] += "foreign"
    elif mutation == "base-dependency":
        predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] += "foreign"
    elif mutation in {"layer-digest", "layer-size", "layer-media"}:
        descriptor = metadata["layers"]["step3:0"][0][-1]
        key = {"layer-digest": "digest", "layer-size": "size", "layer-media": "mediaType"}[mutation]
        descriptor[key] = 123 if key == "size" else "foreign"
    elif mutation == "layer-order":
        metadata["layers"]["step3:0"][0].reverse()
    elif mutation == "base-stack":
        metadata["layers"]["step0:0"][0].pop()
    elif mutation == "ambiguous":
        metadata["layers"]["step3:0"].append(copy.deepcopy(metadata["layers"]["step3:0"][0]))
    elif mutation == "recipe":
        metadata["source"]["infos"][0]["data"] = ""
    else:
        internal["github_run_id" if mutation == "ci-run" else "github_job"] = "foreign"
    with pytest.raises(ValueError):
        bind(fixture, tmp_path)


def test_every_real_planned_query_control_and_declared_principal_pass_actual_tool_identifier_boundary():
    runtime = load("grype_runtime")
    queries = [PRINCIPAL.QUERY, "cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*",
               "pkg:golang/golang.org/x/crypto@0.1.0"]
    for service in ("postgres", "node-exporter", "redis"):
        fixture = json.loads((ROOT / f"tests/fixtures/component-scanner/{service}-amd64.json").read_bytes())
        queries.extend(query for claim in COMPONENTS.partition(fixture["sbom"], service=service,
            package_key=SCAN.package_key)["components"] for query in claim["queries"])
    assert len(queries) == 12 and "pkg:golang/github.com/tianon/gosu@1.19" in queries
    for query in queries:
        runtime.validate_identifier(query)


@pytest.mark.parametrize("name", ["clickhouse.principal-observation.json.pending",
    "clickhouse.principal-observation.json.0123456789abcdef.pending", "foreign.json"])
def test_only_canonical_sibling_filename_is_accepted(name):
    with pytest.raises(ValueError):
        PRINCIPAL.canonical_receipt_path(ROOT / name, expected_parent=ROOT)
    with pytest.raises(ValueError):
        PRINCIPAL.canonical_receipt_path(ROOT / "other" / PRINCIPAL.RECEIPT_NAME, expected_parent=ROOT)
    assert PRINCIPAL.canonical_receipt_path(ROOT / PRINCIPAL.RECEIPT_NAME, expected_parent=ROOT).name == \
        PRINCIPAL.RECEIPT_NAME


def source_fixture_bind(fixture, service, directory):
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    definition = predicate["buildDefinition"]
    args = definition["externalParameters"]["request"]["root"]["request"]["args"]
    keywords = {"platform": "linux/amd64", "selected_manifest": fixture["manifest"], "root": directory,
                "service_manifest": fixture["service_manifest"], "expected_source": {
                "commit": args["vcs:revision"], "repository": args["vcs:source"].removeprefix("https://github.com/")}}
    if service == "clickhouse":
        keywords["expected_ci"] = {key: definition["internalParameters"]["github_" + key]
                                   for key in ("run_id", "run_attempt", "job")}
        return SOURCE.bind_clickhouse(predicate, **keywords)
    return SOURCE.bind(predicate, service=service, **keywords)


@pytest.mark.parametrize("service", ["postgres", "node-exporter", "clickhouse"])
def test_three_actual_captured_graphs_remain_valid_with_exact_observed_hash(service, tmp_path):
    fixture = json.loads((ROOT / f"tests/fixtures/component-scanner/{service}-current-amd64.json").read_bytes())
    matching_source_inputs(fixture, tmp_path)
    graph = fixture["provenance"][0]["statement"]["predicate"]["buildDefinition"]["internalParameters"][
        "buildConfig"]["llbDefinition"]
    proof = source_fixture_bind(fixture, service, tmp_path)
    assert proof["build_graph_sha256"] == hashlib.sha256(
        json.dumps(graph, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("service", ["postgres", "node-exporter", "clickhouse"])
@pytest.mark.parametrize("mutation", ["input-bool", "input-float", "output-float", "flag-int", "flag-float",
                                      "compatibility-float", "layer-size-float"])
def test_captured_source_graph_invocation_and_layer_numeric_aliases_are_refused(service, mutation, tmp_path):
    fixture = json.loads((ROOT / f"tests/fixtures/component-scanner/{service}-current-amd64.json").read_bytes())
    matching_source_inputs(fixture, tmp_path)
    predicate = fixture["provenance"][0]["statement"]["predicate"]
    definition = predicate["buildDefinition"]
    graph = definition["internalParameters"]["buildConfig"]["llbDefinition"]
    if mutation == "compatibility-float":
        definition["externalParameters"]["request"]["compatibilityVersion"] = 30.0
    elif mutation == "layer-size-float":
        step = "step3:0" if service == "clickhouse" else "step12:0"
        descriptor = predicate["runDetails"]["metadata"]["buildkit_metadata"]["layers"][step][0][-1]
        descriptor["size"] = float(descriptor["size"])
    else:
        action = graph[3]["op"]["Op"]["exec"]["mounts"][1] if service == "clickhouse" else \
            graph[2]["op"]["Op"]["file"]["actions"][0]
        if mutation.startswith("input"):
            action["input"] = bool(action["input"]) if mutation.endswith("bool") else float(action["input"])
        elif mutation == "output-float":
            action["output"] = float(action["output"])
        elif service == "clickhouse":
            action["readonly"] = 1 if mutation == "flag-int" else 1.0
        else:
            action["Action"]["mkdir"]["makeParents"] = 1 if mutation == "flag-int" else 1.0
    with pytest.raises(ValueError):
        source_fixture_bind(fixture, service, tmp_path)


def test_pre_zlib_clickhouse_capture_refuses_updated_recipe_and_leaves_observations_untouched():
    fixture = capture()
    original = copy.deepcopy(fixture)
    fixture["service_manifest"] = json.loads((ROOT / "requirements/service-builds/manifest.json").read_bytes())
    with pytest.raises(ValueError, match="stale"):
        bind(fixture, ROOT)
    assert fixture["sbom"] == original["sbom"] and fixture["provenance"] == original["provenance"]
