"""Public captured component observations and explicitly synthetic tool-boundary models."""

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def capture(service):
    if service == "prometheus":
        return synthetic_prometheus_capture()
    suffix = "current-amd64" if service in {"postgres", "node-exporter", "clickhouse"} else "amd64"
    return json.loads((ROOT / f"tests/fixtures/component-scanner/{service}-{suffix}.json").read_bytes())


def resolved_dependencies(root, platform="linux/amd64"):
    """Synthetic CURRENT official base/tool bindings for a projected ClickHouse recipe graph."""
    images = json.loads((root / "requirements/images.json").read_bytes())
    dependencies = []
    for name in ("clickhouse-base", "golang", "sbom-generator"):
        image, digest = images[name]["reference"].split("@")
        repository, version = image.rsplit(":", 1)
        dependencies.append({"uri": f"pkg:docker/{repository}@{version}?digest={digest}&platform=" +
                             platform.replace("/", "%2F"), "digest": {"sha256": digest[7:]}})
    return sorted(dependencies, key=lambda item: item["uri"])


def documents(fixture, source):
    provenance = copy.deepcopy(fixture["provenance"][0]) if fixture["provenance"] else {"blob": "sha256:" + "8" * 64}
    if "statement" in provenance:
        predicate = provenance["statement"]["predicate"]
        hints = predicate["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]
        hints.update({"vcs:revision": source["commit"], "vcs:source": "https://github.com/" + source["repository"]})
        predicate["runDetails"]["metadata"]["buildkit_metadata"]["vcs"].update(
            {"revision": source["commit"], "source": "https://github.com/" + source["repository"]})
    return {"manifest": copy.deepcopy(fixture["manifest"]), "provenance": provenance,
            "config": copy.deepcopy(fixture["config"]),
            "sbom": {"blob": fixture["capture"]["spdx_statement_blob"]}}


def configuration(cache="/tmp/grype-" + "a" * 32 + "/database"):
    runtime = load("grype_runtime")
    result = copy.deepcopy(runtime.TEMPLATE)
    result["ignore-wontfix"] = result.pop("ignore-states")
    result.update({"distro": "", "output-template-file": "", "file": "", "platform": "linux/amd64",
                   "from": None, "name": "", "output": ["json"], "show-suppressed": False,
                   "externalSources": {"enable": False},
                   "match": {"stock": {"using-cpes": True},
                             "golang": {"using-cpes": False, "always-use-cpe-for-stdlib": False,
                                        "allow-main-module-pseudo-version-comparison": False}}})
    result["db"].update({"cache-dir": cache, "max-allowed-built-age": 86400000000000, "ca-cert": ""})
    return result


def principal_receipt(*, subject, config, source, ci, root):
    principal = load("component_principal")
    scan = load("scan-images")
    hashes = scan.source_fingerprints(root, True, True)
    return {"schema": 1, "kind": "clickhouse-cli-version", "status": "verified",
        "invocation": "5814ea0d-a32d-47aa-b82e-d1c6c97e7f03", "ci": ci, "source": source, "subject": subject,
        "collector_sha256": hashes["scripts/observe-clickhouse-version.py"],
        "process_module_sha256": hashes["scripts/grype_runtime.py"], "command_contract": "clickhouse-server-version-v1",
        "observation": {"binary": "/usr/bin/clickhouse", "argv": ["server", "--version"], "version": "25.8.33.6",
            "reported_build_kind": "official build", "stdout_bytes": len(principal.STDOUT),
            "stdout_sha256": hashlib.sha256(principal.STDOUT).hexdigest(), "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(), "docker_cli_exit_code": 0, "container_exit_code": 0},
        "identity": {"image_id_before": subject["image_config"], "image_id_after": subject["image_config"],
            "container_image_before": subject["image_config"], "container_image_after": subject["image_config"],
            "env_matches_image": True,
            "rootfs_diff_ids": config["rootfs"]["diff_ids"]},
        "cleanup": {"container_removed": True, "absence_verified": True},
        "authentication": {"builder_provenance": "unverified", "publisher_signature": "unverified"}}


def runtime_receipt(root, now=None):
    runtime = load("grype_runtime")
    components = load("component_scanner")
    scan = load("scan-images")
    now = now or datetime.now(UTC)
    config = configuration()
    rendered = copy.deepcopy(runtime.TEMPLATE)
    rendered["db"]["cache-dir"] = config["db"]["cache-dir"]
    fingerprints = scan.source_fingerprints(root, True)
    pin = json.loads((root / "requirements/component-scanner.json").read_bytes())
    files = {"6/import.json": "a" * 64, "6/vulnerability.db": "b" * 64}
    return {"tool": {"name": "grype", "version": pin["version"], "release_commit": pin["commit"],
                     "archive_sha256": pin["archives"]["linux/amd64"]["sha256"], "binary_sha256": "c" * 64},
            "manifest_sha256": fingerprints["requirements/component-scanner.json"],
            "config_template_sha256": fingerprints["requirements/grype.yaml"],
            "config_sha256": hashlib.sha256(runtime.canonical(rendered)).hexdigest(), "configuration": config,
            "database": {"status": {"valid": True, "schemaVersion": "v6.1.10",
                "from": "https://grype.anchore.io/databases/v6/db.tar.zst?checksum=sha256%3A" + "a" * 64,
                "path": config["db"]["cache-dir"] + "/6/vulnerability.db",
                "built": (now - timedelta(hours=1)).isoformat()}, "fetched_at": now.isoformat(),
                "files": files, "digest": components.digest(files)},
            "runtime_module_sha256": fingerprints["scripts/grype_runtime.py"]}


def query_report(query, receipt, *, advisory=None, severity="Medium", fixed=False):
    artifact = {"id": "synthetic-direct-query"}
    if query.startswith("pkg:"):
        identity, _, version = query[11:].rpartition("@")
        artifact.update({"name": identity, "version": version, "purl": query})
    else:
        cpe = query.split(":")
        artifact.update({"name": cpe[4], "version": cpe[5], "cpes": [query]})
    return {"descriptor": {"name": "grype", "version": "0.120.1", "configuration": receipt["configuration"],
                           "db": {"status": receipt["database"]["status"], "providers": {"public-model": {}}}},
            "source": {"type": "purl" if query.startswith("pkg:") else "cpe", "target": query},
            "matches": [{"artifact": artifact, "vulnerability": {"id": advisory, "severity": severity,
                         "fix": {"versions": ["9.9.9"] if fixed else [],
                                 "state": "fixed" if fixed else "not-fixed"}}}] if advisory else []}


def synthetic_prometheus_capture(root=ROOT):
    """SYNTHETIC Prometheus model projected onto the preserved node_exporter native capture.

    No native Prometheus capture exists until CI builds the maintained recipe. This model keeps the
    historical node_exporter subject (manifest, config, ordered layers, busybox and dependency
    observations) and projects onto it the CURRENT Prometheus recipe graph, locks and manifest,
    rewriting the one main-module observation into the two unversioned Prometheus binaries that a
    single COPY places in one layer. It exercises the scanner contracts only; it is never evidence
    about a scanned Prometheus image and must not be mistaken for a native capture.
    """
    components = load("component_scanner")
    source = load("component_source")
    fixture = capture("node-exporter")
    service_manifest = json.loads((root / "requirements/service-builds/manifest.json").read_bytes())
    recipe_path = service_manifest["services"]["prometheus"]["dockerfile"]
    recipe = (root / recipe_path).read_bytes()
    sbom = fixture["sbom"]
    old_main = next(p for p in sbom["packages"] if p["name"] == "github.com/prometheus/node_exporter")
    old_file = next(f for f in sbom["files"] if f["fileName"] == "bin/node_exporter")
    dependencies = [p for p in sbom["packages"]
                    if p["SPDXID"] not in {old_main["SPDXID"], components.DOCUMENT_ROOT} and p["name"] != "busybox"]
    packages = [p for p in sbom["packages"] if p["SPDXID"] == components.DOCUMENT_ROOT or p["name"] == "busybox"]
    files = [f for f in sbom["files"] if f["fileName"] != "bin/node_exporter"]
    relationships = [r for r in sbom["relationships"]
                     if r["relationshipType"] == "OTHER" and r["spdxElementId"] != old_main["SPDXID"]]
    trivy_packages = {p["Name"]: p for p in fixture["trivy"]["Results"][0]["Packages"] if p.get("Version")}
    results = []
    # promtool links a subset of the dependencies; the union is the runtime's native inventory.
    for path, tag, selected in (("/bin/prometheus", "prometheus", dependencies),
                                ("/bin/promtool", "promtool", dependencies[:-6])):
        suffix = hashlib.sha256(path.encode()).hexdigest()[:16]
        main_id = f"SPDXRef-Package-go-module-github.com-prometheus-prometheus-{suffix}"
        file_id = f"SPDXRef-File-bin-{tag}-{suffix}"
        packages.append({**copy.deepcopy(old_main), "name": "github.com/prometheus/prometheus", "SPDXID": main_id,
                         "sourceInfo": "acquired package info from go module information: " + path,
                         "externalRefs": [
                             {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                              "referenceLocator": "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*"},
                             {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": "pkg:golang/github.com/prometheus/prometheus"}]})
        files.append({**copy.deepcopy(old_file), "fileName": path[1:], "SPDXID": file_id, "checksums": [
            {"algorithm": "SHA256", "checksumValue": hashlib.sha256(path.encode()).hexdigest()}]})
        relationships.append({"spdxElementId": main_id, "relatedSpdxElement": file_id, "relationshipType": "OTHER",
                              "comment": components.EVIDENT_BY})
        for dependency in selected:
            projected = copy.deepcopy(dependency)
            projected["SPDXID"] = f"{dependency['SPDXID']}-{tag}"
            projected["sourceInfo"] = "acquired package info from go module information: " + path
            packages.append(projected)
            relationships.append({"spdxElementId": projected["SPDXID"], "relatedSpdxElement": main_id,
                                  "relationshipType": "DEPENDENCY_OF"})
        main = copy.deepcopy(fixture["trivy"]["Results"][0]["Packages"][0])
        main.update({"ID": "github.com/prometheus/prometheus", "Name": "github.com/prometheus/prometheus",
                     "Identifier": {"PURL": "pkg:golang/github.com/prometheus/prometheus", "UID": suffix}})
        results.append({"Target": path[1:], "Class": "lang-pkgs", "Type": "gobinary",
                        "Packages": [main, *(copy.deepcopy(trivy_packages[d["name"]]) for d in selected)],
                        "Vulnerabilities": copy.deepcopy(fixture["trivy"]["Results"][0].get("Vulnerabilities", []))})
    relationships = [{"spdxElementId": components.DOCUMENT_ROOT, "relatedSpdxElement": p["SPDXID"],
                      "relationshipType": "CONTAINS"} for p in packages
                     if p["SPDXID"] != components.DOCUMENT_ROOT] + relationships
    fixture["sbom"] = {**sbom, "packages": packages, "files": files, "relationships": relationships}
    fixture["trivy"]["Results"] = results
    provenance = fixture["provenance"][0]
    predicate = provenance["statement"]["predicate"]
    definition = predicate["buildDefinition"]
    definition["externalParameters"]["configSource"]["path"] = Path(recipe_path).name
    definition["externalParameters"]["request"]["root"]["configSource"]["path"] = Path(recipe_path).name
    metadata = predicate["runDetails"]["metadata"]["buildkit_metadata"]
    metadata["source"]["infos"][0].update({"filename": Path(recipe_path).name,
                                           "data": base64.b64encode(recipe).decode()})
    graph = source.expected_graph(recipe, (root / ".dockerignore").read_bytes(), "linux/amd64", "prometheus")
    definition["internalParameters"]["buildConfig"] = {
        "llbDefinition": graph,
        "digestMapping": {"sha256:" + hashlib.sha256(node["id"].encode()).hexdigest(): node["id"] for node in graph}}
    fixture["service_manifest"] = service_manifest
    fixture["source_inputs"] = {name: (root / name).read_text(encoding="utf-8") for name in (
        recipe_path, ".dockerignore", "requirements/service-builds/prometheus/go.mod",
        "requirements/service-builds/prometheus/go.sum", "requirements/service-builds/prometheus/modules.txt")}
    fixture["capture"].update({"service": "prometheus", "synthetic": "projected onto node-exporter-current-amd64; "
                               "not a native Prometheus capture"})
    return fixture
