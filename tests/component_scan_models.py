"""Public captured component observations and explicitly synthetic tool-boundary models."""

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
    suffix = "current-amd64" if service in {"postgres", "node-exporter", "clickhouse"} else "amd64"
    return json.loads((ROOT / f"tests/fixtures/component-scanner/{service}-{suffix}.json").read_bytes())


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
