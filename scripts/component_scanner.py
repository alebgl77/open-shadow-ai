"""Closed, subject-bound coverage for binaries outside Trivy's package inventory.

The original SPDX observations are retained. A source release projection is an
explicit claim about build inputs, never a version observed in an UNKNOWN binary.
"""

import copy
import hashlib
import json
import math
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

FAILURE_STAGES = frozenset({
    "source_guard", "layout_prepare", "layout_check", "trivy_inventory", "trivy_scan", "trivy_report",
    "inventory_partition", "source_binding", "principal_receipt", "principal_source", "native_gate",
    "grype_prepare", "sentinel_query", "sentinel_report", "component_query", "component_report",
    "grype_postcheck", "spdx_postcheck", "layout_postcheck", "source_postcheck", "metadata_prepare",
    "cleanup", "evidence_postcheck", "metadata_publish", "advisory_gate",
})
FAILURE_CODES = frozenset({
    "validation_refused", "filesystem", "nonzero", "timeout", "interrupted", "advisory_failed", "unclassified",
    "platform", "manifest", "config", "identity_changed", "byte_budget", "deadline", "download", "archive",
    "version", "json", "database", "identifier", "query_budget", "output_budget", "owned_cleanup_failed",
    "configuration_unobserved",
})
FAILURE_PREPARE_PHASES = frozenset({
    "source_guard", "workspace", "download", "extract", "config", "version", "check_files",
    "update", "adopt_database", "status", "import_validation",
})
FAILURE_FILESYSTEM_REASONS = frozenset({
    "directory_not_safe", "file_not_regular", "hardlink", "tree_unexpected", "root_unexpected",
    "tree_nonregular", "tree_unlinked", "tree_hardlink", "tree_file_oversize",
    "home_nonempty", "tmp_nonempty", "cache_unexpected", "identity_drift", "syscall",
})
FAILURE_TYPES = {
    ValueError: "ValueError", OSError: "OSError", PermissionError: "PermissionError",
    FileNotFoundError: "FileNotFoundError", FileExistsError: "FileExistsError", TimeoutError: "TimeoutError",
    subprocess.CalledProcessError: "CalledProcessError", subprocess.TimeoutExpired: "TimeoutExpired",
    KeyboardInterrupt: "KeyboardInterrupt", SystemExit: "SystemExit",
}


def validate_failure_diagnostic(value):
    """Failure diagnostics are a closed, unsigned schema with no exception payload."""
    required = {"schema", "kind", "status", "accepted", "stage", "error_type", "code", "secondary"}
    if type(value) is not dict or any(type(key) is not str for key in value) or \
            not required <= set(value) or set(value) - required - {"prepare_phase", "filesystem_reason"} or \
            type(value["schema"]) is not int or type(value["accepted"]) is not bool or \
            any(type(value[key]) is not str for key in ("kind", "status", "stage", "error_type", "code")) or \
            type(value["secondary"]) is not list or \
            any(type(note) is not str for note in value["secondary"]):
        raise ValueError("Invalid unsigned scanner failure diagnostic")
    if "prepare_phase" in value and (value["error_type"] != "GrypeRuntimeError" or
            value["stage"] != "grype_prepare" or type(value["prepare_phase"]) is not str or
            value["prepare_phase"] not in FAILURE_PREPARE_PHASES) or \
            "filesystem_reason" in value and (value["error_type"] != "GrypeRuntimeError" or
            value["code"] != "filesystem" or type(value["filesystem_reason"]) is not str or
            value["filesystem_reason"] not in FAILURE_FILESYSTEM_REASONS):
        raise ValueError("Invalid unsigned scanner failure diagnostic")
    if value["schema"] != 1 or value["kind"] != "image-scan-failure" or value["status"] != "diagnostic-only" or \
            value["accepted"] or \
            value["stage"] not in FAILURE_STAGES or value["code"] not in FAILURE_CODES or \
            value["error_type"] not in {*FAILURE_TYPES.values(), "GrypeRuntimeError", "unclassified"} or \
            any(note != "owned_cleanup_failed" for note in value["secondary"]) or \
            len(value["secondary"]) > 1:
        raise ValueError("Invalid unsigned scanner failure diagnostic")
    if len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")) > 2048:
        raise ValueError("Unsigned scanner failure diagnostic exceeds budget")


class FailureDiagnostic:
    """Capture the first refusal before disposal; never inspect arbitrary exception strings."""

    def __init__(self):
        self.stage = "source_guard"
        self.first = None
        self.secondary = set()
        self.grype_error_type = None

    def at(self, stage):
        if type(stage) is not str or stage not in FAILURE_STAGES:
            raise ValueError("Unknown scanner diagnostic stage")
        self.stage = stage

    def capture(self, error):
        error_type = type(error)
        kind = next((name for known, name in FAILURE_TYPES.items() if error_type is known), "unclassified")
        code = "unclassified"
        trusted = kind != "unclassified" or error_type is self.grype_error_type
        if error_type is self.grype_error_type:
            kind = "GrypeRuntimeError"
            candidate = error.code
            code = candidate if type(candidate) is str and candidate in FAILURE_CODES else "unclassified"
        elif error_type is ValueError:
            code = "validation_refused"
        elif any(error_type is known for known in (OSError, PermissionError, FileNotFoundError, FileExistsError)):
            code = "filesystem"
        elif error_type is subprocess.CalledProcessError:
            code = "nonzero"
        elif error_type is TimeoutError or error_type is subprocess.TimeoutExpired:
            code = "timeout"
        elif error_type is KeyboardInterrupt or error_type is SystemExit:
            code = "advisory_failed" if self.stage == "advisory_gate" else "interrupted"
        if trusted:
            notes = error.__dict__.get("__notes__", [])
            if type(notes) is list and any(type(note) is str and note == "owned_cleanup_failed" for note in notes):
                self.secondary.add("owned_cleanup_failed")
        if self.first is None:
            self.first = {"stage": self.stage, "error_type": kind, "code": code}
            if error_type is self.grype_error_type:
                attributes = error.__dict__
                if type(attributes) is dict:
                    phase = attributes.get("prepare_phase")
                    reason = attributes.get("filesystem_reason")
                    if self.stage == "grype_prepare" and type(phase) is str and phase in FAILURE_PREPARE_PHASES:
                        self.first["prepare_phase"] = phase
                    if code == "filesystem" and type(reason) is str and reason in FAILURE_FILESYSTEM_REASONS:
                        self.first["filesystem_reason"] = reason

    @contextmanager
    def context(self, context):
        try:
            with context as handle:
                try:
                    yield handle
                except BaseException as primary:
                    self.capture(primary)
                    raise
        except BaseException as primary:
            self.capture(primary)
            raise

    def emit(self, output, primary):
        self.capture(primary)
        value = {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
                 **self.first, "secondary": sorted(self.secondary)}
        validate_failure_diagnostic(value)
        data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        parent = Path(output)
        before = parent.lstat()
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or \
                getattr(parent, "is_junction", lambda: False)():
            raise ValueError("Unsigned diagnostic output parent refused")
        name = "image-scan." + uuid4().hex + ".failure.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        directory_fd = file_fd = None
        try:
            anchored = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")
            if anchored:
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
                opened = os.fstat(directory_fd)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError("Unsigned diagnostic output parent changed")
            file_fd = os.open(name if anchored else parent / name, flags, 0o600,
                              **({"dir_fd": directory_fd} if anchored else {}))
            after = parent.lstat()
            if (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode)) != \
                    (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode)):
                raise ValueError("Unsigned diagnostic output parent changed")
            while data:
                written = os.write(file_fd, data)
                if written <= 0:
                    raise OSError("Unsigned diagnostic write refused")
                data = data[written:]
        finally:
            try:
                if file_fd is not None:
                    closing, file_fd = file_fd, None
                    os.close(closing)
            finally:
                if directory_fd is not None:
                    closing, directory_fd = directory_fd, None
                    os.close(closing)

DOCUMENT_ROOT = "SPDXRef-DocumentRoot-Directory-sbom"
EVIDENT_BY = "evident-by: indicates the package's existence is evident by the given file"
COMPONENTS = {
    "postgres": (
        ("github.com/tianon/gosu", None, "/usr/local/bin/gosu", "gosu",
         ("cpe:2.3:a:tianon:gosu:*:*:*:*:*:*:*:*",)),
        ("postgresql", "16.15", "/usr/local/bin/postgres", None,
         ("cpe:2.3:a:postgresql:postgresql:16.15:*:*:*:*:*:*:*",)),
    ),
    "node-exporter": (
        ("busybox", "1.38.0", "/bin/busybox", None,
         ("cpe:2.3:a:busybox:busybox:1.38.0:*:*:*:*:*:*:*",)),
        ("github.com/prometheus/node_exporter", None, "/bin/node_exporter", "node-exporter",
         ("cpe:2.3:a:prometheus:node-exporter:*:*:*:*:*:*:*:*",
          "cpe:2.3:a:prometheus:node_exporter:*:*:*:*:*:*:*:*")),
    ),
    "redis": (
        ("redis", "7.4.11", "/usr/local/bin/redis-server", None,
         ("cpe:2.3:a:redislabs:redis:7.4.11:*:*:*:*:*:*:*",
          "cpe:2.3:a:redis:redis:7.4.11:*:*:*:*:*:*:*")),
    ),
    "clickhouse": (),
}
RELEASES = {"gosu": "1.19", "node-exporter": "1.12.1"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique(items, field):
    if not isinstance(items, list) or any(not isinstance(x, dict) or not isinstance(x.get(field), str)
                                          or not x[field] for x in items):
        raise ValueError("Malformed component inventory")
    result = {x[field]: x for x in items}
    if len(result) != len(items):
        raise ValueError("Ambiguous component inventory")
    return result


def partition(sbom, *, service, package_key):
    """Assign every software package exactly once; retain all original observations."""
    before = digest(sbom)
    packages = unique(sbom.get("packages"), "SPDXID")
    files = unique(sbom.get("files"), "SPDXID")
    relationships = sbom.get("relationships")
    if not isinstance(relationships, list) or any(not isinstance(r, dict) for r in relationships) or \
            len({canonical(r) for r in relationships}) != len(relationships):
        raise ValueError("Malformed or duplicated SPDX relationships")
    root = packages.get(DOCUMENT_ROOT)
    if root != {"name": "sbom", "SPDXID": DOCUMENT_ROOT, "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION", "primaryPackagePurpose": "FILE"}:
        raise ValueError("Unsupported identityless SPDX package")
    if service not in COMPONENTS:
        raise ValueError("Unsupported maintained component")
    native, assigned, claims = set(), set(), []
    for package_id, package in packages.items():
        if package_id == DOCUMENT_ROOT:
            continue
        contained = {"spdxElementId": DOCUMENT_ROOT, "relatedSpdxElement": package_id,
                     "relationshipType": "CONTAINS"}
        if contained not in relationships:
            raise ValueError("Software package is disconnected from SPDX document root")
        refs = package.get("externalRefs")
        if not isinstance(refs, list):
            raise ValueError("Software package has no identity")
        purls = [r.get("referenceLocator") for r in refs if r.get("referenceType") == "purl"]
        if len(purls) != 1 or len({canonical(r) for r in refs}) != len(refs):
            raise ValueError("Software package identity is missing or ambiguous")
        purl = purls[0]
        definition = next((d for d in COMPONENTS[service] if package.get("name") == d[0]), None)
        if definition is None:
            key = package_key(purl)
            observed_version = package.get("versionInfo")
            if key[:2] == ("golang", "stdlib") and isinstance(observed_version, str):
                observed_version = package_key(f"pkg:golang/stdlib@{observed_version}")[2]
            if key[0] not in {"deb", "apk", "golang"} or observed_version != key[2] or \
                    service == "clickhouse" and (key[0] != "apk" or "clickhouse" in key[1].lower()):
                raise ValueError("Unsupported or inconsistent native software package")
            if key in native:
                raise ValueError("Duplicate native software package identity")
            native.add(key)
            continue
        name, version, path, source_component, cpes = definition
        expected_purl = f"pkg:golang/{name}" if version is None else f"pkg:generic/{name}@{version}"
        if purl != expected_purl or package.get("versionInfo") != (version or "UNKNOWN"):
            raise ValueError("Complement component identity/version mismatch")
        if name in assigned:
            raise ValueError("Duplicate complement component")
        assigned.add(name)
        observed_cpes = [r.get("referenceLocator") for r in refs
                         if r.get("referenceType") in {"cpe23Type", "cpe22Type"}]
        if sorted(observed_cpes) != sorted(cpes) or len(refs) != 1 + len(cpes):
            raise ValueError("Complement component CPE inventory mismatch")
        expected_info = ("acquired package info from go module information: " if version is None else
                         "acquired package info from the following paths: ") + path
        if package.get("sourceInfo") != expected_info:
            raise ValueError("Complement component binary path mismatch")
        evidence = [r for r in relationships if r.get("spdxElementId") == package_id and
                    r.get("relationshipType") == "OTHER"]
        if len(evidence) != 1 or evidence[0].get("comment") != EVIDENT_BY:
            raise ValueError("Complement component has no unique binary evidence")
        binary = files.get(evidence[0].get("relatedSpdxElement"))
        if binary is None or binary.get("fileName") != path[1:] or \
                binary.get("fileTypes") != ["APPLICATION", "BINARY"] or \
                not re.fullmatch(r"layerID: sha256:[a-f0-9]{64}", binary.get("comment", "")):
            raise ValueError("Complement binary evidence path/type mismatch")
        checksums = binary.get("checksums")
        if not isinstance(checksums, list) or len(checksums) != 1 or \
                checksums[0].get("algorithm") != "SHA256" or \
                not re.fullmatch(r"[a-f0-9]{64}", checksums[0].get("checksumValue", "")):
            raise ValueError("Complement binary evidence checksum missing")
        queries = []
        if source_component:
            projected_version = RELEASES[source_component]
            queries.append(f"pkg:golang/{name}@{projected_version}")
            queries.extend(cpe.replace(":*:", f":{projected_version}:", 1) for cpe in cpes)
        else:
            projected_version = version
            queries.extend(cpes)
        claims.append({"spdx_id": package_id, "original_package": copy.deepcopy(package),
                       "original_relationships": copy.deepcopy([r for r in relationships if
                            r.get("spdxElementId") == package_id or r.get("relatedSpdxElement") == package_id]),
                       "original_binary_file": copy.deepcopy(binary), "binary_path": path,
                       "source_component": source_component, "source_release_projection": projected_version
                       if source_component else None, "observed_unversioned": version is None,
                       "binary_version_claim": version, "queries": queries})
    if assigned != {d[0] for d in COMPONENTS[service]} or not native or digest(sbom) != before:
        raise ValueError("Incomplete component assignment or SPDX changed")
    return {"spdx_sha256": before, "native": native, "components": claims,
            "software_package_count": len(packages) - 1}


def validate_main_observation(package, result, claim):
    """Require the exact original unversioned main module, never excuse another UNKNOWN."""
    original = claim["original_package"]
    if not claim["observed_unversioned"] or result.get("Type") != "gobinary" or \
            result.get("Class") != "lang-pkgs" or result.get("Target") != claim["binary_path"][1:] or \
            package.get("Name") != original["name"] or package.get("ID") != original["name"] or \
            package.get("Identifier", {}).get("PURL") != f"pkg:golang/{original['name']}" or \
            package.get("Version") not in (None, "") or package.get("Relationship") != "root" or \
            package.get("AnalyzedBy") != "gobinary":
        raise ValueError("Trivy unversioned main module observation mismatch")


def validate_report(report, *, query, configuration, database_status):
    """Validate a direct-query report; matches are findings, not package inventory."""
    if not isinstance(report, dict):
        raise ValueError("Malformed complement report")
    descriptor = report.get("descriptor", {})
    source_type = "purl" if query.startswith("pkg:") else "cpe"
    database = descriptor.get("db", {}) if isinstance(descriptor, dict) else {}
    if not isinstance(descriptor, dict) or not isinstance(database, dict) or \
            set(database) != {"status", "providers"} or database.get("status") != database_status or \
            not isinstance(database.get("providers"), dict) or not database["providers"] or \
            descriptor.get("name") != "grype" or descriptor.get("version") != "0.120.1" or \
            descriptor.get("configuration") != configuration or \
            report.get("source") != {"type": source_type, "target": query}:
        raise ValueError("Complement query/tool/configuration/database echo mismatch")
    matches = report.get("matches")
    # The pinned JSON model omits this field when its list is empty.
    if not isinstance(matches, list) or report.get("ignoredMatches", []) != []:
        raise ValueError("Complement findings are incomplete or ignored")
    findings, seen, observed_artifact = [], set(), None
    for match in matches:
        if not isinstance(match, dict):
            raise ValueError("Malformed complement match")
        artifact, vulnerability = match.get("artifact", {}), match.get("vulnerability", {})
        if not isinstance(artifact, dict) or not isinstance(vulnerability, dict) or \
                not isinstance(artifact.get("id"), str) or not artifact["id"] or \
                not isinstance(vulnerability.get("id"), str) or not vulnerability["id"]:
            raise ValueError("Malformed complement finding identity")
        if source_type == "purl":
            identity, _, version = query[11:].rpartition("@")
            if artifact.get("purl") != query or artifact.get("name") != identity or \
                    artifact.get("version") != version:
                raise ValueError("Complement finding contradicts Go query identity")
        else:
            cpe = query.split(":")
            if artifact.get("name") != cpe[4] or artifact.get("version") != cpe[5] or \
                    artifact.get("cpes") != [query]:
                raise ValueError("Complement finding contradicts CPE query identity")
        if observed_artifact is not None and artifact != observed_artifact:
            raise ValueError("Complement findings contain contradictory package identities")
        observed_artifact = copy.deepcopy(artifact)
        finding_id = (artifact["id"], vulnerability["id"], vulnerability.get("namespace"))
        if finding_id in seen:
            raise ValueError("Duplicate complement finding")
        seen.add(finding_id)
        fix = vulnerability.get("fix")
        if not isinstance(fix, dict) or not isinstance(fix.get("versions"), list) or \
                any(not isinstance(v, str) or not v for v in fix["versions"]):
            raise ValueError("Malformed complement fix status")
        severity = vulnerability.get("severity")
        if fix["versions"] and severity not in {"Low", "Medium", "Negligible"}:
            findings.append(f"{query}: {vulnerability['id']}")
    return findings


def validate_sentinel_report(report, *, query, configuration, database_status, required_advisories):
    """Require a known advisory on the validated query, preserving all original IDs."""
    findings = validate_report(report, query=query, configuration=configuration, database_status=database_status)

    def number(value):
        return type(value) is int or (type(value) is float and math.isfinite(value))

    def record(value, *, strings=(), optional_strings=(), numbers=(), optional_numbers=(), string_lists=()):
        if type(value) is not dict or any(type(key) is not str for key in value) or \
                any(type(value.get(field)) is not str for field in strings) or \
                any(field in value and type(value[field]) is not str for field in optional_strings) or \
                any(not number(value.get(field)) for field in numbers) or \
                any(field in value and not number(value[field]) for field in optional_numbers) or \
                any(field in value and (type(value[field]) is not list or
                    any(type(item) is not str for item in value[field])) for field in string_lists):
            raise ValueError("Malformed sentinel related advisory metadata")

    matched = False
    required_cves = {identifier for identifier in required_advisories if identifier.startswith("CVE-")}
    for match in report["matches"]:
        related = match.get("relatedVulnerabilities")
        if related is not None:
            if type(related) is not list:
                raise ValueError("Malformed sentinel related advisory metadata")
            seen = set()
            for advisory in related:
                if type(advisory) is not dict or any(type(key) is not str for key in advisory) or \
                        type(advisory.get("id")) is not str or not advisory["id"] or \
                        type(advisory.get("dataSource")) is not str or \
                        type(advisory.get("urls")) is not list or \
                        any(type(url) is not str for url in advisory["urls"]) or \
                        type(advisory.get("cvss")) is not list or \
                        any(type(score) is not dict for score in advisory["cvss"]):
                    raise ValueError("Malformed sentinel related advisory metadata")
                for field in ("namespace", "severity", "description"):
                    if field in advisory and type(advisory[field]) is not str:
                        raise ValueError("Malformed sentinel related advisory metadata")
                for field in ("knownExploited", "epss", "cwes"):
                    if field in advisory and (type(advisory[field]) is not list or
                            any(type(item) is not dict for item in advisory[field])):
                        raise ValueError("Malformed sentinel related advisory metadata")
                for score in advisory["cvss"]:
                    record(score, strings=("version", "vector"), optional_strings=("source", "type"))
                    if "vendorMetadata" not in score:
                        raise ValueError("Malformed sentinel related advisory metadata")
                    record(score.get("metrics"), numbers=("baseScore",),
                           optional_numbers=("exploitabilityScore", "impactScore"))
                for item in advisory.get("knownExploited", []):
                    record(item, strings=("cve", "knownRansomwareCampaignUse"),
                           optional_strings=("vendorProject", "product", "dateAdded", "requiredAction",
                                             "dueDate", "notes"),
                           string_lists=("urls", "cwes"))
                for item in advisory.get("epss", []):
                    record(item, strings=("cve", "date"), numbers=("epss", "percentile"))
                for item in advisory.get("cwes", []):
                    record(item, strings=("cve",), optional_strings=("cwe", "source", "type"))
                identity = (advisory["id"], advisory.get("namespace", ""))
                if identity in seen:
                    raise ValueError("Duplicate sentinel related advisory metadata")
                seen.add(identity)
                if advisory["id"] in required_cves:
                    if advisory.get("namespace") != "nvd:cpe" or \
                            advisory["dataSource"] != "https://nvd.nist.gov/vuln/detail/" + advisory["id"]:
                        raise ValueError("Sentinel related advisory source differs")
                    matched = True
        if match["vulnerability"]["id"] in required_advisories:
            matched = True
    if not matched:
        raise ValueError("Complement scanner known-vulnerable sentinel did not match")
    return findings


def bind_components(partition, *, documents, service, platform, root, service_manifest, expected_source, binder):
    """Bind exact file evidence to the selected rootFS and source projections to BuildKit."""
    layers = {descriptor["digest"] for descriptor in documents["manifest"]["layers"]}
    source_proof = None
    for claim in partition["components"]:
        binary_layer = claim["original_binary_file"]["comment"].split(" ")[1]
        if binary_layer not in layers:
            raise ValueError("Complement binary evidence layer is outside selected image")
        if claim["source_component"]:
            if source_proof is not None:
                raise ValueError("Ambiguous main-module source projection")
            source_proof = binder(documents["provenance"]["statement"]["predicate"], service=service,
                                  platform=platform, selected_manifest=documents["manifest"], root=root,
                                  service_manifest=service_manifest, expected_source=expected_source)
            if source_proof["binary_copy_layer"] != binary_layer or \
                    source_proof["binary_path"] != claim["binary_path"]:
                raise ValueError("Observed binary does not correspond to locked source copy output")
            claim["source_proof"] = source_proof
        else:
            claim["source_proof"] = {"claim_kind": "observed_subject_bound_binary_inventory",
                                     "binary_path": claim["binary_path"], "binary_layer": binary_layer,
                                     "binary_version_claim": claim["binary_version_claim"]}
        claim["source_proof_sha256"] = digest(claim["source_proof"])
    return partition


def declare_clickhouse(partition, *, receipt, receipt_sha256, source_proof):
    """Add an explicit absent-inventory principal, without fabricating SPDX observations."""
    if partition["components"] or source_proof.get("functional_version") != "25.8.33.6" or \
            not re.fullmatch(r"[a-f0-9]{64}", receipt_sha256):
        raise ValueError("Declared principal assignment is ambiguous or unbound")
    claim = {"assignment_kind": "declared_principal_binary", "spdx_id": None, "original_spdx_ids": [],
             "original_package": None, "original_relationships": [], "original_binary_file": None,
             "original_inventory_observation": "absent", "binary_path": "/usr/bin/clickhouse",
             "source_component": None, "source_release_projection": None, "observed_unversioned": False,
             "binary_version_claim": None, "declared_version": "25.8.33.6",
             "observed_cli_version": receipt["observation"]["version"],
             "principal_observation_sha256": receipt_sha256,
             "queries": ["cpe:2.3:a:clickhouse:clickhouse:25.8.33.6:*:*:*:*:*:*:*"],
             "source_proof": source_proof, "source_proof_sha256": digest(source_proof)}
    if claim["observed_cli_version"] != claim["declared_version"]:
        raise ValueError("Declared principal and native CLI versions differ")
    partition["components"].append(claim)
    return partition


def query_receipt(*, claim, query, report_path, report_sha256, subject, platform, expected_source, sbom_blob,
                  provenance_blob, runtime_receipt):
    if query not in claim["queries"]:
        raise ValueError("Query is not assigned to the original SPDX component")
    return {"query": query, "report_path": report_path, "report_sha256": report_sha256,
            "spdx_id": claim["spdx_id"], "subject": subject, "platform": platform,
            "assignment_kind": claim.get("assignment_kind", "original_spdx_package"),
            "original_spdx_ids": claim.get("original_spdx_ids", [claim["spdx_id"]]),
            "principal_observation_sha256": claim.get("principal_observation_sha256"),
            "source_commit": expected_source["commit"], "repository": expected_source["repository"],
            "sbom_blob": sbom_blob, "provenance_blob": provenance_blob,
            "source_proof_sha256": claim["source_proof_sha256"], "runtime_receipt_sha256": digest(runtime_receipt)}
