"""Revalidate subject-bound scanner receipts before producing an attestable manifest."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 128 * 1024 * 1024
SHA = re.compile(r"[a-f0-9]{64}")


def script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path):
    """Read one bounded regular file while refusing replacements and native text translation."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > LIMIT:
        raise ValueError("Evidence must be bounded regular files")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            opened = os.fstat(descriptor)
            data = stream.read(LIMIT + 1)
            after = os.fstat(descriptor)
        def identity(item):
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns
        current = path.lstat()
        # Windows CRT fstat reports ctime differently from pathname stat. Compare
        # each clock with its own baseline while still anchoring inode/size/mtime.
        if len(data) > LIMIT or identity(before) != identity(opened) or identity(opened) != identity(after) or \
                identity(after) != identity(current) or opened.st_ctime_ns != after.st_ctime_ns or \
                before.st_ctime_ns != current.st_ctime_ns:
            raise ValueError("Evidence file changed while being read")
        return data
    finally:
        os.close(descriptor)


def decode(data):
    """Reject ambiguous JSON reports rather than silently selecting duplicate keys."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Ambiguous scanner evidence JSON")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("Nonfinite scanner evidence JSON")
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Malformed scanner evidence JSON") from error


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Evidence database timestamp missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Evidence database timestamp malformed") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("Evidence database timestamp must be UTC")
    return parsed


def validate_runtime(receipt, *, root, platform, source_hashes, now):
    """Revalidate recorded integrity/freshness claims; this does not rerun the tool or DB."""
    pin = json.loads((root / "requirements/component-scanner.json").read_bytes())
    tool = receipt.get("tool", {})
    if tool.get("name") != "grype" or tool.get("version") != pin["version"] or \
            tool.get("release_commit") != pin["commit"] or \
            tool.get("archive_sha256") != pin["archives"][platform]["sha256"] or \
            not SHA.fullmatch(tool.get("binary_sha256", "")) or \
            receipt.get("manifest_sha256") != source_hashes["requirements/component-scanner.json"] or \
            receipt.get("config_template_sha256") != source_hashes["requirements/grype.yaml"] or \
            receipt.get("runtime_module_sha256") != source_hashes["scripts/grype_runtime.py"] or \
            not SHA.fullmatch(receipt.get("config_sha256", "")):
        raise ValueError("Recorded complement tool/configuration source binding differs")
    # Reuse the isolated runtime's effective-policy validator, without executing a tool.
    runtime = script("grype_runtime")
    configuration = receipt.get("configuration")
    runtime.validate_configuration(configuration, platform=platform)
    rendered = json.loads(runtime.canonical(runtime.TEMPLATE))
    rendered["db"]["cache-dir"] = configuration["db"]["cache-dir"]
    if receipt["config_sha256"] != hashlib.sha256(runtime.canonical(rendered)).hexdigest():
        raise ValueError("Recorded rendered complement configuration differs")
    database = receipt.get("database", {})
    status = database.get("status", {})
    built, fetched = timestamp(status.get("built")), timestamp(database.get("fetched_at"))
    runtime.validate_status(status, PurePosixPath(configuration["db"]["cache-dir"]), database["fetched_at"])
    if built > fetched or fetched > now or now - built > timedelta(hours=24):
        raise ValueError("Recorded complement database is stale or future dated")
    files = database.get("files")
    if not isinstance(files, dict) or not {"6/import.json", "6/vulnerability.db"} <= files.keys() or \
            files.keys() - {"6/import.json", "6/vulnerability.db", "6/last_update_check"} or \
            any(not isinstance(name, str) or name.startswith("/") or
            ".." in name.split("/") or not SHA.fullmatch(value) for name, value in files.items()) or \
            database.get("digest") != script("component_scanner").digest(files):
        raise ValueError("Recorded complement database file-table digest differs")
    return receipt["configuration"], status


def validate(*, metadata, report, layout, image, platform, root, audit_directory, expected_source, pins,
             service_manifest, load_report, now=None):
    """Reconstruct assignments/queries and every subject/file binding from the exact archive."""
    scan = script("scan-images")
    components = script("component_scanner")
    source = script("component_source")
    maintained = image in pins.SERVICES
    fingerprints = scan.source_fingerprints(root, maintained, image == "clickhouse")
    subject = {"archive_sha256": layout.evidence["archive_sha256"],
               "image_manifest": layout.evidence["image_manifests"][0],
               "image_config": layout.evidence["image_configs"][layout.evidence["image_manifests"][0]]}
    if metadata.get("verdict") != "passed" or metadata.get("findings") != [] or \
            metadata.get("source_dirty") is not False or metadata.get("subject") != subject or \
            metadata.get("platform") != platform or metadata.get("source_commit") != expected_source["commit"] or \
            metadata.get("repository") != expected_source["repository"] or \
            metadata.get("source_fingerprints") != fingerprints or \
            metadata.get("scanner_script_sha256") != fingerprints["scripts/scan-images.py"]:
        raise ValueError("Accepted scanner evidence/source/subject/verdict binding differs")
    if metadata.get("oci_layout") != layout.assert_unchanged():
        raise ValueError("Recorded OCI snapshot/file-table/helper evidence differs")
    image_manifest = subject["image_manifest"]
    sbom = layout.evidence["sboms"][image_manifest]
    complement = None
    if maintained:
        documents = source.subject_documents(layout, image_manifest)
        complement = components.partition(sbom, service=image, package_key=scan.package_key)
        components.bind_components(complement, documents=documents, service=image, platform=platform,
                                   root=root, service_manifest=service_manifest,
                                   expected_source=expected_source, binder=source.bind)
        recorded_principal = metadata.get("complement", {}).get("principal_observation")
        if image == "clickhouse":
            principal = script("component_principal")
            expected_ci = principal.ci_identity(os.environ, signing=True)
            if not isinstance(recorded_principal, dict) or set(recorded_principal) != {
                "report_path", "report_sha256", "receipt"
            } or recorded_principal.get("report_path") != "clickhouse.principal-observation.json":
                raise ValueError("Declared principal observation is absent or ambiguous")
            principal.canonical_receipt_path(audit_directory / recorded_principal["report_path"],
                                             expected_parent=audit_directory)
            observation = load_report(recorded_principal)
            if observation != recorded_principal["receipt"]:
                raise ValueError("Declared principal raw observation changed")
            principal.validate_receipt(observation, subject={**subject,
                "image_manifest": "sha256:" + image_manifest.removeprefix("sha256:"), "platform": platform},
                config=documents["config"], expected_source=expected_source, expected_ci=expected_ci,
                collector_sha256=fingerprints["scripts/observe-clickhouse-version.py"],
                process_module_sha256=fingerprints["scripts/grype_runtime.py"])
            proof = source.bind_clickhouse(documents["provenance"]["statement"]["predicate"], platform=platform,
                selected_manifest=documents["manifest"], root=root, service_manifest=service_manifest,
                expected_source=expected_source, expected_ci=expected_ci)
            components.declare_clickhouse(complement, receipt=observation,
                receipt_sha256=recorded_principal["report_sha256"], source_proof=proof)
        elif recorded_principal is not None:
            raise ValueError("Unexpected principal observation for another component")
        expected = complement["native"]
    else:
        expected = scan.spdx_inventory(sbom, frontend=image == "frontend")
    ecosystems = None if maintained else {"deb", "apk"} if image == "frontend" else {"deb", "apk", "pypi"}
    if scan.gate(report, expected=expected, complement=complement, artifact="/input/layout", platform=platform,
                 image_id=subject["image_config"], ecosystems=ecosystems):
        raise ValueError("Scanner evidence still contains fixable severe runtime findings")
    if metadata.get("expected_packages") != [list(row) for row in sorted(expected)]:
        raise ValueError("Recorded native package inventory differs")
    images = pins.inventory(root)
    if metadata.get("scanner") != images["trivy"]["reference"] or \
            metadata.get("images_manifest_sha256") != fingerprints["requirements/images.json"]:
        raise ValueError("Trivy pin/source binding differs")
    if not maintained:
        if metadata.get("complement") is not None:
            raise ValueError("Application image has unexpected complementary assignment")
        if image != "frontend":
            audit = script("audit-dependencies")
            environment = audit.default_environment()
            environment.update({"sys_platform": "linux", "os_name": "posix", "platform_system": "Linux",
                                "platform_machine": platform.split("/")[1], "python_version": "3.12",
                                "python_full_version": "3.12.15", "implementation_name": "cpython",
                                "platform_python_implementation": "CPython"})
            relative = "requirements/development.txt" if image == "test" else "requirements/runtime.txt"
            closure = audit.expected_python(root / relative, environment)
            if metadata.get("expected_dependencies") != closure or \
                    metadata.get("lock_sha256") != fingerprints[relative] or \
                    not {("pypi", package, version) for package, version in closure.items()} <= expected:
                raise ValueError("Python hash-locked image closure/source binding differs")
        return {"subject": subject, "native_packages": sorted(expected), "components": []}
    recorded = metadata.get("complement", {})
    if recorded.get("schema") != 1 or recorded.get("spdx_sha256") != complement["spdx_sha256"] or \
            recorded.get("components") != complement["components"] or \
            recorded.get("software_package_count") != complement["software_package_count"] or \
            metadata.get("role") != "derived-runtime" or \
            metadata.get("service_recipe") != service_manifest["services"][image] or \
            metadata.get("service_manifest_sha256") != fingerprints["requirements/service-builds/manifest.json"]:
        raise ValueError("Recorded complementary component/source assignment differs")
    runtime_receipt = recorded.get("runtime", {})
    configuration, status = validate_runtime(runtime_receipt, root=root, platform=platform,
                                             source_hashes=fingerprints, now=now or datetime.now(UTC))
    providers = None
    sentinels = recorded.get("sentinels")
    controls = (("cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*", {"CVE-2021-32675"}),
                ("pkg:golang/golang.org/x/crypto@0.1.0", {"CVE-2023-48795", "GHSA-45x7-px36-x8w8", "GO-2023-2402"}))
    if not isinstance(sentinels, list) or len(sentinels) != len(controls):
        raise ValueError("Missing real complementary scanner controls")
    for control, (query, ids) in zip(sentinels, controls, strict=True):
        if control.get("query") != query or control.get("required_advisories") != sorted(ids):
            raise ValueError("Complementary scanner control identity differs")
        raw = load_report(control)
        components.validate_sentinel_report(raw, query=query, configuration=configuration,
                                            database_status=status, required_advisories=ids)
        current_providers = raw["descriptor"]["db"]["providers"]
        if providers is not None and providers != current_providers:
            raise ValueError("Complementary scanner provider metadata changed")
        providers = current_providers
    expected_receipts = [(claim, query) for claim in complement["components"] for query in claim["queries"]]
    receipts = recorded.get("receipts")
    if not isinstance(receipts, list) or len(receipts) != len(expected_receipts):
        raise ValueError("Complementary coverage query inventory is incomplete or extra")
    seen_paths = set()
    for receipt, (claim, query) in zip(receipts, expected_receipts, strict=True):
        if receipt.get("report_path") in seen_paths:
            raise ValueError("Ambiguous complementary report coverage")
        seen_paths.add(receipt.get("report_path"))
        expected_receipt = components.query_receipt(
            claim=claim, query=query, report_path=receipt.get("report_path"),
            report_sha256=receipt.get("report_sha256"),
            subject=subject, platform=platform, expected_source=expected_source,
            sbom_blob=documents["sbom"]["blob"], provenance_blob=documents["provenance"]["blob"],
            runtime_receipt=runtime_receipt)
        if receipt != expected_receipt:
            raise ValueError("Complementary query receipt/source/subject binding differs")
        raw = load_report(receipt)
        if raw["descriptor"]["db"]["providers"] != providers or components.validate_report(
                raw, query=query, configuration=configuration, database_status=status):
            raise ValueError("Complementary runtime findings/provider metadata failed")
    return {"subject": subject, "native_packages": sorted(expected), "components": complement["components"],
            "database_receipt": runtime_receipt["database"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    if current != args.source_commit or dirty:
        raise ValueError("Signing evidence requires exact clean source checkout")
    pins = script("verify-image-pins")
    if args.image not in (*pins.APP_IMAGES, *pins.SERVICES):
        raise ValueError("Unknown scanned image component")
    images = pins.inventory(ROOT)
    services = pins.check_service_builds(ROOT, images)
    fingerprints = script("scan-images").source_fingerprints(
        ROOT, args.image in pins.SERVICES, args.image == "clickhouse")
    expected_source = {"commit": args.source_commit, "repository": args.repository}
    table = {}

    def load_file(name):
        if not isinstance(name, str) or not re.fullmatch(
                rf"{re.escape(args.image)}(?:\.json|\.metadata\.json|\.principal-observation\.json|\.complement-[a-f0-9]{{32}}/"
                r"(?:query-\d{2}|sentinel-[01])\.json)", name):
            raise ValueError("Unsafe or unexpected scanner evidence path")
        path = args.audit / name
        if path.resolve().parent != args.audit.resolve() and path.resolve().parent.parent != args.audit.resolve():
            raise ValueError("Scanner evidence path leaves audit directory")
        data = read(path)
        table[name] = hashlib.sha256(data).hexdigest()
        return decode(data)

    metadata = load_file(args.image + ".metadata.json")
    report = load_file(args.image + ".json")
    if metadata.get("report_sha256") != table[args.image + ".json"]:
        raise ValueError("Native Trivy raw report changed")

    def load_report(receipt):
        value = load_file(receipt.get("report_path"))
        if table[receipt["report_path"]] != receipt.get("report_sha256"):
            raise ValueError("Complementary raw report changed")
        return value

    with script("oci_scan_layout").prepared_layout(
        args.input, platform=args.platform, scratch_parent=args.output.parent,
        expected_source=expected_source, expected_component=args.image,
    ) as layout:
        bound = validate(metadata=metadata, report=report, layout=layout, image=args.image, platform=args.platform,
                         root=ROOT, audit_directory=args.audit, expected_source=expected_source, pins=pins,
                         service_manifest=services, load_report=load_report)
        layout.assert_unchanged()
    for name, fingerprint in table.items():
        if hashlib.sha256(read(args.audit / name)).hexdigest() != fingerprint:
            raise ValueError("Scanner evidence changed during revalidation")
    if script("scan-images").source_fingerprints(
            ROOT, args.image in pins.SERVICES, args.image == "clickhouse") != fingerprints:
        raise ValueError("Scanner source changed during revalidation")
    evidence = {"schema": 1, "verdict": "passed", "source_commit": args.source_commit,
                "repository": args.repository, "component": args.image, "platform": args.platform,
                "source_fingerprints": fingerprints, "files": table,
                "audit_directory": args.audit.name, "verification_kind": "revalidated_recorded_scan_evidence",
                "binding": bound}
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("PASS: exact scanned subject and complete native/complementary evidence revalidated")


if __name__ == "__main__":
    main()
