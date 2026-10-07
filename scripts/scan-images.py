"""Gate complete subject-bound Trivy inventories and retain every advisory."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import uuid
from contextlib import ExitStack, nullcontext
from pathlib import Path
from urllib.parse import parse_qsl, unquote

ROOT = Path(__file__).resolve().parents[1]
TRIVY_VERSION = "0.75.0"
EVIDENCE_SOURCE_FILES = (
    "scripts/scan-images.py", "scripts/component_scanner.py", "scripts/component_source.py",
    "scripts/component_principal.py",
    "scripts/oci_scan_layout.py", "scripts/verify-oci-evidence.py", "scripts/verify-image-pins.py",
    "scripts/verify-scan-evidence.py", ".github/workflows/ci.yml", ".dockerignore",
    "scripts/audit-dependencies.py", "requirements/runtime.txt", "requirements/development.txt",
    "requirements/images.json", "requirements/service-builds/manifest.json",
)


def source_fingerprints(root, maintained=False, principal=False):
    files = EVIDENCE_SOURCE_FILES + (("scripts/grype_runtime.py", "requirements/component-scanner.json",
                                      "requirements/grype.yaml") if maintained else ())
    if principal:
        files += ("scripts/observe-clickhouse-version.py",)
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in files}


def script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_key(purl: str) -> tuple[str, str, str]:
    """Compare ecosystems/names/versions, ignoring distro/arch PURL qualifiers."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        raise ValueError("Package inventory requires versioned PURLs")
    identity, _, query = purl[4:].split("#", 1)[0].partition("?")
    ecosystem, separator, rest = identity.partition("/")
    name, version_separator, version = rest.rpartition("@")
    if not separator or not version_separator or not name or not version:
        raise ValueError("Package inventory requires names and exact versions")
    name, version = unquote(name), unquote(version)
    if ecosystem in {"deb", "apk"}:
        name = name.rsplit("/", 1)[-1]
        epoch = dict(parse_qsl(query)).get("epoch", "0")
        if epoch != "0" and ":" not in version:
            if not epoch.isdigit():
                raise ValueError("Invalid package epoch")
            version = epoch + ":" + version
    elif ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "golang" and name == "stdlib":
        version = re.sub(r"^(?:go|v)?(?=\d+\.\d+\.\d+$)", "v", version)
    return ecosystem, name, version


def spdx_inventory(sbom: dict, *, frontend: bool = False, service: bool = False) -> set[tuple[str, str, str]]:
    expected = set()
    for package in sbom.get("packages", []):
        for reference in package.get("externalRefs", []):
            if reference.get("referenceType") == "purl":
                key = package_key(reference.get("referenceLocator"))
                if service:
                    if key[0] not in {"deb", "apk", "golang"}:
                        raise ValueError("Unsupported maintained runtime package ecosystem")
                    expected.add(key)
                    continue
                # Browser bundles have no installed npm package inventory. Do not claim it.
                if key[0] in ({"deb", "apk"} if frontend else {"deb", "apk", "pypi"}):
                    expected.add(key)
    if not expected or not service and not any(key[0] in {"deb", "apk"} for key in expected):
        raise ValueError("Build SBOM has no supported operating-system package inventory")
    return expected


def cyclone_inventory(report: dict, *, reference: str) -> tuple[set, str]:
    if report.get("bomFormat") != "CycloneDX" or not isinstance(report.get("components"), list):
        raise ValueError("Missing complete infrastructure CycloneDX inventory")
    component = report.get("metadata", {}).get("component", {})
    properties = {item.get("name"): item.get("value") for item in component.get("properties", [])}
    image_id = properties.get("aquasecurity:trivy:ImageID")
    if component.get("name") != reference or not isinstance(image_id, str) or \
            not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise ValueError("Infrastructure SBOM image subject mismatch")
    inventory = {package_key(item["purl"]) for item in report["components"] if item.get("purl")}
    # Prometheus/exporter images may have Go packages without an OS package database.
    if not inventory:
        raise ValueError("Infrastructure SBOM inventory is empty")
    return inventory, image_id


def immutable_subject(reference: str) -> tuple[str, str]:
    repository, separator, digest = reference.partition("@")
    if not separator or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Image subject requires an immutable SHA256 reference")
    head, colon, _ = repository.rpartition(":")
    if colon and "/" not in repository[len(head):]:
        repository = head
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if repository.startswith(prefix):
            repository = repository[len(prefix):]
            break
    if repository.startswith("library/"):
        repository = repository[8:]
    return repository, digest


def gate(report: dict, *, expected: set | None = None, image_id: str | None = None,
         artifact: str | None = None, platform: str | None = None, reference: str | None = None,
         ecosystems: set | None = None, complement: dict | None = None) -> list[str]:
    results = report.get("Results") if isinstance(report, dict) else None
    if not isinstance(results, list) or not results:
        raise ValueError("Image scanner produced no results")
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image" or \
            report.get("Trivy", {}).get("Version") != TRIVY_VERSION or "Error" in report:
        raise ValueError("Incomplete or unexpected Trivy report schema/version")
    metadata = report.get("Metadata", {})
    if image_id is not None and metadata.get("ImageID") != image_id or \
            artifact is not None and report.get("ArtifactName") != artifact:
        raise ValueError("Trivy report image subject mismatch")
    if reference is not None and immutable_subject(reference) not in {
        immutable_subject(value) for value in metadata.get("RepoDigests", [])
    }:
        raise ValueError("Trivy report has no matching immutable repository digest")
    if platform is not None:
        config = metadata.get("ImageConfig", {})
        if platform != f"{config.get('os')}/{config.get('architecture')}":
            raise ValueError("Trivy report native platform mismatch")
    covered, targets, package_instances = set(), set(), set()
    observed_main = set()
    findings = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str) or not result["Target"] or \
                result.get("Class") not in {"os-pkgs", "lang-pkgs"} or not isinstance(result.get("Type"), str):
            raise ValueError("Malformed Trivy scan target")
        target = (result["Target"], result["Class"], result["Type"])
        if target in targets:
            raise ValueError("Duplicate Trivy scan target")
        targets.add(target)
        packages = result.get("Packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError("Trivy report requires complete --list-all-pkgs inventory")
        for package in packages:
            if complement and isinstance(package, dict) and not package.get("Version"):
                claim = next((claim for claim in complement["components"] if claim["observed_unversioned"] and
                              claim["original_package"]["name"] == package.get("Name")), None)
                if claim is None or claim["spdx_id"] in observed_main:
                    raise ValueError("Unexpected or duplicate Trivy unversioned main module")
                script("component_scanner").validate_main_observation(package, result, claim)
                if package.get("Layer", {}).get("Digest") != claim["original_binary_file"]["comment"].split(" ")[1]:
                    raise ValueError("Trivy main module binary layer differs from SPDX observation")
                observed_main.add(claim["spdx_id"])
                continue
            if not isinstance(package, dict) or not package.get("Name") or not package.get("Version"):
                raise ValueError("Malformed Trivy package inventory")
            key = package_key(package.get("Identifier", {}).get("PURL"))
            package_name = re.sub(r"[-_.]+", "-", package["Name"]).lower() if key[0] == "pypi" else \
                package["Name"].lower() if key[0] in {"golang", "npm"} else package["Name"]
            version = package["Version"] + ("-" + package["Release"] if package.get("Release") else "")
            if package.get("Epoch") and ":" not in version:
                version = str(package["Epoch"]) + ":" + version
            if key[0] == "golang" and key[1] == "stdlib":
                version = re.sub(r"^(?:go|v)?(?=\d+\.\d+\.\d+$)", "v", version)
            if (package_name, version) != key[1:]:
                raise ValueError("Trivy package name/version differs from its inventory identifier")
            instance = (target, key, package.get("FilePath", ""))
            if instance in package_instances:
                raise ValueError("Duplicate Trivy package coverage")
            package_instances.add(instance)
            if ecosystems is None or key[0] in ecosystems:
                covered.add(key)
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Malformed Trivy vulnerability results")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("VulnerabilityID"), str) or \
                    not vulnerability.get("PkgName"):
                raise ValueError("Malformed Trivy vulnerability result")
            if vulnerability.get("FixedVersion") and vulnerability.get("Severity") not in {"LOW", "MEDIUM", "NONE"}:
                findings.append(f"{result['Target']}: {vulnerability['VulnerabilityID']} ({vulnerability['PkgName']})")
    if expected is not None and covered != expected:
        missing, extra = expected - covered, covered - expected
        raise ValueError(f"Trivy report does not cover exact package inventory: "
                         f"missing={sorted(missing)}, extra={sorted(extra)}")
    if complement and observed_main != {claim["spdx_id"] for claim in complement["components"]
                                       if claim["observed_unversioned"]}:
        raise ValueError("Trivy report lacks the original unversioned main module observation")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="OCI image archive built by this CI run")
    pins = script("verify-image-pins")
    parser.add_argument("--image", choices=(*pins.APP_IMAGES, *pins.SERVICES))
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--infrastructure", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--repository")
    args = parser.parse_args()
    if bool(args.input) == args.infrastructure or bool(args.image) != bool(args.input):
        parser.error("Choose --input with --image, or --infrastructure")
    args.output.mkdir(parents=True, exist_ok=True)
    early_targets = [args.image] if args.image else [name for name, role in pins.ROLES.items() if role == "runtime"]
    for name in early_targets:
        for suffix in (".metadata.json", ".evidence-manifest.json"):
            (args.output / (name + suffix)).unlink(missing_ok=True)
    images_path = ROOT / "requirements/images.json"
    images_bytes = images_path.read_bytes()
    images = pins.inventory(ROOT)
    service_manifest = pins.check_service_builds(ROOT, images)
    service_manifest_path = ROOT / "requirements/service-builds/manifest.json"
    service_manifest_bytes = service_manifest_path.read_bytes()
    source_hashes = source_fingerprints(ROOT, args.image in pins.SERVICES, args.image == "clickhouse")
    cache = ROOT / "tmp/production-delivery/trivy-cache"
    cache.mkdir(parents=True, exist_ok=True)
    references = {name: image["reference"] for name, image in images.items() if image["role"] == "runtime"} \
        if args.infrastructure else {}
    targets = references if args.infrastructure else {args.image: None}
    invocation = uuid.uuid4().hex
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_commit = args.source_commit or current
    if not re.fullmatch(r"[a-f0-9]{40}", source_commit) or source_commit != current:
        raise ValueError("Image evidence requires the exact source commit")
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY") or "local"
    failures = []
    pending_metadata = []
    report_inputs = {}

    def capture_report(path, expected_json=None):
        data = script("verify-scan-evidence").read(path)
        if expected_json is not None and script("verify-scan-evidence").decode(data) != expected_json:
            raise ValueError("Raw scanner report differs from validated observations")
        fingerprint = hashlib.sha256(data).hexdigest()
        report_inputs[path] = fingerprint
        return fingerprint
    for name in targets:
        # A rejected snapshot/preflight must not leave a prior successful scan sidecar.
        for suffix in (".json", ".metadata.json", ".inventory.json", ".evidence-manifest.json"):
            (args.output / (name + suffix)).unlink(missing_ok=True)
    context = script("oci_scan_layout").prepared_layout(
        args.input, platform=args.platform, scratch_parent=cache.parent,
        expected_source={"commit": source_commit, "repository": repository}, expected_component=args.image,
    ) if args.input else nullcontext(None)
    with context as layout, ExitStack() as component_contexts:
        for name, reference in targets.items():
            maintained = name in pins.SERVICES
            python_runtime = name in pins.APP_IMAGES and name != "frontend"
            mounts = ["--mount", f"type=bind,src={args.output.resolve()},dst=/output",
                      "--mount", f"type=bind,src={cache.resolve()},dst=/cache"]
            source = [reference]
            artifact = reference
            if args.input:
                evidence = layout.evidence
                layout.assert_unchanged()
                if len(evidence["image_manifests"]) != 1:
                    raise ValueError("Image gate requires one native runtime manifest")
                image_digest = evidence["image_manifests"][0]
                image_id = evidence["image_configs"][image_digest]
                # Run the subject-bound scan before inventory validation so a rejected
                # SBOM still leaves raw diagnostic findings, never an accepted sidecar.
                if python_runtime:
                    audit = script("audit-dependencies")
                    environment = audit.default_environment()
                    environment.update({"sys_platform": "linux", "os_name": "posix", "platform_system": "Linux",
                                        "platform_machine": args.platform.split("/")[1], "python_version": "3.12",
                                        "python_full_version": "3.12.15", "implementation_name": "cpython",
                                        "platform_python_implementation": "CPython"})
                    lock = ROOT / "requirements" / ("development.txt" if name == "test" else "runtime.txt")
                    closure = audit.expected_python(lock, environment)
                mounts.extend(["--mount", f"type=bind,src={layout.layout_path.resolve()},dst=/input/layout,readonly"])
                artifact = layout.container_input
                source = ["--input", artifact]
                subject = {"archive_sha256": evidence["archive_sha256"], "image_manifest": image_digest,
                           "image_config": image_id}
            command = ["docker", "run", "--rm", *mounts, images["trivy"]["reference"], "image", "--cache-dir", "/cache",
                       "--image-src", "remote",
                       "--platform", args.platform, "--scanners", "vuln", "--list-all-pkgs"]
            if reference:
                inventory_output = args.output / f"{name}.inventory.json"
                inventory_output.unlink(missing_ok=True)
                subprocess.run([*command, "--format", "cyclonedx", "--output",
                                f"/output/{inventory_output.name}", *source],
                               check=True)
                inventory = json.loads(inventory_output.read_text(encoding="utf-8"))
                expected, image_id = cyclone_inventory(inventory, reference=reference)
                subject = {"reference": reference, "image_config": image_id,
                           "inventory_sha256": hashlib.sha256(inventory_output.read_bytes()).hexdigest()}
            output = args.output / f"{name}.json"
            output.unlink(missing_ok=True)
            output.with_suffix(".metadata.json").unlink(missing_ok=True)
            scan_command = [*command, "--format", "json", "--output", f"/output/{output.name}", *source]
            subprocess.run(scan_command, check=True)
            report = script("verify-scan-evidence").decode(script("verify-scan-evidence").read(output))
            report_hash = capture_report(output, report)
            layout_metadata = layout.assert_unchanged() if layout else None
            complement = None
            complement_evidence = None
            principal_evidence = None
            if args.input:
                if maintained:
                    components = script("component_scanner")
                    source_binding = script("component_source")
                    documents = source_binding.subject_documents(layout, image_digest)
                    complement = components.partition(evidence["sboms"][image_digest], service=name,
                                                      package_key=package_key)
                    expected_source = {"commit": source_commit, "repository": repository}
                    components.bind_components(complement, documents=documents, service=name, platform=args.platform,
                                               root=ROOT, service_manifest=service_manifest,
                                               expected_source=expected_source, binder=source_binding.bind)
                    if name == "clickhouse":
                        principal = script("component_principal")
                        expected_ci = principal.ci_identity(os.environ)
                        principal_path = principal.canonical_receipt_path(args.output / principal.RECEIPT_NAME,
                                                                         expected_parent=args.output)
                        principal_bytes = script("verify-scan-evidence").read(principal_path)
                        if len(principal_bytes) > 16 * 1024:
                            raise ValueError("Principal observation exceeds receipt budget")
                        observation = script("verify-scan-evidence").decode(principal_bytes)
                        principal.validate_receipt(observation, subject={**subject,
                            "image_manifest": "sha256:" + image_digest.removeprefix("sha256:"),
                            "platform": args.platform},
                            config=documents["config"], expected_source=expected_source, expected_ci=expected_ci,
                            collector_sha256=source_hashes["scripts/observe-clickhouse-version.py"],
                            process_module_sha256=source_hashes["scripts/grype_runtime.py"])
                        proof = source_binding.bind_clickhouse(documents["provenance"]["statement"]["predicate"],
                            platform=args.platform, selected_manifest=documents["manifest"], root=ROOT,
                            service_manifest=service_manifest, expected_source=expected_source, expected_ci=expected_ci)
                        principal_hash = hashlib.sha256(principal_bytes).hexdigest()
                        report_inputs[principal_path] = principal_hash
                        components.declare_clickhouse(complement, receipt=observation, receipt_sha256=principal_hash,
                                                     source_proof=proof)
                        principal_evidence = {"report_path": principal_path.name, "report_sha256": principal_hash,
                                              "receipt": observation}
                    expected = complement["native"]
                else:
                    expected = spdx_inventory(evidence["sboms"][image_digest], frontend=name == "frontend")
                if python_runtime and not \
                        {("pypi", package, version) for package, version in closure.items()} <= expected:
                    raise ValueError("Image SBOM does not include the complete native runtime hash-lock closure")
            ecosystems = None if reference or maintained else \
                {"deb", "apk"} if name == "frontend" else {"deb", "apk", "pypi"}
            target_failures = gate(report, expected=expected, image_id=image_id, artifact=artifact,
                                   platform=args.platform, reference=reference, ecosystems=ecosystems,
                                   complement=complement)
            if maintained:
                runtime = component_contexts.enter_context(script("grype_runtime").prepared_grype(
                    scratch_parent=cache.parent, manifest_path=ROOT / "requirements/component-scanner.json",
                    config_path=ROOT / "requirements/grype.yaml", platform=args.platform))
                query_directory = args.output / f"{name}.complement-{invocation}"
                query_directory.mkdir(mode=0o700, exist_ok=False)
                sentinels = []
                providers = None
                for index, (query, identifiers) in enumerate((
                    ("cpe:2.3:a:redislabs:redis:5.0.0:*:*:*:*:*:*:*", {"CVE-2021-32675"}),
                    ("pkg:golang/golang.org/x/crypto@0.1.0", {"CVE-2023-48795", "GHSA-45x7-px36-x8w8",
                                                            "GO-2023-2402"}),
                )):
                    path = query_directory / f"sentinel-{index}.json"
                    sentinel = runtime.run_query(query, path)
                    components.validate_report(sentinel, query=query, configuration=runtime.configuration,
                                               database_status=runtime.database_status)
                    current_providers = sentinel["descriptor"]["db"]["providers"]
                    if providers is not None and current_providers != providers:
                        raise ValueError("Complement database provider metadata changed")
                    providers = current_providers
                    if not identifiers.intersection({match["vulnerability"]["id"] for match in sentinel["matches"]}):
                        raise ValueError("Complement scanner known-vulnerable sentinel did not match")
                    sentinels.append({"query": query, "report_path": path.relative_to(args.output).as_posix(),
                                      "report_sha256": capture_report(path, sentinel),
                                      "required_advisories": sorted(identifiers)})
                reports = []
                for claim in complement["components"]:
                    for query in claim["queries"]:
                        path = query_directory / f"query-{len(reports):02d}.json"
                        raw_report = runtime.run_query(query, path)
                        if raw_report.get("descriptor", {}).get("db", {}).get("providers") != providers:
                            raise ValueError("Complement database provider metadata changed")
                        target_failures.extend(components.validate_report(
                            raw_report, query=query, configuration=runtime.configuration,
                            database_status=runtime.database_status))
                        reports.append((claim, query, str(path.relative_to(args.output)).replace("\\", "/"),
                                        capture_report(path, raw_report)))
                runtime_receipt = runtime.assert_unchanged()
                if components.digest(evidence["sboms"][image_digest]) != complement["spdx_sha256"]:
                    raise ValueError("Original SPDX observations changed during complement scan")
                complement_evidence = {"schema": 1, "spdx_sha256": complement["spdx_sha256"],
                                       "software_package_count": complement["software_package_count"],
                                       "components": complement["components"], "runtime": runtime_receipt,
                                       "principal_observation": principal_evidence,
                                       "sentinels": sentinels, "receipts": [components.query_receipt(
                    claim=claim, query=query, report_path=path, report_sha256=report_hash,
                    subject=subject, platform=args.platform, expected_source=expected_source,
                    sbom_blob=documents["sbom"]["blob"], provenance_blob=documents["provenance"]["blob"],
                    runtime_receipt=runtime_receipt) for claim, query, path, report_hash in reports]}
                layout_metadata = layout.assert_unchanged()
            failures.extend(target_failures)
            if args.input:
                with args.input.open("rb") as source_file:
                    if hashlib.file_digest(source_file, "sha256").hexdigest() != subject["archive_sha256"]:
                        raise ValueError("OCI archive changed during image scan")
                if python_runtime and audit.expected_python(lock, environment) != closure:
                    raise ValueError("Runtime hash lock changed during image scan")
            if images_path.read_bytes() != images_bytes:
                raise ValueError("Image pin manifest changed during image scan")
            if service_manifest_path.read_bytes() != service_manifest_bytes:
                raise ValueError("Maintained service manifest changed during image scan")
            pins.check_service_builds(ROOT, images)
            metadata = {"invocation": invocation, "platform": args.platform, "subject": subject,
                        "verdict": "failed" if target_failures else "passed", "findings": target_failures,
                        "command": scan_command,
                        "source_commit": source_commit, "repository": repository,
                        "source_dirty": bool(subprocess.check_output(
                            ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                        "scanner_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        "scanner": images["trivy"]["reference"], "expected_packages": sorted(expected),
                        "images_manifest_sha256": hashlib.sha256(images_bytes).hexdigest(),
                        "report_sha256": report_hash}
            metadata["source_fingerprints"] = source_hashes
            if layout:
                metadata["oci_layout"] = layout_metadata
            if maintained:
                metadata["role"] = "derived-runtime"
                metadata["service_recipe"] = service_manifest["services"][name]
                metadata["service_manifest_sha256"] = hashlib.sha256(service_manifest_bytes).hexdigest()
                metadata["complement"] = complement_evidence
            if args.input and python_runtime:
                metadata["lock_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
                metadata["expected_dependencies"] = closure
            pending_metadata.append((output.with_suffix(".metadata.json"), metadata))
    # Successful disposal is part of the proof; a refused cleanup cannot publish success metadata.
    if source_fingerprints(ROOT, args.image in pins.SERVICES, args.image == "clickhouse") != source_hashes:
        raise ValueError("Scanner source inputs changed during image scan")
    for path, fingerprint in report_inputs.items():
        if hashlib.sha256(script("verify-scan-evidence").read(path)).hexdigest() != fingerprint:
            raise ValueError("Raw scanner evidence changed during image scan")
    for path, metadata in pending_metadata:
        path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    if failures:
        raise SystemExit("Fixable severe image advisories:\n" + "\n".join(failures))
    print("PASS: complete subject-bound image reports; no fixable high/critical findings")


if __name__ == "__main__":
    main()
