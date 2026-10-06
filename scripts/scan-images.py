"""Gate complete subject-bound Trivy inventories and retain every advisory."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, unquote

ROOT = Path(__file__).resolve().parents[1]
TRIVY_VERSION = "0.75.0"


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
    return ecosystem, name, version


def spdx_inventory(sbom: dict, *, frontend: bool = False) -> set[tuple[str, str, str]]:
    expected = set()
    for package in sbom.get("packages", []):
        for reference in package.get("externalRefs", []):
            if reference.get("referenceType") == "purl":
                key = package_key(reference.get("referenceLocator"))
                # Browser bundles have no installed npm package inventory. Do not claim it.
                if key[0] in ({"deb", "apk"} if frontend else {"deb", "apk", "pypi"}):
                    expected.add(key)
    if not expected or not any(key[0] in {"deb", "apk"} for key in expected):
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
         ecosystems: set | None = None) -> list[str]:
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
            if not isinstance(package, dict) or not package.get("Name") or not package.get("Version"):
                raise ValueError("Malformed Trivy package inventory")
            key = package_key(package.get("Identifier", {}).get("PURL"))
            package_name = re.sub(r"[-_.]+", "-", package["Name"]).lower() if key[0] == "pypi" else \
                package["Name"].lower() if key[0] in {"golang", "npm"} else package["Name"]
            version = package["Version"] + ("-" + package["Release"] if package.get("Release") else "")
            if package.get("Epoch") and ":" not in version:
                version = str(package["Epoch"]) + ":" + version
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
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="OCI image archive built by this CI run")
    parser.add_argument("--image", choices=("api", "worker", "collector", "test", "frontend"))
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--infrastructure", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--repository")
    args = parser.parse_args()
    if bool(args.input) == args.infrastructure or bool(args.image) != bool(args.input):
        parser.error("Choose --input with --image, or --infrastructure")
    images_path = ROOT / "requirements/images.json"
    images_bytes = images_path.read_bytes()
    images = json.loads(images_bytes)
    args.output.mkdir(parents=True, exist_ok=True)
    cache = ROOT / "tmp/production-delivery/trivy-cache"
    cache.mkdir(parents=True, exist_ok=True)
    references = {name: images[name]["reference"]
                  for name in ("postgres", "clickhouse", "redis", "prometheus", "node-exporter")} \
        if args.infrastructure else {}
    targets = references if args.infrastructure else {args.image: None}
    invocation = uuid.uuid4().hex
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_commit = args.source_commit or current
    if not re.fullmatch(r"[a-f0-9]{40}", source_commit) or source_commit != current:
        raise ValueError("Image evidence requires the exact source commit")
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY") or "local"
    failures = []
    for name, reference in targets.items():
        mounts = ["--mount", f"type=bind,src={args.output.resolve()},dst=/output",
                  "--mount", f"type=bind,src={cache.resolve()},dst=/cache"]
        source = [reference]
        artifact = reference
        if args.input:
            evidence = script("verify-oci-evidence").verify(args.input, platform=args.platform, include_sbom=True)
            if len(evidence["image_manifests"]) != 1:
                raise ValueError("Image gate requires one native runtime manifest")
            image_digest = evidence["image_manifests"][0]
            image_id = evidence["image_configs"][image_digest]
            expected = spdx_inventory(evidence["sboms"][image_digest], frontend=name == "frontend")
            if name != "frontend":
                audit = script("audit-dependencies")
                environment = audit.default_environment()
                environment.update({"sys_platform": "linux", "os_name": "posix", "platform_system": "Linux",
                                    "platform_machine": args.platform.split("/")[1], "python_version": "3.12",
                                    "python_full_version": "3.12.15", "implementation_name": "cpython",
                                    "platform_python_implementation": "CPython"})
                lock = ROOT / "requirements" / ("development.txt" if name == "test" else "runtime.txt")
                closure = audit.expected_python(lock, environment)
                if not {("pypi", package, version) for package, version in closure.items()} <= expected:
                    raise ValueError("Image SBOM does not include the complete native runtime hash-lock closure")
            mounts.extend(["--mount", f"type=bind,src={args.input.resolve().parent},dst=/input,readonly"])
            artifact = "/input/" + args.input.name
            source = ["--input", artifact]
            subject = {"archive_sha256": evidence["archive_sha256"], "image_manifest": image_digest,
                       "image_config": image_id}
        command = ["docker", "run", "--rm", *mounts, images["trivy"]["reference"], "image", "--cache-dir", "/cache",
                   "--image-src", "remote",
                   "--platform", args.platform, "--scanners", "vuln", "--list-all-pkgs"]
        if reference:
            inventory_output = args.output / f"{name}.inventory.json"
            inventory_output.unlink(missing_ok=True)
            subprocess.run([*command, "--format", "cyclonedx", "--output", f"/output/{inventory_output.name}", *source],
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
        report = json.loads(output.read_text(encoding="utf-8"))
        ecosystems = None if reference else {"deb", "apk"} if name == "frontend" else {"deb", "apk", "pypi"}
        failures.extend(gate(report, expected=expected, image_id=image_id, artifact=artifact, platform=args.platform,
                             reference=reference, ecosystems=ecosystems))
        if args.input:
            with args.input.open("rb") as source_file:
                if hashlib.file_digest(source_file, "sha256").hexdigest() != subject["archive_sha256"]:
                    raise ValueError("OCI archive changed during image scan")
            if name != "frontend" and audit.expected_python(lock, environment) != closure:
                raise ValueError("Runtime hash lock changed during image scan")
        if images_path.read_bytes() != images_bytes:
            raise ValueError("Image pin manifest changed during image scan")
        metadata = {"invocation": invocation, "platform": args.platform, "subject": subject, "command": scan_command,
                    "source_commit": source_commit, "repository": repository,
                    "source_dirty": bool(subprocess.check_output(
                        ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                    "scanner_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "scanner": images["trivy"]["reference"], "expected_packages": sorted(expected),
                    "images_manifest_sha256": hashlib.sha256(images_bytes).hexdigest(),
                    "report_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
        if args.input and name != "frontend":
            metadata["lock_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
            metadata["expected_dependencies"] = closure
        output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    if failures:
        raise SystemExit("Fixable severe image advisories:\n" + "\n".join(failures))
    print("PASS: complete subject-bound image reports; no fixable high/critical findings")


if __name__ == "__main__":
    main()
