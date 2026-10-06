"""Report dependency advisories and gate fixable high/critical runtime findings."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import uuid
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]


def expected_python(lock: Path, environment: dict | None = None) -> dict[str, str]:
    """Evaluate the universal hash lock on the scanner's actual native interpreter."""
    manifest = json.loads((lock.parent / "manifest.json").read_text(encoding="utf-8"))
    if hashlib.sha256(lock.read_bytes()).hexdigest() != manifest["locks"].get(lock.name):
        raise ValueError("Lock content drift before dependency audit")
    records = lock.read_text(encoding="utf-8").replace("\\\n", " ").splitlines()
    expected = {}
    for record in records:
        if not record.strip() or record.lstrip().startswith("#"):
            continue
        head, *hashes = record.split(" --hash=sha256:")
        if not hashes or any(not re.fullmatch(r"[a-f0-9]{64}", value.strip()) for value in hashes):
            raise ValueError("Dependency audit requires a complete hash lock")
        requirement = Requirement(head.strip())
        versions = list(requirement.specifier)
        if requirement.url or len(versions) != 1 or versions[0].operator != "==" or "*" in versions[0].version:
            raise ValueError("Dependency audit requires exact versions")
        if requirement.marker and not requirement.marker.evaluate(environment or default_environment()):
            continue
        name = canonicalize_name(requirement.name)
        if name in expected:
            raise ValueError("Duplicate active lock dependency")
        expected[name] = versions[0].version
    if not expected:
        raise ValueError("Empty native dependency closure")
    return expected


def validate_python(report: dict, expected: dict[str, str] | None = None) -> None:
    dependencies = report.get("dependencies") if isinstance(report, dict) else None
    if not isinstance(dependencies, list) or not dependencies or "error" in report:
        raise ValueError("Dependency scanner produced no complete dependencies")
    covered = {}
    for dependency in dependencies:
        if not isinstance(dependency, dict) or "skip_reason" in dependency:
            raise ValueError("Incomplete advisory coverage")
        name, version, vulnerabilities = (dependency.get(key) for key in ("name", "version", "vulns"))
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version or \
                not isinstance(vulnerabilities, list):
            raise ValueError("Malformed dependency advisory report")
        name = canonicalize_name(name)
        if name in covered:
            raise ValueError("Duplicate dependency advisory coverage")
        covered[name] = version
        ids = set()
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict) or not isinstance(vulnerability.get("id"), str) or \
                    not vulnerability["id"] or not isinstance(vulnerability.get("fix_versions"), list) or \
                    any(not isinstance(value, str) or not value for value in vulnerability["fix_versions"]):
                raise ValueError("Malformed vulnerability advisory")
            if vulnerability["id"] in ids:
                raise ValueError("Duplicate vulnerability advisory")
            ids.add(vulnerability["id"])
    if expected is not None and covered != expected:
        raise ValueError("Dependency report does not cover the exact native hash-lock closure")


def github_severity(vulnerability: dict) -> str:
    ids = [vulnerability["id"], *vulnerability.get("aliases", [])]
    advisory = next((value for value in ids if re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", value)), None)
    if advisory is None:
        return "unknown"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request("https://api.github.com/advisories/" + advisory, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)["severity"]


def gate_python(report: dict, severity_lookup=github_severity, *, expected: dict[str, str] | None = None) -> list[str]:
    validate_python(report, expected)
    findings = []
    for dependency in report["dependencies"]:
        for vulnerability in dependency.get("vulns", []):
            if not vulnerability.get("fix_versions"):
                continue
            severity = severity_lookup(vulnerability) if severity_lookup is not None else None
            severity = severity.lower() if isinstance(severity, str) else "unknown"
            if severity not in {"low", "moderate", "medium", "high", "critical"}:
                severity = "unknown"
            vulnerability["severity"] = severity
            # An advisory without severity data requires review; it cannot silently pass.
            if severity in {"high", "critical", "unknown"}:
                findings.append(f"{dependency['name']}=={dependency['version']}: {vulnerability['id']} ({severity})")
    return findings


def gate_npm(report: dict) -> list[str]:
    if not isinstance(report, dict) or report.get("auditReportVersion") != 2 or "error" in report or \
            not isinstance(report.get("vulnerabilities"), dict) or \
            not isinstance(report.get("metadata", {}).get("dependencies", {}).get("total"), int) or \
            report["metadata"]["dependencies"]["total"] <= 0:
        raise ValueError("npm advisory service returned no complete report")
    return [f"{name}: {value['severity']}" for name, value in report["vulnerabilities"].items()
            if value.get("fixAvailable") and value.get("severity") not in {"info", "low", "moderate"}]


def write_metadata(output: Path, *, subject: Path, invocation: str, command: list[str], scanner: str,
                   environment: dict, source_commit: str, repository: str, expected: dict | None = None) -> None:
    metadata = {"invocation": invocation, "scanner": scanner, "command": command,
                "source_commit": source_commit, "repository": repository,
                "source_dirty": bool(subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                "scanner_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "input": str(subject.relative_to(ROOT)),
                "input_sha256": hashlib.sha256(subject.read_bytes()).hexdigest(),
                "report_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "environment": environment}
    if expected is not None:
        metadata["expected_dependencies"] = expected
        metadata["manifest_sha256"] = hashlib.sha256((subject.parent / "manifest.json").read_bytes()).hexdigest()
    output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def source_identity(commit: str | None, repository: str | None) -> tuple[str, str]:
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    commit = commit or current
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or commit != current:
        raise ValueError("Advisory evidence requires the exact source commit")
    return commit, repository or os.environ.get("GITHUB_REPOSITORY") or "local"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--npm", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--repository")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    failures = []
    invocation = uuid.uuid4().hex
    environment = default_environment()
    source_commit, repository = source_identity(args.source_commit, args.repository)
    if args.npm:
        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is not installed")
        for name, extra in (("frontend-all", []), ("frontend-runtime", ["--omit=dev"])):
            output = args.output / f"{name}.json"
            output.unlink(missing_ok=True)
            output.with_suffix(".metadata.json").unlink(missing_ok=True)
            result = subprocess.run([npm, "audit", "--json", *extra], cwd=ROOT / "frontend",
                                    capture_output=True, text=True, check=False)
            if result.returncode not in {0, 1}:
                raise RuntimeError(f"npm audit failed ({result.returncode})")
            report = json.loads(result.stdout)
            gate_npm(report)
            lock = ROOT / "frontend/package-lock.json"
            packages = json.loads(lock.read_text(encoding="utf-8"))["packages"]
            if report["metadata"]["dependencies"]["total"] != len(packages) - 1:
                raise ValueError("npm advisory report dependency count differs from package lock")
            output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            write_metadata(output, subject=lock, invocation=invocation, command=[npm, "audit", "--json", *extra],
                           scanner="npm", environment=environment, source_commit=source_commit, repository=repository)
            if name == "frontend-runtime":
                failures.extend(gate_npm(report))
    else:
        for name in ("runtime", "agent", "development", "build", "tools"):
            output = args.output / f"python-{name}.json"
            lock = ROOT / "requirements" / f"{name}.txt"
            expected = expected_python(lock, environment)
            input_digest = hashlib.sha256(lock.read_bytes()).hexdigest()
            output.unlink(missing_ok=True)
            output.with_suffix(".metadata.json").unlink(missing_ok=True)
            command = [sys.executable, "-m", "pip_audit", "--strict", "--disable-pip", "--require-hashes",
                       "--cache-dir", str(ROOT / "tmp/production-delivery/audit-cache"),
                       "--format", "json", "--output", str(output), "-r", str(ROOT / "requirements" / f"{name}.txt")]
            result = subprocess.run(command, check=False)
            if result.returncode not in {0, 1} or not output.exists():
                raise RuntimeError(f"Dependency scan failed for {name} ({result.returncode})")
            report = json.loads(output.read_text(encoding="utf-8"))
            if hashlib.sha256(lock.read_bytes()).hexdigest() != input_digest or \
                    expected_python(lock, environment) != expected:
                raise ValueError("Dependency input changed during advisory scan")
            validate_python(report, expected)
            if name in {"runtime", "agent"}:
                failures.extend(gate_python(report, expected=expected))
                output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            write_metadata(output, subject=lock, invocation=invocation, command=command,
                           scanner="pip-audit " + importlib.metadata.version("pip-audit"),
                           environment=environment, source_commit=source_commit, repository=repository,
                           expected=expected)
    if failures:
        raise SystemExit("Fixable severe runtime advisories:\n" + "\n".join(failures))
    print("PASS: dependency advisory reports; no fixable high/critical runtime findings")


if __name__ == "__main__":
    main()
