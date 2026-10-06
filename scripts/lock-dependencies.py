"""Generate and verify pip-compatible, universal third-party dependency locks."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.11.16"
LOCKS = {
    "runtime.txt": (["pyproject.toml", "agent/pyproject.toml"], "3.12", []),
    "development.txt": (["pyproject.toml", "agent/pyproject.toml"], "3.12", ["--extra", "dev"]),
    "agent.txt": (["agent/pyproject.toml"], "3.10", ["--extra", "docker"]),
    "build.txt": (["requirements/build.in"], "3.10", []),
    "tools.txt": (["requirements/tools.in"], "3.12", []),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_fingerprint(root: Path = ROOT) -> str:
    """Only metadata affecting dependency resolution belongs to this fingerprint."""
    sources = {}
    for name in ("pyproject.toml", "agent/pyproject.toml"):
        data = tomllib.loads((root / name).read_text(encoding="utf-8"))
        project = data["project"]
        sources[name] = {
            "requires-python": project["requires-python"],
            "dependencies": project["dependencies"],
            "optional-dependencies": project.get("optional-dependencies", {}),
            "build-system": data["build-system"],
        }
    for name in ("requirements/build.in", "requirements/tools.in"):
        sources[name] = (root / name).read_text(encoding="utf-8")
    sources["resolver"] = {"version": UV_VERSION, "locks": LOCKS}
    return sha256(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode())


def validate_lock(path: Path) -> None:
    """Reject unpinned/direct project installs, incomplete hashes and alternate indexes."""
    # uv emits adjacent records without a blank separator, so group continuation lines.
    records = []
    record = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        record += line.strip().removesuffix("\\").strip() + " "
        if not line.endswith("\\"):
            records.append(record.strip())
            record = ""
    if record or not records:
        raise ValueError(f"Incomplete/empty lock: {path}")
    for requirement in records:
        head, *hashes = requirement.split(" --hash=sha256:")
        package = head.split("==", 1)[0].split("[", 1)[0].lower().replace("_", "-")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.!+-]+(?: ; .+)?", head) or \
                package in {"shadai", "shadai-agent"}:
            raise ValueError(f"Unpinned/local project requirement in {path}: {head}")
        if not hashes or any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                             for value in hashes):
            raise ValueError(f"Missing/invalid SHA256 in {path}: {head}")


def check(root: Path = ROOT) -> None:
    manifest = json.loads((root / "requirements/manifest.json").read_text(encoding="utf-8"))
    if manifest["source_sha256"] != source_fingerprint(root):
        raise ValueError("Dependency metadata drift: regenerate locks with scripts/lock-dependencies.py")
    if manifest["uv_version"] != UV_VERSION:
        raise ValueError("Resolver version drift")
    for name in LOCKS:
        path = root / "requirements" / name
        validate_lock(path)
        if sha256(path.read_bytes()) != manifest["locks"][name]:
            raise ValueError(f"Lock content drift: {name}")


def generate(uv: str, *, verify: bool, upgrade: list[str], constraints: str | None) -> None:
    version = subprocess.check_output([uv, "--version"], text=True).split()[1]
    if version != UV_VERSION:
        raise ValueError(f"Use uv {UV_VERSION}; got {version}")
    # Resolve into an isolated directory; a failed resolution never overwrites working locks.
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="locks-", dir=ROOT / "tmp") as temporary:
        directory = Path(temporary)
        for name, (sources, python, extra) in LOCKS.items():
            output = directory / name
            existing = ROOT / "requirements" / name
            if existing.exists():
                shutil.copyfile(existing, output)
            command = [uv, "pip", "compile", *sources, *extra, "--universal", "--python-version", python,
                       "--generate-hashes", "--no-header", "--no-annotate", "--no-sources", "--no-build", "--no-config",
                       "--default-index", "https://pypi.org/simple", "--python", sys.executable,
                       "--no-python-downloads", "--output-file", str(output),
                       "--cache-dir", str(ROOT / "tmp/production-delivery/uv-cache")]
            for package in upgrade:
                command.extend(["--upgrade-package", package])
            if constraints and name in {"runtime.txt", "development.txt"}:
                command.extend(["--constraints", constraints])
            # Ignore ambient config files and private indexes, overrides, sources or credentials.
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("UV_", "PIP_"))}
            subprocess.run(command, cwd=ROOT, env=environment, check=True, stdout=subprocess.DEVNULL)
            output.write_bytes(output.read_bytes().replace(b"\r\n", b"\n"))
            validate_lock(output)
            if verify and output.read_bytes() != existing.read_bytes():
                raise ValueError(f"Non-reproducible resolution: {name}")
        if not verify:
            manifest = {
                "uv_version": UV_VERSION,
                "source_sha256": source_fingerprint(),
                "locks": {name: sha256((directory / name).read_bytes()) for name in LOCKS},
            }
            for name in LOCKS:
                shutil.copyfile(directory / name, ROOT / "requirements" / name)
            (ROOT / "requirements/manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    check()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Offline source/hash drift check")
    parser.add_argument("--verify", action="store_true", help="Regenerate without changing files and compare bytes")
    parser.add_argument("--uv", default="uv", help=f"Path to uv {UV_VERSION}")
    parser.add_argument("--upgrade-package", action="append", default=[])
    parser.add_argument("--constraints", help="Optional validated initial runtime/dev versions; not an override")
    args = parser.parse_args()
    if args.check:
        check()
    else:
        generate(args.uv, verify=args.verify, upgrade=args.upgrade_package, constraints=args.constraints)
    print("PASS: universal dependency locks and source fingerprint")


if __name__ == "__main__":
    main()
