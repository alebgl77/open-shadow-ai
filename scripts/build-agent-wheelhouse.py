"""Build a target-platform agent wheelhouse and prove hash-checked offline installation."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New, empty wheelhouse directory")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("The wheelhouse must not already exist; stale extra wheels change offline resolution")
    args.output.mkdir(parents=True)
    manifest = json.loads((ROOT / "requirements/manifest.json").read_text(encoding="utf-8"))
    for name in ("agent.txt", "build.txt"):
        if digest(ROOT / "requirements" / name) != manifest["locks"][name]:
            raise ValueError(f"Dependency lock drift: {name}")
        shutil.copyfile(ROOT / "requirements" / name, args.output / name)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("UV_", "PIP_"))}
    base = [sys.executable, "-m", "pip", "--cache-dir", str(ROOT / "tmp/production-delivery/pip-cache")]
    subprocess.run([*base, "download", "--index-url", "https://pypi.org/simple", "--require-hashes",
                    "--only-binary=:all:", "-r", str(args.output / "agent.txt"), "-r", str(args.output / "build.txt"),
                    "--dest", str(args.output)], env=environment, check=True)
    subprocess.run([*base, "wheel", "--no-index", "--no-deps", "--no-build-isolation", str(ROOT / "agent"),
                    "--wheel-dir", str(args.output)], env=environment, check=True)
    wheel, = args.output.glob("shadai_agent-*.whl")
    version = wheel.name.split("-")[1]
    (args.output / "local-agent.txt").write_text(
        f"shadai-agent=={version} --hash=sha256:{digest(wheel)}\n", encoding="utf-8")
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="offline-agent-", dir=ROOT / "tmp") as temporary:
        directory = Path(temporary)
        venv.EnvBuilder(with_pip=True).create(directory)
        python = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-index", "--find-links", str(args.output.resolve()),
                        "--require-hashes", "-r", str(args.output / "agent.txt"),
                        "-r", str(args.output / "local-agent.txt")], env=environment, check=True)
        subprocess.run([str(python), "-m", "pip", "check"], env=environment, check=True)
        subprocess.run([str(python), "-I", "-c", (
            "from shadai_agent import main; from shadai_agent.config import AgentConfig; import docker; "
            "header={'hostname':'synthetic-offline-proof','agent_version':'0.1.0',"
            "'timestamp':'2026-01-01T00:00:00+00:00'}; "
            "batches=main.split_batches(header,{'processes':[{'name':'synthetic','username':'test'}]}); "
            "assert len(batches)==1 and batches[0]['processes'][0]['name']=='synthetic'; "
            "assert AgentConfig().poll_interval_seconds>0; print('PASS: isolated standalone agent import and batching')"
        )], env=environment, cwd=directory, check=True)
    (args.output / "SHA256SUMS.json").write_text(json.dumps(
        {path.name: digest(path) for path in sorted(args.output.iterdir()) if path.is_file()},
        indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS: clean target-platform wheelhouse; hash-checked offline agent install")


if __name__ == "__main__":
    main()
