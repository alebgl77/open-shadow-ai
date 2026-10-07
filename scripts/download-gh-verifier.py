"""Download the reviewed official GitHub CLI verifier; extract only its checked binary."""

import argparse
import hashlib
import json
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def install(destination: Path, opener=urllib.request.urlopen) -> None:
    if destination.exists():
        raise ValueError("GitHub verifier destination must be new")
    metadata = json.loads((ROOT / "requirements/github-cli.json").read_text(encoding="utf-8"))
    if not metadata["url"].startswith("https://github.com/cli/cli/releases/download/v" + metadata["version"] + "/"):
        raise ValueError("GitHub verifier must come from the pinned official release")
    # No archive paths, symlinks or scripts are extracted or executed from the release.
    with tempfile.TemporaryFile() as downloaded:
        checksum = hashlib.sha256()
        with opener(metadata["url"], timeout=60) as source:
            while chunk := source.read(1024 * 1024):
                checksum.update(chunk)
                downloaded.write(chunk)
        if checksum.hexdigest() != metadata["sha256"]:
            raise ValueError("GitHub CLI release SHA256 mismatch")
        downloaded.seek(0)
        with tarfile.open(fileobj=downloaded, mode="r:gz") as archive:
            member = archive.getmember(metadata["member"])
            if not member.isfile():
                raise ValueError("GitHub verifier is not a regular binary file")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("GitHub verifier binary is missing")
            (destination / "bin").mkdir(parents=True)
            with source, (destination / "bin/gh").open("xb") as output:
                shutil.copyfileobj(source, output)
            (destination / "bin/gh").chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    install(args.output)
    print("PASS: pinned official GitHub verifier archive SHA256 and regular binary")


if __name__ == "__main__":
    main()
