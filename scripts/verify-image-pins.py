"""Check immutable image references and optionally verify official registry manifests."""

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^[a-z0-9./-]+:v?\d+\.\d+[a-zA-Z0-9._-]*@sha256:[a-f0-9]{64}$")
ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)


def inventory(root: Path = ROOT) -> dict:
    return json.loads((root / "requirements/images.json").read_text(encoding="utf-8"))


def check_references(root: Path = ROOT) -> None:
    images = inventory(root)
    references = {value["reference"] for value in images.values()}
    if any(not PIN.fullmatch(reference) for reference in references):
        raise ValueError("Every image must have an exact version and SHA256 index digest")
    for path in [*sorted((root / "docker").glob("Dockerfile.*")), root / "frontend/Dockerfile"]:
        stages = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM "):
                fields = line.split()
                reference = fields[1]
                if reference not in stages and reference not in references:
                    raise ValueError(f"Unrecorded/mutable base image in {path}: {reference}")
                if len(fields) == 4 and fields[2].lower() == "as":
                    stages.add(fields[3])
    for path in [*sorted(root.glob("docker-compose*.yml")), root / "deploy/qualification/compose.yaml"]:
        for reference in re.findall(r"^\s+image:\s+(\S+)", path.read_text(encoding="utf-8"), re.MULTILINE):
            if reference not in references:
                raise ValueError(f"Unrecorded/mutable service image in {path}: {reference}")


def check_registry(images: dict) -> None:
    for name, image in images.items():
        repository, version_digest = image["reference"].split(":", 1)
        version, digest = version_digest.split("@", 1)
        if repository.startswith("quay.io/"):
            repository = repository.removeprefix("quay.io/")
            registry = "https://quay.io"
            headers = {"Accept": ACCEPT}
        else:
            registry = "https://registry-1.docker.io"
            if "/" not in repository:
                repository = "library/" + repository
            query = urllib.parse.urlencode({"service": "registry.docker.io", "scope": f"repository:{repository}:pull"})
            with urllib.request.urlopen("https://auth.docker.io/token?" + query, timeout=30) as response:
                token = json.load(response)["token"]
            headers = {"Authorization": "Bearer " + token, "Accept": ACCEPT}
        # Both exact version and immutable digest must resolve to the recorded index bytes.
        for selector in (version, digest):
            url = f"{registry}/v2/{repository}/manifests/{selector}"
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
                body = response.read()
                advertised = response.headers["Docker-Content-Digest"]
            actual = "sha256:" + hashlib.sha256(body).hexdigest()
            if advertised != digest or actual != digest:
                raise ValueError(f"Registry index mismatch for {name} ({selector})")
            manifest = json.loads(body)
            platforms = {
                f"{entry['platform']['os']}/{entry['platform']['architecture']}"
                for entry in manifest.get("manifests", [])
            }
            if not {"linux/amd64", "linux/arm64"} <= platforms:
                raise ValueError(f"Missing supported platform in {name}: {sorted(platforms)}")
        print(f"PASS: {name}, exact tag/index SHA256, linux/amd64 + linux/arm64")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", action="store_true", help="Read official public Docker registry metadata")
    parser.add_argument("--reference", choices=tuple(inventory()), help="Print one recorded reference for CI")
    args = parser.parse_args()
    if args.reference:
        print(inventory()[args.reference]["reference"])
        return
    check_references()
    if args.registry:
        check_registry(inventory())
    print("PASS: immutable Docker image references")


if __name__ == "__main__":
    main()
