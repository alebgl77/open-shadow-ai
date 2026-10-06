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
SERVICES = ("postgres", "clickhouse", "redis", "node-exporter")
APP_IMAGES = ("api", "worker", "collector", "test", "frontend")
BUILD_IMAGES = ("python", "node", "nginx", "trivy", "buildkit", "sbom-generator", "golang",
                "postgres-base", "clickhouse-base", "redis-base", "node-exporter-base")
ROLES = {**dict.fromkeys(BUILD_IMAGES, "build-only"), "prometheus": "runtime",
         **dict.fromkeys(SERVICES, "derived-runtime")}
VERSIONS = {"postgres": "16.15", "clickhouse": "25.8.33.6", "redis": "7.4.11", "node-exporter": "1.12.1"}
SERVICE_BASES = {"postgres-base": "postgres:16.15-alpine3.24",
                 "clickhouse-base": "clickhouse/clickhouse-server:25.8.33.6-alpine",
                 "redis-base": "redis:7.4.11-alpine3.21",
                 "node-exporter-base": "quay.io/prometheus/node-exporter:v1.12.1"}


def validate_inventory(images: dict) -> None:
    if not isinstance(images, dict) or set(images) != set(ROLES):
        raise ValueError("Image inventory requires every known base, tool and runtime; unknown names are forbidden")
    for name, image in images.items():
        if not isinstance(image, dict) or image.get("role") != ROLES[name]:
            raise ValueError(f"Invalid image role for {name}")
        fields = {"role", "reference", "dockerfile"} if name in SERVICES else {"role", "reference"}
        if set(image) != fields or not isinstance(image.get("reference"), str):
            raise ValueError(f"Malformed image inventory entry for {name}")
        if name not in SERVICES and not PIN.fullmatch(image["reference"]):
            raise ValueError(f"Official image requires an exact version and SHA256 index digest: {name}")
        if name in SERVICE_BASES and image["reference"].partition("@")[0] != SERVICE_BASES[name]:
            raise ValueError(f"Maintained service base version or distribution changed: {name}")
        if name in SERVICES and image["dockerfile"] != f"deploy/service-builds/Dockerfile.{name}":
            raise ValueError(f"Unknown maintained runtime recipe for {name}")


def check_service_builds(root: Path, images: dict) -> dict:
    path = root / "requirements/service-builds/manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or \
            type(manifest.get("recipe_version")) is not int or \
            manifest.get("schema") != 1 or manifest.get("recipe_version") != 1 or \
            set(manifest.get("services", {})) != set(SERVICES):
        raise ValueError("Incomplete or unknown maintained service manifest")
    files = {f"requirements/service-builds/{component}/{name}"
             for component in ("gosu", "node-exporter")
             for name in ("go.mod", "go.sum", "modules.txt", "LICENSE", "go.mod.diff",
                          "upstream.go.mod", "upstream.go.sum")}
    files |= {images[name]["dockerfile"] for name in SERVICES}
    files |= {"requirements/service-builds/.gitattributes", "deploy/service-builds/.gitattributes",
              "requirements/service-builds/NOTICE.md"}
    if set(manifest.get("files", {})) != files:
        raise ValueError("Maintained service inputs are missing or unexpected")
    for name, digest in manifest["files"].items():
        source = (root / name).resolve()
        if not source.is_relative_to(root.resolve()) or not isinstance(digest, str) or \
                not re.fullmatch(r"[a-f0-9]{64}", digest) or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Maintained service input hash mismatch: {name}")
    for name, service in manifest["services"].items():
        version = service.get("functional_version")
        if version != VERSIONS[name] or service.get("base") != name + "-base" or \
                service.get("dockerfile") != images[name]["dockerfile"] or \
                service.get("runtime_tag") != images[name]["reference"] or \
                images[name]["reference"] != f"shadai/{name}:{version}-maintained.1":
            raise ValueError(f"Maintained service recipe/reference mismatch: {name}")
    if manifest.get("toolchain") != {"version": "go1.26.6", "image": "golang", "goproxy": "https://proxy.golang.org",
                                     "gosumdb": "sum.golang.org", "gotoolchain": "local"}:
        raise ValueError("Maintained Go toolchain or checksum database mismatch")
    if not images["golang"]["reference"].startswith("golang:1.26.6-alpine3.24@sha256:"):
        raise ValueError("Maintained Go image must use the exact approved compiler version")
    recipes = {name: (root / images[name]["dockerfile"]).read_text(encoding="utf-8") for name in SERVICES}
    for name, recipe in recipes.items():
        bases = re.findall(r"(?m)^FROM (\S+)", recipe)
        if bases != [images["golang"]["reference"], images[name + "-base"]["reference"]]:
            raise ValueError("Maintained recipe must use its exact compiler/fetch and service base images")
    components = manifest.get("components", {})
    if set(components) != {"gosu", "node-exporter"}:
        raise ValueError("Incomplete maintained source inventory")
    for name, repository, tag in (("gosu", "tianon/gosu", "1.19"),
                                  ("node-exporter", "prometheus/node_exporter", "v1.12.1")):
        component = components[name]
        commit = component.get("commit", "")
        if component.get("repository") != repository or component.get("tag") != tag or \
                not re.fullmatch(r"[a-f0-9]{40}", commit) or \
                component.get("source_url") != f"https://codeload.github.com/{repository}/tar.gz/{commit}" or \
                component.get("archive_prefix") != repository.rsplit("/", 1)[1] + "-" + commit or \
                not re.fullmatch(r"[a-f0-9]{64}", component.get("source_sha256", "")):
            raise ValueError("Maintained source must be an exact publisher release commit and archive SHA256")
        directory = root / "requirements/service-builds" / name
        upstream = (directory / "upstream.go.mod").read_text(encoding="utf-8")
        maintained = (directory / "go.mod").read_text(encoding="utf-8")
        expected = upstream if name == "gosu" else upstream.replace(
            "golang.org/x/crypto v0.54.0", "golang.org/x/crypto v0.55.0"
        ).replace("golang.org/x/text v0.40.0", "golang.org/x/text v0.41.0")
        if maintained != expected:
            raise ValueError("Maintained module changes exceed the approved targeted dependency updates")
        recipe = recipes["postgres" if name == "gosu" else name]
        if component["source_url"] not in recipe or component["source_sha256"] not in recipe or \
                any(manifest["files"][f"requirements/service-builds/{name}/{filename}"] not in recipe
                    for filename in ("go.mod", "go.sum", "modules.txt")):
            raise ValueError("Maintained recipe is not bound to its exact source and module locks")
    packages = manifest.get("packages", {})
    if set(packages) != {"clickhouse", "redis"}:
        raise ValueError("Missing maintained APK runtime inventory")
    for name, alpine, version in (("clickhouse", "v3.24", "3.5.9-r0"), ("redis", "v3.21", "3.3.7-r2")):
        if set(packages[name]) != {"x86_64", "aarch64"}:
            raise ValueError("Maintained APKs require both native architectures")
        for arch, values in packages[name].items():
            if not isinstance(values, list) or len(values) != 2 or \
                    {value.get("package") for value in values} != {"libcrypto3", "libssl3"}:
                raise ValueError("Maintained APKs require exact OpenSSL library coverage")
            key = "6165ee59" if arch == "x86_64" else "616ae350"
            for value in values:
                package = value["package"]
                url = f"https://dl-cdn.alpinelinux.org/alpine/{alpine}/main/{arch}/{package}-{version}.apk"
                signature = f".SIGN.RSA.alpine-devel@lists.alpinelinux.org-{key}.rsa.pub"
                if value.get("architecture") != arch or value.get("version") != version or \
                        value.get("url") != url or \
                        not re.fullmatch(r"[a-f0-9]{64}", value.get("sha256", "")) or \
                        value.get("signature_members") != [signature]:
                    raise ValueError("Maintained APK publisher, architecture, hash or signature mismatch")
                if value["sha256"] not in recipes[name] or \
                        f"/{alpine}/main/$arch/{package}-{version}.apk" not in recipes[name]:
                    raise ValueError("Maintained recipe is not bound to the exact native APK bytes")
    return manifest


def inventory(root: Path = ROOT) -> dict:
    images = json.loads((root / "requirements/images.json").read_text(encoding="utf-8"))
    validate_inventory(images)
    return images


def check_references(root: Path = ROOT) -> None:
    images = inventory(root)
    check_service_builds(root, images)
    references = {value["reference"] for value in images.values()}
    bases = {image["reference"] for image in images.values() if image["role"] == "build-only"}
    for path in [*sorted((root / "docker").glob("Dockerfile.*")), root / "frontend/Dockerfile",
                 *sorted((root / "deploy/service-builds").glob("Dockerfile.*"))]:
        stages = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM "):
                fields = line.split()
                reference = fields[1]
                if reference not in stages and reference not in bases:
                    raise ValueError(f"Unrecorded/mutable base image in {path}: {reference}")
                if len(fields) == 4 and fields[2].lower() == "as":
                    stages.add(fields[3])
    for path in [*sorted(root.glob("docker-compose*.yml")), root / "deploy/qualification/compose.yaml"]:
        content = path.read_text(encoding="utf-8")
        for reference in re.findall(r"^\s+image:\s+(\S+)", content, re.MULTILINE):
            if reference not in references:
                raise ValueError(f"Unrecorded/mutable service image in {path}: {reference}")
            image = next(value for value in images.values() if value["reference"] == reference)
            if image["role"] == "build-only":
                raise ValueError(f"Build-only image cannot be deployed as a runtime: {reference}")
        for block in re.split(r"(?m)^  [a-zA-Z0-9_-]+:\s*$", content)[1:]:
            match = re.search(r"(?m)^    image:\s+(\S+)", block)
            if match and match[1] in {images[name]["reference"] for name in SERVICES}:
                image = next(value for value in images.values() if value["reference"] == match[1])
                if not re.search(r"(?m)^    pull_policy: build\s*$", block) or \
                        not re.search(r"dockerfile:\s*" + re.escape(image["dockerfile"]) + r"[\s},]", block):
                    raise ValueError("Maintained runtime requires its exact recipe and pull_policy build")


def check_registry(images: dict) -> None:
    validate_inventory(images)
    for name, image in images.items():
        if image["role"] == "derived-runtime":
            continue  # A local recipe tag has no registry digest; its exact built OCI runtime is gated in CI.
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
    print("PASS: immutable official bases and exact maintained runtime recipes")


if __name__ == "__main__":
    main()
