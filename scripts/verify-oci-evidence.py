"""Validate a bounded, complete OCI graph and its image-bound build evidence."""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
EMPTY_CONFIG_TYPE = "application/vnd.oci.empty.v1+json"
LAYER_TYPES = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
               "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.oci.image.layer.nondistributable.v1.tar",
               "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
               "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
               "application/vnd.docker.image.rootfs.diff.tar.gzip",
               "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"}
STATEMENT_TYPE = "application/vnd.in-toto+json"
MAX_MEMBERS = 100_000
MAX_JSON = 128 * 1024 * 1024
MAX_DEPTH = 16
MAX_DESCRIPTORS = 10_000


def verify(path: Path, *, platform: str = "linux/amd64", include_sbom: bool = False) -> dict:
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("Expected native platform must be linux/amd64 or linux/arm64")
    with path.open("rb") as source_file:
        initial_digest = hashlib.file_digest(source_file, "sha256").hexdigest()
    with tarfile.open(path, "r:*") as archive:
        members = {}
        # Hash layer bytes in chunks; do not load image layers or extract arbitrary paths.
        for member in archive:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            if not name or name.startswith("/") or "\\" in name or ":" in name or \
                    any(part in {"..", "."} for part in name.split("/")) or \
                    name in members or len(members) >= MAX_MEMBERS or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe or duplicate OCI archive member")
            if not (name in {"index.json", "oci-layout", "blobs", "blobs/sha256"} or
                    (len(parts) == 3 and parts[:2] == ("blobs", "sha256") and re.fullmatch(r"[a-f0-9]{64}", parts[2]))):
                raise ValueError("Unexpected OCI archive member")
            members[name] = member
            if name.startswith("blobs/sha256/"):
                if not member.isfile():
                    raise ValueError("OCI blob must be a regular file")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("Unreadable OCI blob")
                with source:
                    checksum = hashlib.file_digest(source, "sha256").hexdigest()
                if checksum != parts[2]:
                    raise ValueError("OCI blob SHA256 mismatch")

        def document(name):
            member = members.get(name)
            if member is None or not member.isfile() or member.size > MAX_JSON:
                raise ValueError("Missing or oversized OCI JSON document")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("Unreadable OCI JSON document")
            with source:
                result = json.load(source)
            if not isinstance(result, dict):
                raise ValueError("OCI JSON document must be an object")
            return result

        if document("oci-layout").get("imageLayoutVersion") != "1.0.0":
            raise ValueError("Unsupported OCI layout")
        descriptors = 0
        seen = {}

        def descriptor(entry, types):
            nonlocal descriptors
            descriptors += 1
            if descriptors > MAX_DESCRIPTORS or not isinstance(entry, dict):
                raise ValueError("Unbounded or malformed OCI descriptor graph")
            digest, size, media = (entry.get(key) for key in ("digest", "size", "mediaType"))
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest) or \
                    type(size) is not int or size < 0 or media not in types:
                raise ValueError("Invalid OCI descriptor digest, size or mediaType")
            member = members.get("blobs/sha256/" + digest[7:])
            if member is None or not member.isfile() or member.size != size:
                raise ValueError("Missing OCI graph blob or descriptor size mismatch")
            identity = (media, size)
            if digest in seen and seen[digest] != identity:
                raise ValueError("Inconsistent OCI descriptors for the same digest")
            seen[digest] = identity
            return digest

        flattened = []

        def walk(index, ancestry=()):
            if len(ancestry) > MAX_DEPTH or index.get("schemaVersion") != 2 or \
                    index.get("mediaType", "application/vnd.oci.image.index.v1+json") not in INDEX_TYPES or \
                    not isinstance(index.get("manifests"), list) or not 0 < len(index["manifests"]) <= 1024:
                raise ValueError("Malformed or unbounded OCI index")
            for entry in index["manifests"]:
                digest = descriptor(entry, INDEX_TYPES | MANIFEST_TYPES)
                if digest in ancestry:
                    raise ValueError("Cycle in OCI descriptor graph")
                if entry["mediaType"] in INDEX_TYPES:
                    walk(document("blobs/sha256/" + digest[7:]), (*ancestry, digest))
                else:
                    flattened.append(entry)

        walk(document("index.json"))
        evidence = {}
        configs = {}
        statements = []
        sboms = {}
        for entry in flattened:
            digest = entry["digest"][7:]
            annotations = entry.get("annotations", {})
            if not isinstance(annotations, dict):
                raise ValueError("Malformed OCI descriptor annotations")
            attestation = annotations.get("vnd.docker.reference.type") == "attestation-manifest"
            expected_platform = {"os": "unknown", "architecture": "unknown"} if attestation else \
                dict(zip(("os", "architecture"), platform.split("/"), strict=True))
            actual_platform = entry.get("platform", {})
            if not isinstance(actual_platform, dict) or any(actual_platform.get(key) != value
                                                          for key, value in expected_platform.items()):
                raise ValueError("OCI image native platform mismatch or unrecognized unknown platform")
            manifest = document("blobs/sha256/" + digest)
            if manifest.get("schemaVersion") != 2 or \
                    manifest.get("mediaType", entry["mediaType"]) != entry["mediaType"] or \
                    not isinstance(manifest.get("layers"), list) or len(manifest["layers"]) > 1024:
                raise ValueError("Malformed OCI image manifest")
            artifact = attestation and manifest.get("artifactType") == \
                "application/vnd.docker.attestation.manifest.v1+json"
            config_digest = descriptor(manifest.get("config"), {EMPTY_CONFIG_TYPE} if artifact else CONFIG_TYPES)
            config = document("blobs/sha256/" + config_digest[7:])
            if artifact:
                if config != {} or descriptor(manifest.get("subject"), MANIFEST_TYPES) != \
                        annotations.get("vnd.docker.reference.digest"):
                    raise ValueError("OCI attestation artifact subject or empty config mismatch")
            elif any(config.get(key) != value for key, value in expected_platform.items()):
                raise ValueError("OCI config native platform mismatch")
            rootfs = config.get("rootfs", {})
            if not artifact and (not isinstance(rootfs, dict) or rootfs.get("type") != "layers" or \
                    not isinstance(rootfs.get("diff_ids"), list) or \
                    len(rootfs["diff_ids"]) != len(manifest["layers"]) or \
                    any(not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value)
                        for value in rootfs["diff_ids"])):
                raise ValueError("Malformed OCI config rootfs")
            if not attestation:
                if digest in evidence:
                    raise ValueError("Duplicate OCI image manifest")
                evidence[digest] = set()
                configs[digest] = config_digest
            for layer in manifest["layers"]:
                layer_digest = descriptor(layer, {STATEMENT_TYPE} if attestation else LAYER_TYPES)
                if attestation:
                    related = annotations.get("vnd.docker.reference.digest")
                    statements.append((related, document("blobs/sha256/" + layer_digest[7:])))
        for related, statement in statements:
            if not isinstance(related, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", related) or \
                    related[7:] not in evidence:
                raise ValueError("Attestation manifest has no matching image")
            related = related[7:]
            statement_types = {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}
            if statement.get("_type") not in statement_types or \
                    not isinstance(statement.get("subject"), list) or not statement["subject"] or \
                    any(not isinstance(subject, dict) or subject.get("digest", {}).get("sha256") != related
                        for subject in statement["subject"]):
                raise ValueError("Attestation statement subject is not the exact linked image")
            kind, predicate = statement.get("predicateType"), statement.get("predicate")
            if not isinstance(kind, str) or not isinstance(predicate, dict):
                raise ValueError("Malformed in-toto statement")
            if kind == "https://spdx.dev/Document":
                if not isinstance(predicate.get("packages"), list) or not predicate["packages"]:
                    raise ValueError("Empty SPDX SBOM")
                evidence[related].add("sbom")
                sboms[related] = predicate
            elif kind.startswith("https://slsa.dev/provenance/"):
                if not predicate:
                    raise ValueError("Empty SLSA provenance")
                evidence[related].add("provenance")
        if not evidence or any(kinds != {"sbom", "provenance"} for kinds in evidence.values()):
            raise ValueError("Missing image-bound SPDX SBOM or SLSA provenance")
        with path.open("rb") as archive_file:
            archive_digest = hashlib.file_digest(archive_file, "sha256").hexdigest()
        if archive_digest != initial_digest:
            raise ValueError("OCI archive changed during evidence verification")
        result = {"archive_sha256": archive_digest, "platform": platform, "image_manifests": sorted(evidence),
                  "image_configs": configs,
                  "verified": ["blob-sha256", "oci-graph", "native-platform", "spdx-sbom", "slsa-provenance"]}
        if include_sbom:
            result["sboms"] = sboms
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(verify(args.archive, platform=args.platform), indent=2) + "\n", encoding="utf-8")
    print("PASS: complete native OCI graph and image-bound SBOM/provenance")


if __name__ == "__main__":
    main()
