"""Validate one declared principal identity using a separate native CLI observation."""

import hashlib
import re
from uuid import UUID

VERSION = "25.8.33.6"
RECEIPT_NAME = "clickhouse.principal-observation.json"
QUERY = "cpe:2.3:a:clickhouse:clickhouse:25.8.33.6:*:*:*:*:*:*:*"
STDOUT = b"ClickHouse server version 25.8.33.6 (official build).\n"
SHA = re.compile(r"[a-f0-9]{64}")


def canonical_receipt_path(path, *, expected_parent=None):
    """Pending or arbitrary JSON filenames never constitute principal evidence."""
    if path.name != RECEIPT_NAME or expected_parent is not None and path.parent != expected_parent:
        raise ValueError("Principal observation requires its canonical sibling filename")
    return path


def ci_identity(environment, *, signing=False):
    job = environment.get("GITHUB_JOB")
    if job not in ({"derived-service-builds", "signed-image-evidence"} if signing else {"derived-service-builds"}):
        raise ValueError("Principal observation requires the native CI job identity")
    identity = {"run_id": environment.get("GITHUB_RUN_ID"), "run_attempt": environment.get("GITHUB_RUN_ATTEMPT"),
                "job": "derived-service-builds"}
    if any(not isinstance(identity[key], str) or not re.fullmatch(r"[1-9]\d{0,19}", identity[key])
           for key in ("run_id", "run_attempt")):
        raise ValueError("Principal observation requires current numeric CI identity")
    return identity


def validate_receipt(receipt, *, subject, config, expected_source, expected_ci,
                     collector_sha256, process_module_sha256):
    """Verify the bounded exact receipt; verified means collection, not authentication."""
    if not isinstance(receipt, dict) or not isinstance(receipt.get("invocation"), str):
        raise ValueError("Missing declared principal CLI receipt")
    try:
        invocation = str(UUID(receipt["invocation"]))
    except ValueError as error:
        raise ValueError("Invalid principal observation invocation") from error
    if invocation != receipt["invocation"] or not SHA.fullmatch(collector_sha256) or \
            not SHA.fullmatch(process_module_sha256):
        raise ValueError("Invalid principal observation collector/invocation")
    if subject.get("platform") not in {"linux/amd64", "linux/arm64"} or \
            subject["platform"] != f"{config.get('os')}/{config.get('architecture')}":
        raise ValueError("Principal observation selected native platform differs")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    if not isinstance(diff_ids, list) or not diff_ids or any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in diff_ids):
        raise ValueError("Principal observation needs exact selected OCI RootFS")
    expected = {"schema": 1, "kind": "clickhouse-cli-version", "status": "verified", "invocation": invocation,
                "ci": expected_ci, "source": expected_source, "subject": subject,
                "collector_sha256": collector_sha256, "command_contract": "clickhouse-server-version-v1",
                "process_module_sha256": process_module_sha256,
                "observation": {"binary": "/usr/bin/clickhouse", "argv": ["server", "--version"], "version": VERSION,
                    "reported_build_kind": "official build", "stdout_bytes": len(STDOUT),
                    "stdout_sha256": hashlib.sha256(STDOUT).hexdigest(), "stderr_bytes": 0,
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(), "docker_cli_exit_code": 0,
                    "container_exit_code": 0},
                "identity": {"image_id_before": subject["image_config"], "image_id_after": subject["image_config"],
                    "container_image_before": subject["image_config"], "container_image_after": subject["image_config"],
                    "env_matches_image": True,
                    "rootfs_diff_ids": diff_ids},
                "cleanup": {"container_removed": True, "absence_verified": True},
                "authentication": {"builder_provenance": "unverified", "publisher_signature": "unverified"}}
    # Equality alone would accept bool as an integer. Require exact scalar/container types too.
    def exact(actual, wanted):
        if type(actual) is not type(wanted):
            return False
        if isinstance(wanted, dict):
            return actual.keys() == wanted.keys() and all(exact(actual[key], value) for key, value in wanted.items())
        if isinstance(wanted, list):
            return len(actual) == len(wanted) and all(exact(a, b) for a, b in zip(actual, wanted, strict=True))
        return actual == wanted
    if not exact(receipt, expected):
        raise ValueError("Declared principal CLI/source/subject/identity/cleanup receipt differs")
    return expected
