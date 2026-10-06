"""Versioned qualification inputs and sanitized reports."""

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path

MAX_PROFILE_BYTES = 65536
SCENARIOS = frozenset(
    {
        "baseline",
        "pause_ingest",
        "correlation_outage",
        "reclaim",
        "cold_restore",
        "redis_pressure",
        "probes",
        "physical",
        "kubernetes",
        "idp",
        "quality",
    }
)


class QualificationError(ValueError):
    """An input or proof does not satisfy the qualification contract."""


def strict_object(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise QualificationError("Missing or unknown schema fields")
    return value


def bounded_number(value, low, high, *, integral=False):
    types = (int,) if integral else (int, float)
    if type(value) not in types or not math.isfinite(value) or not low <= value <= high:
        raise QualificationError("Numeric budget is outside supported bounds")
    return value


def bounded_text(value, maximum=255):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise QualificationError("Invalid bounded string")
    return value


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def bounded_read(path, maximum):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise QualificationError("Input must be a bounded regular file without links")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        after = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size > maximum
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise QualificationError("Input identity or regular-file boundary changed")
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise QualificationError("Input exceeds byte budget")
    return data


def read_json(path, maximum=MAX_PROFILE_BYTES):
    raw = bounded_read(path, maximum)
    try:

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise QualificationError("Duplicate JSON field")
                result[key] = value
            return result

        return json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(QualificationError("Nonfinite JSON")),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError("Malformed JSON") from exc


def validate_profile(value):
    profile = strict_object(
        value, {"schema", "scope", "installation", "run", "scenarios", "load", "limits"}, {"objectives", "target"}
    )
    if type(profile["schema"]) is not int or profile["schema"] != 1:
        raise QualificationError("Unknown profile schema")
    if profile["scope"] not in {"disposable_lab", "target"}:
        raise QualificationError("Unknown qualification scope")
    installation = bounded_text(profile["installation"], 100)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", installation):
        raise QualificationError("Invalid installation identifier")
    bounded_text(profile["run"], 100)
    scenarios = profile["scenarios"]
    if not isinstance(scenarios, list) or not scenarios or len(set(scenarios)) != len(scenarios):
        raise QualificationError("Scenarios must be distinct and explicit")
    if not all(type(item) is str and item in SCENARIOS for item in scenarios):
        raise QualificationError("Unknown scenario")
    load = strict_object(
        profile["load"],
        {
            "total_events",
            "events_per_second",
            "batch_size",
            "concurrency",
            "request_timeout_seconds",
            "drain_timeout_seconds",
            "seed",
        },
    )
    bounds = {"total_events": (1, 10000000), "batch_size": (1, 500), "concurrency": (1, 64), "seed": (0, 2**32 - 1)}
    for field, (low, high) in bounds.items():
        bounded_number(load[field], low, high, integral=True)
    for field, low, high in (
        ("events_per_second", 0.01, 100000),
        ("request_timeout_seconds", 0.1, 60),
        ("drain_timeout_seconds", 1, 3600),
    ):
        bounded_number(load[field], low, high)
    limits = strict_object(
        profile["limits"], {"max_wall_seconds", "max_requests", "max_request_bytes", "max_disk_bytes"}
    )
    for field, low, high in (
        ("max_wall_seconds", 1, 86400),
        ("max_requests", 1, 10000000),
        ("max_request_bytes", 1, 16777216),
        ("max_disk_bytes", 1048576, 2**40),
    ):
        bounded_number(limits[field], low, high, integral=True)
    if math.ceil(load["total_events"] / load["batch_size"]) > limits["max_requests"]:
        raise QualificationError("Request budget cannot carry the requested events")
    objectives = profile.get("objectives", {})
    strict_object(
        objectives,
        set(),
        {
            "max_http_p95_seconds",
            "max_end_to_end_p95_seconds",
            "max_recovery_seconds",
            "max_restore_seconds",
            "minimum_precision",
            "minimum_recall",
        },
    )
    for field, objective in objectives.items():
        bounded_number(objective, 0, 1 if field.startswith("minimum") else 86400)
    if "target" in profile:
        target = strict_object(
            profile["target"],
            set(),
            {
                "api_url",
                "issuer",
                "origin",
                "docker_context",
                "namespace",
                "kubernetes_context",
                "stores",
                "secret_files",
                "images",
                "egress_cidrs",
                "maintenance",
                "ingress_namespace",
                "ingress_pod_selector",
                "runtime_secret_name",
                "tls_secret_name",
            },
        )
        for field in {"api_url", "issuer", "origin", "docker_context", "namespace", "kubernetes_context"} & set(target):
            bounded_text(target[field], 2048)
        for field in {"stores", "secret_files", "images"} & set(target):
            if not isinstance(target[field], dict):
                raise QualificationError("Target references must be explicit mappings")
            for key, item in target[field].items():
                bounded_text(key, 100)
                bounded_text(item, 2048)
        if "egress_cidrs" in target and (
            not isinstance(target["egress_cidrs"], list) or len(target["egress_cidrs"]) > 100
        ):
            raise QualificationError("Invalid target egress list")
        if "maintenance" in target and not isinstance(target["maintenance"], bool):
            raise QualificationError("Maintenance authorization must be explicit")
        for field in ("ingress_namespace", "runtime_secret_name", "tls_secret_name"):
            if field in target:
                bounded_text(target[field], 253)
        if "ingress_pod_selector" in target:
            selector = target["ingress_pod_selector"]
            if not isinstance(selector, dict) or not 1 <= len(selector) <= 8:
                raise QualificationError("Ingress controller requires a bounded explicit label selector")
            for key, item in selector.items():
                bounded_text(key, 253)
                bounded_text(item, 63)
    return profile


def load_profile(path):
    return validate_profile(read_json(path))


def objective_results(profile, scenarios):
    paths = {
        "max_http_p95_seconds": ("load", "http_latency_p95_seconds"),
        "max_end_to_end_p95_seconds": ("verification", "end_to_end_latency_p95_seconds"),
        "max_recovery_seconds": ("recovery_seconds",),
        "max_restore_seconds": ("measured_restore_seconds",),
        "minimum_precision": ("quality", "global", "precision"),
        "minimum_recall": ("quality", "global", "recall"),
    }
    results = {}
    for name, limit in profile.get("objectives", {}).items():
        values = []
        for scenario in scenarios:
            value = scenario.get("measurements", {})
            for part in paths[name]:
                value = value.get(part) if isinstance(value, dict) else None
            if type(value) in {int, float} and math.isfinite(value):
                values.append(value)
        if not values:
            results[name] = {"status": "not_evaluated", "limit": limit, "measured": None}
        else:
            measured = min(values) if name.startswith("minimum") else max(values)
            passed = measured >= limit if name.startswith("minimum") else measured <= limit
            results[name] = {"status": "passed" if passed else "failed", "limit": limit, "measured": measured}
    return results


def report(profile, scenarios, *, evidence=None, missing=None):
    from shadai.qualification.provenance import source_stamp

    evidence = dict(evidence or {})
    evidence.setdefault("source", source_stamp())
    missing = missing or []
    seen = set()
    for item in scenarios:
        if (
            item.get("scenario") not in SCENARIOS
            or item.get("scenario") in seen
            or item.get("status") not in {"passed", "failed", "not_evaluated"}
            or type(item.get("executed")) is not bool
            or type(item.get("required")) is not bool
        ):
            raise QualificationError("Invalid scenario evidence")
        if item["status"] == "passed" and not item["executed"]:
            raise QualificationError("Unexecuted scenario cannot pass")
        seen.add(item["scenario"])
    failed = any(item.get("status") == "failed" for item in scenarios)
    objectives = objective_results(profile, scenarios)
    failed = failed or any(item["status"] == "failed" for item in objectives.values())
    missing += ["objective:" + name for name, item in objectives.items() if item["status"] == "not_evaluated"]
    absent = missing or any(item.get("status") == "not_evaluated" for item in scenarios)
    required = set(profile["scenarios"])
    executed = {item["scenario"] for item in scenarios}
    absent = absent or required - executed
    return {
        "schema": 1,
        "scope": profile["scope"],
        "profile_sha256": hashlib.sha256(canonical_bytes(profile)).hexdigest(),
        "scenarios": scenarios,
        "objectives": objectives,
        "missing_evidence": sorted(set(missing) | (required - executed)),
        "evidence": evidence,
        "exit_code": 1 if failed else 2 if absent else 0,
    }
