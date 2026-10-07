"""Owned disposable Docker laboratory orchestration, using only host stdlib."""

import base64
import hashlib
import json
import math
import os
import platform
import re
import secrets
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from shadai.qualification.http_transport import HttpTransport
from shadai.qualification.journal import (
    LABEL,
    RunJournal,
    atomic_json,
    resource_identity,
    validate_helper_record,
    verify_resource,
)
from shadai.qualification.load import LoadSender
from shadai.qualification.schemas import SCENARIOS, QualificationError, canonical_bytes, report
from shadai.qualification.snapshot import EXPORT_REASONS, EXPORT_STEPS, parse_export_diagnostic
from shadai.workers.probe import READINESS_REASONS, SECONDARY_REASONS, parse_readiness_diagnostic

SERVICES = {
    "api",
    "ingest-worker",
    "correlation-worker",
    "purge-worker",
    "postgres",
    "clickhouse",
    "redis",
    "labredis-pressure",
    "migrate",
}
TOOLS = {"node-exporter", "probe-ingest-peer"}
WRITERS = {"api", "ingest-worker", "correlation-worker", "purge-worker"}
STORES = {"postgres", "clickhouse", "redis"}
FAILURE_STAGES = {
    "starting_compose", "starting_discover", "initialize_stop", "initialize_inspector", "initialize_start",
    "readiness", "enroll", "scenario",
}
DOCKER_FAILURE_CODES = {"docker_nonzero", "docker_timeout", "docker_process_error", "docker_output_budget"}
PRESSURE_STEPS = {
    "seed": {"name_inspect", "launch", "capture", "wait", "reinspect", "cleanup_inspect", "remove_inspect",
             "remove", "junit"},
    "stop": {"inspect", "stop", "reinspect"},
    "export": {"source_inspect", "stopped_inspect", "worker_inspect", "volume_inspect", "create", "capture",
               "volume_absence", "volume_create", "volume_capture", "name_inspect", "inspect", "start", "wait",
               "logs", "copy_inspect", "copy", "remove_inspect", "remove", "validate"},
    "import": {"validate", "volume_absence", "volume_create", "volume_capture", "worker_inspect", "volume_inspect",
               "create", "capture", "inspect", "start", "wait", "logs", "remove_inspect", "remove"},
    "restore": {"up", "discover_list", "discover_inspect"},
    "assert": {"name_inspect", "launch", "capture", "wait", "reinspect", "cleanup_inspect", "remove_inspect",
               "remove", "junit"},
}
PRESSURE_CHECKPOINTS = {"pressure_" + section + "_" + step
                        for section, steps in PRESSURE_STEPS.items() for step in steps}
PHYSICAL_STEPS = {
    "inspector": {"guard_inspect", "run", "name_inspect", "wait", "logs", "remove_inspect", "remove"},
    "services": {"inspect", "stats"},
    "volume": {"source_inspect", "worker_inspect", "volume_inspect", "create", "capture", "inspect", "start",
               "wait", "logs", "remove_inspect", "remove"},
    "exporter": {"guard_inspect", "up", "discover_list", "discover_inspect", "inspect", "observe"},
}
PHYSICAL_CHECKPOINTS = {"physical_" + section + "_" + step
                        for section, steps in PHYSICAL_STEPS.items() for step in steps}
PROBE_STEPS = {
    "baseline": {"registry", "startup_identity", "startup", "liveness_identity", "liveness", "restart"},
    "outage": {"registry", "inspect", "stop", "start", "reinspect", "wait", "liveness_identity", "liveness",
               "readiness_identity", "readiness", "restart"},
    "dependencies": {"registry", "unique", "budget", "inspect", "identity", "state", "health", "wait",
                     "readiness_identity", "readiness", "launch_budget"},
    "peer": {"guard_inspect", "launch", "discover_list", "discover_inspect", "discover_identity", "discover_save",
             "registry", "budget", "startup_identity", "startup", "wait", "liveness_identity", "liveness"},
    "suspend": {"identity", "signal", "wait", "liveness_identity", "liveness"},
    "resume": {"identity", "signal", "registry", "inspect", "stop", "reinspect"},
    "witness": {"launch", "worker_registry", "worker_inspect", "create", "capture", "inspect", "start", "wait",
                "logs", "result", "remove_inspect", "remove", "report", "record"},
}
PROBE_CHECKPOINTS = {"probes_" + section + "_" + step
                     for section, steps in PROBE_STEPS.items() for step in steps}
PROBE_SERVICES = {"ingest-worker", "probe-ingest-peer", "migrate", "redis", "clickhouse"}
COLD_INSPECTOR_STEPS = {"run", "guard_inspect", "name_inspect", "identity", "wait", "logs", "result",
                        "remove_inspect", "remove"}
COLD_STEPS = {
    "entry": {"budget"},
    "writers_stop": {"registry", "inspect", "stop", "reinspect"},
    "seed_pending": COLD_INSPECTOR_STEPS | {"pel"},
    "redis_persistence": COLD_INSPECTOR_STEPS | {"budget", "complete"},
    "inventory_source": COLD_INSPECTOR_STEPS,
    "stores_stop": {"registry", "inspect", "stop", "reinspect"},
    "export": PRESSURE_STEPS["export"] | {"budget", "registry", "capability", "archive", "name", "result",
                                          "copy_budget", "copy_size", "retained", "hash"},
    "manifest": {"write"},
    "secrets": {"verify"},
    "import": PRESSURE_STEPS["import"] | {"retained", "registry", "capability", "archive", "result"},
    "stores_start": {"guard_inspect", "up", "discover_list", "discover_inspect", "discover_identity", "discover_save"},
    "inventory_restore": COLD_INSPECTOR_STEPS,
    "inventory_compare": {"read_source", "read_restore", "compare"},
    "writers_start": {"guard_inspect", "up", "discover_list", "discover_inspect", "discover_identity", "discover_save"},
    "readiness": {"deadline", "port", "request", "wait"},
    "fresh_send": {"send"},
    "fresh_accepted": {"verify"},
    "fresh_verify": COLD_INSPECTOR_STEPS | {"drain", "deadline", "sleep"},
    "fresh_receipts": {"verify"},
    "record": {"write"},
}
COLD_CHECKPOINTS = {"cold_restore_" + section + "_" + step
                    for section, steps in COLD_STEPS.items() for step in steps}
COLD_SERVICES = WRITERS | STORES | {"inspector"}
COLD_OPERATIONS = {
    "guard_inspect": "container_inspect", "name_inspect": "container_inspect", "source_inspect": "container_inspect",
    "stopped_inspect": "container_inspect", "worker_inspect": "container_inspect", "capture": "container_inspect",
    "inspect": "container_inspect", "reinspect": "container_inspect", "copy_inspect": "container_inspect",
    "remove_inspect": "container_inspect", "volume_absence": "volume_inspect", "volume_inspect": "volume_inspect",
    "volume_capture": "volume_inspect", "volume_create": "volume_create", "create": "container_create",
    "start": "container_start", "stop": "container_stop", "wait": "container_wait", "logs": "container_logs",
    "copy": "container_cp", "remove": "container_rm", "run": "compose_run", "up": "compose_up",
    "discover_list": "container_list", "discover_inspect": "container_inspect",
}
DIAGNOSTIC_CHECKPOINTS = PRESSURE_CHECKPOINTS | PHYSICAL_CHECKPOINTS | PROBE_CHECKPOINTS | COLD_CHECKPOINTS
EXPORT_ARCHIVE_LIMIT = 1073741824
EXPORT_METADATA_MARGIN = 10485760
EXPORT_SNAPSHOT_CODE = """import resource,runpy,sys
limit=int(sys.argv[1])
if limit <= 0: raise ValueError('archive_limit')
resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
sys.argv=['shadai.qualification',*sys.argv[2:]]
from shadai.qualification.snapshot import export_diagnostics
with export_diagnostics() as diagnostic:
    runpy.run_module('shadai.qualification',run_name='__main__',init_globals={'print':diagnostic.print})
"""
FAILURE_STAGES |= DIAGNOSTIC_CHECKPOINTS
DOCKER_OPERATIONS = {
    (kind, command): kind + "_" + command
    for kind, commands in {
        "container": {"inspect", "create", "start", "stop", "wait", "logs", "cp", "rm", "exec"},
        "volume": {"inspect", "create", "ls", "rm"}, "network": {"inspect", "ls", "rm"},
        "compose": {"run", "up"},
    }.items() for command in commands
}
DOCKER_OPERATION_NAMES = set(DOCKER_OPERATIONS.values()) | {"container_list", "container_stats", "unknown"}


def docker_operation(args):
    if not args or type(args[0]) is not str:
        return "unknown"
    if args[0] == "ps":
        return "container_list"
    if args[0] == "stats":
        return "container_stats"
    command = args[1] if len(args) > 1 else None
    if args[0] == "compose" and len(args) > 7 and type(args[1]) is str and args[1] == "--project-name":
        if type(args[3]) is not str or type(args[5]) is not str or args[3] != "--file" or args[5] != "--env-file":
            return "unknown"
        command = args[7]
    return DOCKER_OPERATIONS.get((args[0], command), "unknown") if type(command) is str else "unknown"


class DockerOperationError(QualificationError):
    """Only fixed failure codes and bounded exit status may enter public proof."""

    def __init__(self, code, returncode=None, *, operation="unknown", checkpoint=None, last_completed=None):
        super().__init__("Docker operation failed; upstream output is excluded from proof")
        self.code = code if type(code) is str and code in DOCKER_FAILURE_CODES else "docker_process_error"
        self.returncode = returncode if type(returncode) is int and -255 <= returncode <= 255 else None
        self.operation = operation if type(operation) is str and operation in DOCKER_OPERATION_NAMES else "unknown"
        self.checkpoint = checkpoint if type(checkpoint) is str and checkpoint in DIAGNOSTIC_CHECKPOINTS else None
        self.last_completed = (last_completed if type(last_completed) is str and
                               last_completed in DIAGNOSTIC_CHECKPOINTS else None)


def safe_exception_type(exc):
    for kind in (
        DockerOperationError, QualificationError, AssertionError, ValueError, TypeError, KeyError,
        json.JSONDecodeError, PermissionError, FileNotFoundError, OSError, RuntimeError,
        KeyboardInterrupt, SystemExit, subprocess.TimeoutExpired,
    ):
        if type(exc) is kind:
            return kind.__name__
    return "UnexpectedError"


def failure_evidence(exc, phase, stage):
    value = {
        "phase": phase if type(phase) is str and phase in SCENARIOS | {"created", "starting", "initialized"}
        else "unknown",
        "stage": stage if type(stage) is str and stage in FAILURE_STAGES else "unknown",
        "error_type": safe_exception_type(exc),
        "code": "qualification_error" if type(exc) is QualificationError else "exception",
    }
    if type(exc) is DockerOperationError:
        value["code"] = (exc.code if type(exc.code) is str and exc.code in DOCKER_FAILURE_CODES
                         else "docker_process_error")
        if type(exc.returncode) is int and -255 <= exc.returncode <= 255:
            value["returncode"] = exc.returncode
        checkpoint = (exc.checkpoint if type(exc.checkpoint) is str and
                      exc.checkpoint in DIAGNOSTIC_CHECKPOINTS else None)
        if checkpoint is not None:
            # Freeze the failed call's context before a finally-block performs cleanup.
            value["stage"] = value["checkpoint"] = checkpoint
            value["operation"] = (exc.operation if type(exc.operation) is str and
                                  exc.operation in DOCKER_OPERATION_NAMES else "unknown")
            if type(exc.last_completed) is str and exc.last_completed in DIAGNOSTIC_CHECKPOINTS:
                value["last_completed"] = exc.last_completed
    return value


def probe_failure_evidence(exc, checkpoint, operation, service, last_completed, *, reason_code=None,
                           secondary_reason=None):
    value = failure_evidence(exc, "probes", checkpoint)
    if type(checkpoint) is str and checkpoint in PROBE_CHECKPOINTS:
        value["stage"] = value["checkpoint"] = checkpoint
        actual_operation = operation
        if (type(exc) is DockerOperationError and type(exc.operation) is str and
                exc.operation in DOCKER_OPERATION_NAMES and exc.operation != "unknown"):
            actual_operation = exc.operation
        value["operation"] = (actual_operation if type(actual_operation) is str and
                              actual_operation in DOCKER_OPERATION_NAMES else "unknown")
        if type(service) is str and service in PROBE_SERVICES:
            value["service"] = service
        if type(last_completed) is str and last_completed in PROBE_CHECKPOINTS:
            value["last_completed"] = last_completed
        if checkpoint == "probes_dependencies_readiness":
            if type(reason_code) is str and reason_code in READINESS_REASONS:
                value["reason_code"] = reason_code
            if type(secondary_reason) is str and secondary_reason in SECONDARY_REASONS:
                value["secondary_reason"] = secondary_reason
    return value


def cold_failure_evidence(exc, checkpoint, operation, service, last_completed):
    if type(exc) is DockerOperationError:
        if type(exc.checkpoint) is str and exc.checkpoint in COLD_CHECKPOINTS:
            checkpoint = exc.checkpoint
        if type(exc.operation) is str and exc.operation in DOCKER_OPERATION_NAMES:
            operation = exc.operation
        if type(exc.last_completed) is str and exc.last_completed in COLD_CHECKPOINTS:
            last_completed = exc.last_completed
    value = failure_evidence(exc, "cold_restore", checkpoint)
    for field in ("checkpoint", "operation", "last_completed"):
        value.pop(field, None)
    value["stage"] = checkpoint if type(checkpoint) is str and checkpoint in COLD_CHECKPOINTS else "unknown"
    if type(checkpoint) is str and checkpoint in COLD_CHECKPOINTS:
        value["stage"] = value["checkpoint"] = checkpoint
        value["operation"] = operation if type(operation) is str and operation in DOCKER_OPERATION_NAMES else "unknown"
        if type(service) is str and service in COLD_SERVICES:
            value["service"] = service
        if type(last_completed) is str and last_completed in COLD_CHECKPOINTS:
            value["last_completed"] = last_completed
    return value


def closed_cold_evidence(value):
    if type(value) is not dict or any(type(key) is not str for key in value):
        return False
    enums = {"phase": {"cold_restore"}, "stage": COLD_CHECKPOINTS | {"unknown"},
             "checkpoint": COLD_CHECKPOINTS, "operation": DOCKER_OPERATION_NAMES, "service": COLD_SERVICES,
             "last_completed": COLD_CHECKPOINTS, "code": DOCKER_FAILURE_CODES | {"qualification_error", "exception"},
             "error_type": {"DockerOperationError", "QualificationError", "AssertionError", "ValueError", "TypeError",
                            "KeyError", "JSONDecodeError", "PermissionError", "FileNotFoundError", "OSError",
                            "RuntimeError", "KeyboardInterrupt", "SystemExit", "TimeoutExpired", "UnexpectedError"}}
    if (not {"phase", "stage", "code", "error_type"} <= value.keys()
            or not value.keys() <= enums.keys() | {"returncode", "helper_exit_status", "helper_step", "helper_reason",
                                                   "inventory_comparison"}):
        return False
    for key, item in value.items():
        if key == "inventory_comparison":
            if not closed_inventory_comparison(item):
                return False
        elif key == "returncode":
            if type(item) is not int or not -255 <= item <= 255:
                return False
        elif key == "helper_exit_status":
            if type(item) is not int or not 1 <= item <= 255:
                return False
        elif key in {"helper_step", "helper_reason"}:
            choices = EXPORT_STEPS if key == "helper_step" else EXPORT_REASONS
            if type(item) is not str or item not in choices:
                return False
        elif type(item) is not str or item not in enums[key]:
            return False
    if ("inventory_comparison" in value
            and (value.get("checkpoint") != "cold_restore_inventory_compare_compare"
                 or value.get("error_type") != "AssertionError")):
        return False
    if ({"helper_exit_status", "helper_step", "helper_reason"} & value.keys()
            and (value.get("checkpoint") != "cold_restore_export_result"
                 or not {"helper_step", "helper_reason"} <= value.keys())):
        return False
    return True


INVENTORY_TABLE_WIDTHS = {
    "ingest_receipts": 1, "correlation_receipts": 2, "detections": 3, "collectors": 4,
    "collector_credentials": 4, "detection_identity_members": 3,
}
INVENTORY_REDIS_COMPONENTS = {
    "keys", "strings", "hashes", "zsets", "stream_entries", "stream_groups", "stream_pending",
}
INVENTORY_REDIS_GROUP_FIELDS = (
    "name", "consumers", "pending", "last-delivered-id", "entries-read", "lag",
)


def closed_inventory_comparison(value):
    def keys(item, expected):
        return (type(item) is dict and all(type(key) is str for key in item)
                and item.keys() == expected)

    def counts(item, minimum=0):
        return (type(item) is list and len(item) == 3 and type(item[0]) is bool
                and all(type(count) is int and minimum <= count <= 100000 for count in item[1:]))

    required = {"schema", "stores", "postgres", "clickhouse", "redis"}
    if not (type(value) is dict and all(type(key) is str for key in value)
            and required <= value.keys() <= required | {"redis_group_fields"}
            and type(value["schema"]) is int and value["schema"] == 1
            and keys(value["stores"], {"postgres", "clickhouse", "redis"})
            and all(type(flag) is bool for flag in value["stores"].values())
            and keys(value["postgres"], INVENTORY_TABLE_WIDTHS.keys())
            and all(counts(item, -1) for item in value["postgres"].values())
            and counts(value["clickhouse"])
            and keys(value["redis"], INVENTORY_REDIS_COMPONENTS)
            and all(counts(item) for item in value["redis"].values())):
        return False
    if "redis_group_fields" not in value:
        return True
    detail = value["redis_group_fields"]
    # Validate every nested type before inspecting its dependent comparison flag.
    if not (keys(detail, {"aligned", "fields", "unknown_fields"})
            and type(detail["aligned"]) is bool
            and keys(detail["fields"], set(INVENTORY_REDIS_GROUP_FIELDS))
            and all(type(flag) is bool for flag in detail["fields"].values())
            and type(detail["unknown_fields"]) is list and len(detail["unknown_fields"]) == 2
            and all(type(flag) is bool for flag in detail["unknown_fields"])):
        return False
    return (value["redis"]["stream_groups"][0] is False
            and (detail["aligned"] or not any(detail["fields"].values())))


def cold_inventory_comparison(source, restored):
    """Validate both private inventories before comparing; publish only fixed counts/flags."""
    visited = characters = 0
    active = set()

    def walk(value, depth=0):
        nonlocal visited, characters
        visited += 1
        if visited > 100000 or depth > 32:
            raise ValueError("inventory_diagnostic_unavailable")
        kind = type(value)
        if kind is str:
            characters += len(value)
            if characters > 1048576:
                raise ValueError("inventory_diagnostic_unavailable")
        elif kind is int:
            if value.bit_length() > 4096:
                raise ValueError("inventory_diagnostic_unavailable")
        elif kind is float:
            if not math.isfinite(value):
                raise ValueError("inventory_diagnostic_unavailable")
        elif value is None or kind is bool:
            pass
        elif kind is dict or kind is list:
            identity = id(value)
            if identity in active or len(value) > 100000 - visited:
                raise ValueError("inventory_diagnostic_unavailable")
            active.add(identity)
            if kind is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise ValueError("inventory_diagnostic_unavailable")
                    walk(key, depth + 1)
                    walk(item, depth + 1)
            else:
                for item in value:
                    walk(item, depth + 1)
            active.remove(identity)
        else:
            raise ValueError("inventory_diagnostic_unavailable")

    def rows(value, width):
        return type(value) is list and all(type(row) is list and len(row) == width for row in value)

    def shape(value):
        if type(value) is not dict or value.keys() != {"postgres", "clickhouse_events", "redis"}:
            return False
        postgres, redis = value["postgres"], value["redis"]
        if (type(postgres) is not dict or not postgres.keys() <= INVENTORY_TABLE_WIDTHS.keys()
                or not all(rows(table, INVENTORY_TABLE_WIDTHS[name]) for name, table in postgres.items())
                or not rows(value["clickhouse_events"], 4) or type(redis) is not dict):
            return False
        for record in redis.values():
            if type(record) is not dict or type(record.get("type")) is not str:
                return False
            kind = record["type"]
            if kind in {"hash", "string", "zset"}:
                if record.keys() != {"type", "value"}:
                    return False
                item = record["value"]
                if kind == "string" and item is not None and type(item) is not str:
                    return False
                if kind == "hash" and (type(item) is not dict or
                                       not all(type(v) is str for v in item.values())):
                    return False
                if kind == "zset" and (not rows(item, 2) or not all(
                        type(pair[0]) is str and type(pair[1]) in {int, float} for pair in item)):
                    return False
            elif kind == "stream":
                if record.keys() != {"type", "entries", "groups", "pending"}:
                    return False
                if (not rows(record["entries"], 2) or not all(type(pair[0]) is str and
                        type(pair[1]) is dict and all(type(v) is str for v in pair[1].values())
                        for pair in record["entries"])):
                    return False
                if (type(record["groups"]) is not list or not all(type(group) is dict
                        for group in record["groups"]) or type(record["pending"]) is not dict or
                        not all(type(items) is list and all(type(item) is dict for item in items)
                                for items in record["pending"].values())):
                    return False
            else:
                return False
        return True

    try:
        walk(source)
        walk(restored)
        if not shape(source) or not shape(restored):
            return None
    except ValueError:
        return None

    def redis_parts(value):
        parts = {name: {} for name in INVENTORY_REDIS_COMPONENTS if name != "keys"}
        sizes = dict.fromkeys(INVENTORY_REDIS_COMPONENTS, 0)
        sizes["keys"] = len(value)
        for key, record in value.items():
            kind = record["type"]
            if kind == "stream":
                for component, field in (("stream_entries", "entries"), ("stream_groups", "groups"),
                                         ("stream_pending", "pending")):
                    parts[component][key] = record[field]
                    sizes[component] += (sum(len(items) for items in record[field].values())
                                         if field == "pending" else len(record[field]))
            else:
                component = {"string": "strings", "hash": "hashes", "zset": "zsets"}[kind]
                parts[component][key] = record["value"]
                sizes[component] += 1 if kind == "string" else len(record["value"])
        return parts, sizes

    left, left_sizes = redis_parts(source["redis"])
    right, right_sizes = redis_parts(restored["redis"])
    redis = {name: [left[name] == right[name], left_sizes[name], right_sizes[name]] for name in left}
    redis["keys"] = [source["redis"].keys() == restored["redis"].keys(), left_sizes["keys"], right_sizes["keys"]]
    postgres = {}
    for name in INVENTORY_TABLE_WIDTHS:
        a, b = source["postgres"].get(name), restored["postgres"].get(name)
        postgres[name] = [a == b, -1 if a is None else len(a), -1 if b is None else len(b)]
    summary = {"schema": 1, "stores": {
        "postgres": source["postgres"] == restored["postgres"],
        "clickhouse": source["clickhouse_events"] == restored["clickhouse_events"],
        "redis": source["redis"] == restored["redis"]}, "postgres": postgres,
        "clickhouse": [source["clickhouse_events"] == restored["clickhouse_events"],
                       len(source["clickhouse_events"]), len(restored["clickhouse_events"])], "redis": redis}
    if redis["stream_groups"][0] is False:
        groups = (left["stream_groups"], right["stream_groups"])
        valid = True
        unknown = [False, False]
        for side, streams in enumerate(groups):
            for items in streams.values():
                for group in items:
                    if (not set(INVENTORY_REDIS_GROUP_FIELDS) <= group.keys()
                            or any(type(group[field]) is not str for field in ("name", "last-delivered-id"))
                            or any(type(group[field]) is not int for field in ("consumers", "pending"))
                            or any(group[field] is not None and type(group[field]) is not int
                                   for field in ("entries-read", "lag"))):
                        valid = False
                    unknown[side] |= any(field not in INVENTORY_REDIS_GROUP_FIELDS for field in group)
        if valid:
            a, b = groups
            aligned = a.keys() == b.keys() and all(len(items) == len(b[key]) for key, items in a.items())
            fields = dict.fromkeys(INVENTORY_REDIS_GROUP_FIELDS, False)
            if aligned:
                for field in fields:
                    fields[field] = all(group[field] == b[key][index][field]
                                        for key, items in a.items() for index, group in enumerate(items))
            summary["redis_group_fields"] = {"aligned": aligned, "fields": fields, "unknown_fields": unknown}
    return summary if closed_inventory_comparison(summary) else None


class Docker:
    def __init__(self, context, *, runner=subprocess.run):
        if not context or any(char.isspace() for char in context):
            raise QualificationError("An explicit Docker context is required")
        self.context, self.runner = context, runner
        self.deadline = None
        self.checkpoint = self.last_completed = None

    def call(self, *args, environment=None, timeout=120, absent=False):
        def failure(code, returncode=None):
            return DockerOperationError(code, returncode, operation=docker_operation(args),
                                        checkpoint=self.checkpoint, last_completed=self.last_completed)

        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError("Laboratory wall budget exhausted")
            timeout = min(timeout, remaining)
        try:
            result = self.runner(
                ["docker", "--context", self.context, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=environment,
            )
        except subprocess.TimeoutExpired:
            raise failure("docker_timeout") from None
        except OSError:
            raise failure("docker_process_error") from None
        if result.returncode:
            if absent and re.search(r"\bno such (?:container|network|volume|object)\b", result.stderr, re.I):
                self.last_completed = self.checkpoint
                return None
            raise failure("docker_nonzero", result.returncode)
        if len(result.stdout) > 4 * 1048576:
            raise failure("docker_output_budget", result.returncode)
        self.last_completed = self.checkpoint
        return result.stdout.strip()

    def inspect(self, kind, identifier, *, absent=False):
        result = self.call(kind, "inspect", identifier, absent=absent)
        return None if result is None else json.loads(result)[0]


class Laboratory:
    def __init__(self, repository, directory, profile, context, *, docker=None):
        self.repository = Path(repository).resolve()
        self.directory = Path(directory).absolute()
        self.profile, self.context = profile, context
        self.compose_file = self.repository / "deploy/qualification/compose.yaml"
        self.config_hash = hashlib.sha256(self.compose_file.read_bytes() + canonical_bytes(profile)).hexdigest()
        self.docker = docker or Docker(context)
        self.journal = None
        self.sender = None
        self.scenarios = []
        self.deadline = None
        self.failure = None
        self.stage = "scenario"
        self.pressure_section = None
        self.physical_section = None
        self.probe_section = None
        self.probe_operation = "unknown"
        self.probe_service = None
        self.probe_reason = self.probe_secondary_reason = None
        self.cold_section = self.cold_service = self.cold_target_service = self.cold_primary = None
        self.cold_operation = "unknown"

    def cold_checkpoint(self, step, *, operation=None, service=None):
        section = getattr(self, "cold_section", None)
        if (type(section) is not str or section not in COLD_STEPS or type(step) is not str
                or step not in COLD_STEPS[section]):
            return False
        self.stage = "cold_restore_" + section + "_" + step
        self.docker.checkpoint = self.stage
        operation = COLD_OPERATIONS.get(step, "unknown") if operation is None else operation
        self.cold_operation = operation if type(operation) is str and operation in DOCKER_OPERATION_NAMES else "unknown"
        if service is None:
            service = "ingest-worker" if step == "worker_inspect" else self.cold_target_service
        self.cold_service = service if type(service) is str and service in COLD_SERVICES else None
        return True

    def cold_phase(self, section, step, *, service=None):
        self.cold_section = section if type(section) is str and section in COLD_STEPS else None
        self.cold_target_service = service if type(service) is str and service in COLD_SERVICES else None
        self.cold_checkpoint(step)

    def cold_failure(self, exc, *, secondary=False):
        # Diagnostics must never replace the exception or cancellation being handled.
        try:
            value = cold_failure_evidence(exc, self.stage, self.cold_operation, self.cold_service,
                                          getattr(self.docker, "last_completed", None))
            if not closed_cold_evidence(value):
                return
            if self.failure is None:
                if len(canonical_bytes(value)) <= 2048:
                    self.failure = self.cold_primary = value
            elif (secondary and self.failure is self.cold_primary and closed_cold_evidence(self.failure)
                  and "secondary" not in self.failure):
                candidate = {**self.failure, "secondary": [value]}
                if (len(canonical_bytes(candidate)) > 2048
                        and "redis_group_fields" in candidate.get("inventory_comparison", {})):
                    candidate["inventory_comparison"] = {
                        key: item for key, item in candidate["inventory_comparison"].items()
                        if key != "redis_group_fields"}
                if len(canonical_bytes(candidate)) <= 2048:
                    self.failure = self.cold_primary = candidate
        except BaseException:
            pass

    def cold_export_failure(self, exc, code, output):
        # Only already-failed helpers use the existing bounded capture. No raw output is retained.
        try:
            if (type(self.stage) is not str or self.stage != "cold_restore_export_result"
                    or self.failure is not None):
                return
            self.cold_failure(exc)
            if self.failure is not self.cold_primary or not closed_cold_evidence(self.failure):
                return
            diagnostic = parse_export_diagnostic(output)
            from shadai.qualification.snapshot import closed_export_diagnostic

            if not closed_export_diagnostic(diagnostic):
                return
            value = {**self.failure, "helper_step": diagnostic["step"], "helper_reason": diagnostic["reason"]}
            if type(code) is int and 1 <= code <= 255:
                value["helper_exit_status"] = code
            if diagnostic["secondary"]:
                point = diagnostic["secondary"][0]
                value["secondary"] = [{**self.failure, "helper_step": point["step"],
                                       "helper_reason": point["reason"]}]
            primary = {key: item for key, item in value.items() if key != "secondary"}
            if (closed_cold_evidence(primary)
                    and all(closed_cold_evidence(item) for item in value.get("secondary", []))
                    and len(canonical_bytes(value)) <= 2048):
                self.failure = self.cold_primary = value
        except BaseException:
            pass

    def cold_inventory_failure(self, exc, source, restored):
        if self.failure is not None:
            return
        self.cold_failure(exc)
        if (type(exc) is not AssertionError or type(self.stage) is not str
                or self.stage != "cold_restore_inventory_compare_compare"
                or self.failure is not self.cold_primary or not closed_cold_evidence(self.failure)):
            return
        summary = cold_inventory_comparison(source, restored)
        if summary is not None:
            candidate = {**self.failure, "inventory_comparison": summary}
            if not closed_cold_evidence(candidate):
                return
            if len(canonical_bytes(candidate)) > 2048 and "redis_group_fields" in summary:
                candidate["inventory_comparison"] = {
                    key: item for key, item in summary.items() if key != "redis_group_fields"}
            if len(canonical_bytes(candidate)) <= 2048:
                self.failure = self.cold_primary = candidate

    @contextmanager
    def cold_diagnostics(self, section):
        previous = (self.cold_section, self.stage, getattr(self.docker, "checkpoint", None),
                    self.cold_operation, self.cold_service, self.cold_target_service,
                    getattr(self.docker, "last_completed", None))
        self.cold_phase(section, "budget" if type(section) is str and section == "entry" else "registry")
        try:
            yield
        except BaseException as exc:
            self.cold_failure(exc)
            raise
        finally:
            (self.cold_section, self.stage, self.docker.checkpoint, self.cold_operation,
             self.cold_service, self.cold_target_service, last_completed) = previous
            if self.cold_section is None:
                self.docker.last_completed = last_completed

    def probe_checkpoint(self, step, *, operation="unknown", service=None):
        if self.cold_checkpoint("registry" if type(step) is str and step == "worker_registry" else step,
                                operation=operation, service=service):
            return
        section = self.probe_section
        if type(section) is str and section in PROBE_STEPS and type(step) is str and step in PROBE_STEPS[section]:
            self.stage = "probes_" + section + "_" + step
            self.docker.checkpoint = self.stage
            self.probe_operation = (operation if type(operation) is str and operation in DOCKER_OPERATION_NAMES
                                    else "unknown")
            self.probe_service = service if type(service) is str and service in PROBE_SERVICES else None

    def probe_completed(self):
        if type(self.stage) is str and self.stage in PROBE_CHECKPOINTS:
            self.docker.last_completed = self.stage

    def probe_failure(self, exc, *, secondary=False):
        value = probe_failure_evidence(exc, self.stage, self.probe_operation, self.probe_service,
                                       getattr(self.docker, "last_completed", None), reason_code=self.probe_reason,
                                       secondary_reason=self.probe_secondary_reason)
        if self.failure is None:
            self.failure = value
        elif secondary:
            self.failure["secondary"] = [value]

    @contextmanager
    def probe_diagnostics(self, *, secondary=False):
        previous = (self.probe_section, self.stage, getattr(self.docker, "checkpoint", None),
                    self.probe_operation, self.probe_service, self.probe_reason, self.probe_secondary_reason)
        if self.probe_section is None:
            self.probe_section = "baseline"
        try:
            yield
        except BaseException as exc:
            self.probe_failure(exc, secondary=secondary)
            raise
        finally:
            (self.probe_section, self.stage, self.docker.checkpoint,
             self.probe_operation, self.probe_service, self.probe_reason, self.probe_secondary_reason) = previous

    def pressure_checkpoint(self, step):
        if self.cold_checkpoint(step):
            return
        if self.probe_section == "witness":
            operation = {"worker_inspect": "container_inspect", "capture": "container_inspect",
                         "inspect": "container_inspect", "create": "container_create", "start": "container_start",
                         "wait": "container_wait", "logs": "container_logs", "remove_inspect": "container_inspect",
                         "remove": "container_rm"}.get(step, "unknown") if type(step) is str else "unknown"
            self.probe_checkpoint(step, operation=operation)
        section = self.pressure_section
        if type(section) is str and section in PRESSURE_STEPS and type(step) is str and step in PRESSURE_STEPS[section]:
            self.stage = "pressure_" + section + "_" + step
            self.docker.checkpoint = self.stage
        else:
            self.physical_checkpoint(step)

    def physical_checkpoint(self, step):
        if self.cold_checkpoint(step):
            return
        section = getattr(self, "physical_section", None)
        if type(section) is str and section in PHYSICAL_STEPS and type(step) is str and step in PHYSICAL_STEPS[section]:
            self.stage = "physical_" + section + "_" + step
            self.docker.checkpoint = self.stage

    @contextmanager
    def physical_diagnostics(self, section):
        previous = self.physical_section, self.stage, getattr(self.docker, "checkpoint", None)
        self.physical_section = section if type(section) is str and section in PHYSICAL_STEPS else None
        try:
            yield
        except BaseException as exc:
            if self.failure is None:
                self.failure = failure_evidence(exc, "physical", self.stage)
            raise
        finally:
            self.physical_section, self.stage, self.docker.checkpoint = previous

    def physical_secondary(self, primary, secondary):
        if self.failure is None:
            self.failure = failure_evidence(primary, "physical", self.stage)
        self.failure["secondary"] = [failure_evidence(secondary, "physical", self.stage)]

    @contextmanager
    def pressure_diagnostics(self, section):
        previous = self.pressure_section, self.stage, getattr(self.docker, "checkpoint", None)
        self.pressure_section = section if type(section) is str and section in PRESSURE_STEPS else None
        try:
            yield
        except BaseException as exc:
            if self.failure is None:
                self.failure = failure_evidence(exc, "redis_pressure", self.stage)
            raise
        finally:
            self.pressure_section, self.stage, self.docker.checkpoint = previous

    def pressure_secondary(self, primary, secondary):
        if self.failure is None:
            self.failure = failure_evidence(primary, "redis_pressure", self.stage)
        self.failure["secondary"] = [failure_evidence(secondary, "redis_pressure", self.stage)]

    def remaining(self):
        if self.deadline is None:
            return self.profile["limits"]["max_wall_seconds"]
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise QualificationError("Laboratory wall budget exhausted")
        return remaining

    def local_deadline(self, seconds):
        return time.monotonic() + min(seconds, self.remaining())

    def sleep(self, seconds):
        time.sleep(min(seconds, self.remaining()))
        self.remaining()

    def retained_bytes(self):
        total, count = 0, 0
        for directory, directories, files in os.walk(self.directory, followlinks=False):
            self.remaining()
            for name in [*directories, *files]:
                metadata = (Path(directory) / name).lstat()
                if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                    raise QualificationError("Run artifacts must be regular files or directories without links")
                if stat.S_ISREG(metadata.st_mode):
                    total += metadata.st_size
                    count += 1
                    if count > 100000 or total > self.profile["limits"]["max_disk_bytes"]:
                        raise QualificationError("Cumulative run artifact budget exhausted")
        return total

    def artifact_remaining(self, reserve=0):
        available = self.profile["limits"]["max_disk_bytes"] - self.retained_bytes() - reserve
        if available <= 0:
            raise QualificationError("Cumulative run artifact budget exhausted")
        return available

    def prepare(self, resume=False):
        if platform.system() != "Linux" or os.getuid() == 0:
            raise QualificationError("Lab execution requires a nonroot Linux orchestrator")
        self.docker.call("info", "--format", "{{json .ServerVersion}}", timeout=20)
        factory = RunJournal.resume if resume else RunJournal.create
        self.journal = factory(self.directory, self.profile, self.config_hash, self.context)
        self.tenant = "q-" + self.journal.value["run_id"].replace("-", "")
        self.run_profile = {**self.profile, "installation": self.tenant}
        if resume:
            self.guard_all()
            self.verify_secrets()
            if json.loads((self.directory / "source.json").read_text()) != self.source_proof():
                raise QualificationError("Resume source or execution environment changed")
        else:
            self.make_secrets()
            atomic_json(self.directory / "profile.json", self.run_profile)
            atomic_json(self.directory / "source.json", self.source_proof())
        self.scenarios = (
            json.loads((self.directory / "report.json").read_text()).get("scenarios", [])
            if (self.directory / "report.json").exists()
            else []
        )

    def source_proof(self):
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repository,
            capture_output=True,
            text=True,
            check=True,
            timeout=min(10, self.remaining()),
        ).stdout.strip()
        files = [
            *self.repository.glob("src/**/*.py"),
            *self.repository.glob("docker/**"),
            *self.repository.glob("catalog/builtin/*.yaml"),
            self.compose_file,
        ]
        hashes = {
            str(path.relative_to(self.repository)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
            if path.is_file()
        }
        return {
            "revision": revision,
            "source_sha256": hashes,
            "environment": {
                "system": platform.system(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "runtime_production_uid": 10001,
                "docker_context": self.context,
            },
        }

    def make_secrets(self):
        directory = self.directory / "secrets"
        directory.mkdir(mode=0o700)
        values = {
            name: secrets.token_urlsafe(48)
            for name in ("pg_password", "redis_password", "redis_pressure_password", "ch_password", "jwt_secret")
        }
        values["encryption_key"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        hashes = {}
        for name, value in values.items():
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as file:
                file.write(value)
            hashes[name] = hashlib.sha256(value.encode()).hexdigest()
        atomic_json(self.directory / "secret-hashes.json", hashes)

    def verify_secrets(self):
        expected = json.loads((self.directory / "secret-hashes.json").read_text())
        actual = {
            name: hashlib.sha256((self.directory / "secrets" / name).read_bytes()).hexdigest() for name in expected
        }
        if actual != expected:
            raise QualificationError("Lab key material changed after journaling")

    def environment(self, role="source"):
        return {
            **os.environ,
            "SHADAI_QUAL_REPO": str(self.repository),
            "SHADAI_QUAL_DIR": str(self.directory),
            "SHADAI_QUAL_RUN": self.journal.value["run_id"],
            "SHADAI_QUAL_ROLE": role,
            "SHADAI_QUAL_TENANT": self.tenant,
            "SHADAI_QUAL_UID": str(os.getuid()),
            "SHADAI_QUAL_GID": str(os.getgid()),
        }

    def compose(self, *args, role="source", timeout=120):
        self.guard_all()
        project = self.journal.value["projects"][role]
        if args:
            self.physical_checkpoint(args[0])
        self.probe_checkpoint("launch", operation="compose_up", service="probe-ingest-peer")
        return self.docker.call(
            "compose",
            "--project-name",
            project,
            "--file",
            str(self.compose_file),
            "--env-file",
            str(self.directory / "empty.env"),
            *args,
            environment=self.environment(role),
            timeout=min(timeout, self.remaining()),
        )

    def discover(self, role="source"):
        project = self.journal.value["projects"][role]
        records = []
        for kind, command in (("container", "ps"), ("network", "network"), ("volume", "volume")):
            args = [command, "-aq"] if kind == "container" else [command, "ls", "-q"]
            self.pressure_checkpoint("discover_list")
            self.probe_checkpoint("discover_list", operation=docker_operation(args))
            identifiers = self.docker.call(*args, "--filter", "label=com.docker.compose.project=" + project)
            for identifier in identifiers.splitlines():
                self.pressure_checkpoint("discover_inspect")
                self.probe_checkpoint("discover_inspect", operation=docker_operation((kind, "inspect")))
                inspected = self.docker.inspect(kind, identifier)
                self.probe_checkpoint("discover_identity")
                labels = inspected.get("Config", {}).get("Labels", {}) if kind == "container" else inspected["Labels"]
                actual_role = labels.get(LABEL + "role")
                if actual_role not in {role, "pressure"}:
                    raise QualificationError("Foreign resource shares the lab project name")
                records.append(resource_identity(kind, inspected, self.journal.value["run_id"], actual_role, project))
                self.probe_completed()
        self.probe_checkpoint("discover_save")
        self.journal.add_resources(records)
        self.probe_completed()

    def guard_all(self):
        if self.journal:
            for record in self.journal.value["resources"]:
                self.physical_checkpoint("guard_inspect")
                self.probe_checkpoint("guard_inspect", operation=docker_operation((record["kind"], "inspect")),
                                      service=record.get("service"))
                inspected = self.docker.inspect(record["kind"], record["id"])
                verify_resource(record, inspected)
                self.probe_completed()

    def containers(self, services, role="source"):
        if not set(services) <= SERVICES | TOOLS:
            raise QualificationError("Unknown lab service")
        records = [
            item
            for item in self.journal.value["resources"]
            if item["kind"] == "container"
            and item["project"] == self.journal.value["projects"][role]
            and item["service"] in services
        ]
        if {item["service"] for item in records} != set(services):
            raise QualificationError("Required lab container identity is absent")
        return records

    def change(self, operation, services, role="source"):
        self.probe_checkpoint("registry")
        for record in self.containers(services, role):
            self.pressure_checkpoint("inspect")
            self.probe_checkpoint("inspect", operation="container_inspect", service=record["service"])
            inspected = self.docker.inspect("container", record["id"])
            verify_resource(record, inspected)
            self.probe_completed()
            self.pressure_checkpoint("stop")
            self.probe_checkpoint(operation, operation=docker_operation(("container", operation)),
                                  service=record["service"])
            self.docker.call("container", operation, record["id"])
            self.pressure_checkpoint("reinspect")
            self.probe_checkpoint("reinspect", operation="container_inspect", service=record["service"])
            state = self.docker.inspect("container", record["id"])["State"]
            if operation == "stop" and state["Running"]:
                raise QualificationError("Container did not stop")
            self.probe_completed()

    def inspector(self, action, *, case="baseline", role="source"):
        name = self.journal.value["projects"][role] + "-inspector-" + uuid4().hex[:12]
        self.compose(
            "run",
            "--no-deps",
            "-d",
            "--name",
            name,
            "inspector",
            "python",
            "-m",
            "shadai.qualification",
            "fixture",
            action,
            "--run-id",
            self.journal.value["run_id"],
            "--case",
            case,
            role=role,
        )
        # Compose can build this one-off image and mix progress with its ID on
        # stdout. Resolve our generated name, then use only the verified ID.
        self.physical_checkpoint("name_inspect")
        inspected = self.docker.inspect("container", name)
        self.cold_checkpoint("identity", service="inspector")
        record = resource_identity(
            "container", inspected, self.journal.value["run_id"], role, self.journal.value["projects"][role]
        )
        image = inspected.get("Image")
        if (record["service"] != "inspector" or inspected.get("Name") != "/" + name or
                type(record["id"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record["id"]) or
                type(image) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
            raise QualificationError("Inspector identity proof is invalid")
        identifier = record["id"]
        self.journal.add_resources([record])
        primary = None
        try:
            self.physical_checkpoint("wait")
            code = self.docker.call("container", "wait", identifier, timeout=180)
            self.physical_checkpoint("logs")
            output = self.docker.call("container", "logs", identifier)
            self.cold_checkpoint("result", service="inspector")
            if int(code) != 0:
                raise QualificationError("Lab inspector failed its requested proof")
            return json.loads(output.splitlines()[-1])
        except BaseException as exc:
            primary = exc
            if type(self.cold_section) is str and self.cold_section in COLD_STEPS:
                self.cold_failure(exc)
            if self.physical_section is not None and self.failure is None:
                self.failure = failure_evidence(exc, "physical", self.stage)
            raise
        finally:
            try:
                self.remove(record)
            except BaseException as secondary:
                if type(self.cold_section) is str and self.cold_section in COLD_STEPS:
                    self.cold_failure(secondary, secondary=primary is not None)
                if primary is None or self.physical_section is None:
                    raise
                self.physical_secondary(primary, secondary)
                if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                    raise
                primary.add_note("physical_inspector_cleanup_failed")

    def remove(self, record, *, volumes=False):
        validate_helper_record(record)
        if record["kind"] == "volume" and not volumes:
            return
        self.pressure_checkpoint("remove_inspect")
        if type(record) is dict:
            self.cold_checkpoint("remove_inspect", operation=docker_operation((record.get("kind"), "inspect")))
        inspected = self.docker.inspect(record["kind"], record["id"], absent=True)
        if inspected is not None:
            verify_resource(record, inspected)
            self.pressure_checkpoint("remove")
            if type(record) is dict:
                self.cold_checkpoint("remove", operation=docker_operation((record.get("kind"), "rm")))
            self.docker.call(record["kind"], "rm", record["id"])
        self.journal.value["resources"] = [item for item in self.journal.value["resources"] if item != record]
        self.journal.save()

    def wait_ready(self, role="source"):
        self.cold_checkpoint("deadline", operation="unknown")
        deadline = self.local_deadline(120)
        self.cold_checkpoint("port", operation="unknown")
        port = self.compose("port", "api", "8443", role=role)
        if not port.startswith("127.0.0.1:"):
            raise QualificationError("Lab API is not published on an ephemeral loopback port")
        url = "http://" + port
        transport = HttpTransport()
        while time.monotonic() < deadline:
            self.cold_checkpoint("request", operation="unknown")
            status, _, error = transport.request(url + "/ready", deadline=deadline, timeout=3)
            if status == 200 and error == "none":
                return url
            self.cold_checkpoint("wait", operation="unknown")
            self.sleep(min(1, max(0, deadline - time.monotonic())))
        raise QualificationError("Lab API readiness prerequisite failed")

    def send(self, url, case, *, total=None):
        profile = self.run_profile
        if total is not None:
            profile = {**profile, "load": {**profile["load"], "total_events": total}}
        used = sum(json.loads(path.read_text()).get("requests", 0) for path in self.directory.glob("*-load.json"))
        available = self.profile["limits"]["max_requests"] - used
        if available <= 0:
            raise QualificationError("Laboratory cumulative HTTP request budget exhausted")
        profile = {
            **profile,
            "limits": {**profile["limits"], "max_wall_seconds": self.remaining(), "max_requests": available},
        }
        collector = "qualification-" + self.journal.value["run_id"].replace("-", "")
        self.sender = LoadSender(profile, self.journal.value["run_id"], case, self.directory, collector)
        try:
            return self.sender.run(url, (self.directory / "collector-key").read_text(), deadline=self.deadline)
        finally:
            self.sender = None

    def drain(self, case, role="source"):
        self.cold_checkpoint("deadline", operation="unknown")
        deadline = self.local_deadline(self.profile["load"]["drain_timeout_seconds"])
        while time.monotonic() < deadline:
            result = self.inspector("verify_load", case=case, role=role)
            if not (result["missing"] or result["missing_receipts"] or result["missing_correlations"]):
                return result
            self.cold_checkpoint("sleep", operation="unknown")
            self.sleep(min(2, max(0, deadline - time.monotonic())))
        raise AssertionError("Accepted logical events did not reach receipts and correlation within the budget")

    def record(self, scenario, **measurements):
        self.scenarios = [item for item in self.scenarios if item["scenario"] != scenario]
        self.scenarios.append(
            {"scenario": scenario, "required": True, "executed": True, "status": "passed", "measurements": measurements}
        )
        self.journal.phase(scenario, completed=True)
        self.write_report()

    def write_report(self, missing=None):
        result = report(
            self.profile,
            self.scenarios,
            evidence={
                "run_id": self.journal.value["run_id"],
                "installation": self.tenant,
                "source": json.loads((self.directory / "source.json").read_text()),
                "laboratory_only": True,
                "production_rpo_rto": "not_evaluated",
                **({"failure": self.failure} if self.failure is not None else {}),
            },
            missing=missing,
        )
        atomic_json(self.directory / "report.json", result)
        return result["exit_code"]

    def execute(self, resume=False):
        self.deadline = time.monotonic() + self.profile["limits"]["max_wall_seconds"]
        self.docker.deadline = self.deadline
        self.prepare(resume)
        (self.directory / "empty.env").touch(mode=0o600, exist_ok=True)
        self.failure = None
        try:
            if not resume:
                self.journal.phase("starting")
                self.stage = "starting_compose"
                try:
                    self.compose("up", "-d", "--build", *sorted(SERVICES), timeout=600)
                except BaseException as exc:
                    self.failure = failure_evidence(exc, "starting", self.stage)
                    self.stage = "starting_discover"
                    try:
                        self.discover()
                    except BaseException as secondary:
                        self.failure["secondary"] = [failure_evidence(secondary, "starting", self.stage)]
                        if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                            raise
                    raise
                else:
                    self.stage = "starting_discover"
                    self.discover()
            if "initialized" not in self.journal.value["completed"]:
                self.stage = "initialize_stop"
                self.change("stop", WRITERS)
                self.stage = "initialize_inspector"
                self.inspector("initialize")
                self.journal.phase("initialized", completed=True)
                self.stage = "initialize_start"
                self.change("start", WRITERS)
            self.stage = "readiness"
            url = self.wait_ready()
            if not (self.directory / "collector-key").exists():
                self.stage = "enroll"
                self.inspector("enroll")
            self.stage = "scenario"
            completed = set(self.journal.value["completed"])
            if "baseline" in self.profile["scenarios"] and "baseline" not in completed:
                self.journal.phase("baseline")
                load = self.send(url, "baseline")
                assert load["accepted"] == self.profile["load"]["total_events"]
                persisted = self.drain("baseline")
                self.record("baseline", load=load, verification=persisted)
            if "pause_ingest" in self.profile["scenarios"] and "pause_ingest" not in completed:
                self.journal.phase("pause_ingest")
                self.change("stop", {"ingest-worker"})
                load = self.send(url, "pause_ingest", total=20)
                backlog = self.inspector("inventory", case="paused")["pipeline"]
                assert any(
                    row["undelivered"]
                    for stage in backlog["stages"]
                    for row in stage["streams"]
                    if stage["stage"] == "ingest"
                )
                self.change("start", {"ingest-worker"})
                before = time.monotonic()
                self.record(
                    "pause_ingest",
                    load=load,
                    backlog=backlog,
                    verification=self.drain("pause_ingest"),
                    recovery_seconds=time.monotonic() - before,
                )
            if "correlation_outage" in self.profile["scenarios"] and "correlation_outage" not in completed:
                self.journal.phase("correlation_outage")
                self.change("stop", {"correlation-worker"})
                load = self.send(url, "correlation_outage", total=20)
                deadline = self.local_deadline(60)
                while time.monotonic() < deadline:
                    backlog = self.inspector("inventory", case="correlation-outage")["pipeline"]
                    if any(
                        row["undelivered"]
                        for stage in backlog["stages"]
                        for row in stage["streams"]
                        if stage["stage"] == "correlation"
                    ):
                        break
                    self.sleep(min(1, max(0, deadline - time.monotonic())))
                else:
                    raise AssertionError("Correlation outage did not retain observable backlog")
                self.change("start", {"correlation-worker"})
                before = time.monotonic()
                self.record(
                    "correlation_outage",
                    load=load,
                    backlog=backlog,
                    verification=self.drain("correlation_outage"),
                    recovery_seconds=time.monotonic() - before,
                )
            self.execute_special(url, completed)
            return self.write_report()
        except (KeyboardInterrupt, BaseException) as exc:
            if self.sender:
                self.sender.stop()
            self.journal.value["cancelled"] = isinstance(exc, (KeyboardInterrupt, SystemExit))
            phase = self.journal.value["phase"]
            if self.failure is None:
                self.failure = failure_evidence(exc, phase, self.stage)
            if phase in SCENARIOS:
                self.scenarios = [item for item in self.scenarios if item["scenario"] != phase]
                self.scenarios.append(
                    {
                        "scenario": phase,
                        "required": True,
                        "executed": True,
                        "status": "failed" if isinstance(exc, AssertionError) else "not_evaluated",
                        "reason": safe_exception_type(exc),
                    }
                )
            self.journal.phase("cancelled" if self.journal.value["cancelled"] else "interrupted")
            return self.write_report([phase])

    def execute_special(self, url, completed):
        for scenario in ("reclaim", "redis_pressure", "probes", "physical", "cold_restore"):
            if scenario in self.profile["scenarios"] and scenario not in completed:
                self.journal.phase(scenario)
                if scenario == "cold_restore":
                    with self.cold_diagnostics("entry"):
                        self.remaining()
                        getattr(self, "experiment_" + scenario)(url)
                else:
                    self.remaining()
                    getattr(self, "experiment_" + scenario)(url)

    def experiment_reclaim(self, url):
        self.change("stop", {"clickhouse"})
        load = self.send(url, "reclaim", total=20)
        deadline = self.local_deadline(60)
        while time.monotonic() < deadline:
            pipeline = self.inspector("pipeline")["pipeline"]
            if any(
                row["pending"] for stage in pipeline["stages"] if stage["stage"] == "ingest" for row in stage["streams"]
            ):
                break
            self.sleep(min(1, max(0, deadline - time.monotonic())))
        else:
            raise AssertionError("No real consumer PEL was witnessed before termination")
        self.change("stop", {"ingest-worker"})
        self.change("start", {"clickhouse"})
        self.change("start", {"ingest-worker"})
        before = time.monotonic()
        persisted = self.drain("reclaim")
        self.record(
            "reclaim",
            load=load,
            witnessed_pel=pipeline,
            terminated_after_witness=True,
            verification=persisted,
            recovery_seconds=time.monotonic() - before,
        )

    def create_export_resource(self, kind, name, args, *, image=None):
        """Capture an owned creation even when its CLI response fails or is cancelled."""
        project = self.journal.value["projects"]["source"]
        suffix = r"_export_[0-9a-f]{32}" if kind == "volume" else r"-export-[0-9a-f]{32}"
        self.cold_checkpoint("name", operation="unknown")
        if kind not in {"container", "volume"} or not re.fullmatch(re.escape(project) + suffix, name) or \
                (kind == "container" and (type(image) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", image))):
            raise QualificationError("Export resource creation contract is invalid")
        self.pressure_checkpoint("volume_absence" if kind == "volume" else "name_inspect")
        if self.docker.inspect(kind, name, absent=True) is not None:
            raise QualificationError("Export resource name already exists")
        primary = None
        record = None
        try:
            self.pressure_checkpoint("volume_create" if kind == "volume" else "create")
            self.docker.call(*args)
        except BaseException as error:
            primary = error
            if type(self.cold_section) is str and self.cold_section in COLD_STEPS:
                self.cold_failure(error)
            if self.pressure_section == "export" and self.failure is None:
                self.failure = failure_evidence(error, "redis_pressure", self.stage)
        try:
            self.pressure_checkpoint("volume_capture" if kind == "volume" else "capture")
            inspected = self.docker.inspect(kind, name, absent=True)
            if inspected is None:
                if primary is None:
                    raise QualificationError("Created export resource identity is absent")
            else:
                record = resource_identity(kind, inspected, self.journal.value["run_id"], "source", project)
                if (kind == "volume" and record["id"] != name) or (kind == "container" and (
                    inspected.get("Name") != "/" + name or inspected.get("Image") != image or
                    type(record["id"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record["id"]))):
                    raise QualificationError("Export resource identity is invalid")
                self.journal.add_resources([record])
        except BaseException as secondary:
            if primary is None:
                raise
            if type(self.cold_section) is str and self.cold_section in COLD_STEPS:
                self.cold_failure(secondary, secondary=True)
            primary.add_note("owned_export_capture_failed")
            if self.pressure_section == "export":
                self.pressure_secondary(primary, secondary)
            if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                raise
        if primary is not None:
            raise primary
        return record

    def run_owned(self, command, *, role="source", volumes=(), root=False, caps=(), archive=None, export_name=None):
        project = self.journal.value["projects"][role]
        self.probe_checkpoint("worker_registry", service="ingest-worker")
        worker = self.containers({"ingest-worker"})[0]
        self.pressure_checkpoint("worker_inspect")
        inspected = self.docker.inspect("container", worker["id"])
        verify_resource(worker, inspected)
        args = [
            "container",
            "create",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--user",
            "0:0" if root else f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,size=1073741824",
            "--label",
            LABEL + "run=" + self.journal.value["run_id"],
            "--label",
            LABEL + "role=" + role,
            "--label",
            "com.docker.compose.project=" + project,
            "--entrypoint",
            "python",
        ]
        for capability in caps:
            self.cold_checkpoint("capability", operation="unknown")
            if capability not in {"DAC_READ_SEARCH", "CHOWN", "FOWNER"}:
                raise QualificationError("Unapproved archive helper capability")
            args.extend(["--cap-add", capability])
        for volume, destination, readonly in volumes:
            self.pressure_checkpoint("volume_inspect")
            current = self.docker.inspect("volume", volume["id"])
            verify_resource(volume, current)
            args.extend(
                [
                    "--mount",
                    "type=volume,src=" + volume["id"] + ",dst=" + destination + (",readonly" if readonly else "")
                    + (",volume-nocopy" if export_name and destination == "/export" else ""),
                ]
            )
        if archive:
            self.cold_checkpoint("archive", operation="unknown")
            path = self.directory / archive
            if path.is_symlink() or path.parent != self.directory or not path.is_file():
                raise QualificationError("Archive must be a regular owned-run file")
            args.extend(["--mount", "type=bind,src=" + str(path) + ",dst=/archive.tar,readonly"])
        args.extend([inspected["Image"], *command])
        if export_name is not None:
            if role != "source" or not re.fullmatch(re.escape(project) + r"-export-[0-9a-f]{32}", export_name):
                raise QualificationError("Export helper name is invalid")
            args[2:2] = ["--name", export_name]
            return self.create_export_resource("container", export_name, args, image=inspected["Image"])
        self.pressure_checkpoint("create")
        identifier = self.docker.call(*args)
        self.pressure_checkpoint("capture")
        record = resource_identity(
            "container", self.docker.inspect("container", identifier), self.journal.value["run_id"], role, project
        )
        self.journal.add_resources([record])
        return record

    def helper_result(self, record, *, copy_archive=None):
        self.pressure_checkpoint("inspect")
        inspected = self.docker.inspect("container", record["id"])
        verify_resource(record, inspected)
        self.pressure_checkpoint("start")
        self.docker.call("container", "start", record["id"])
        self.pressure_checkpoint("wait")
        code = int(self.docker.call("container", "wait", record["id"], timeout=180))
        self.pressure_checkpoint("logs")
        output = self.docker.call("container", "logs", record["id"])
        if code != 0:
            self.cold_checkpoint("result", operation="unknown")
            error = QualificationError("Archive helper failed")
            self.cold_export_failure(error, code, output)
            raise error
        self.cold_checkpoint("result", operation="unknown")
        self.probe_checkpoint("result")
        result = json.loads(output.splitlines()[-1])
        self.probe_completed()
        if copy_archive:
            self.pressure_checkpoint("copy_inspect")
            verify_resource(record, self.docker.inspect("container", record["id"]))
            destination = self.directory / copy_archive
            if destination.exists() or destination.is_symlink():
                raise QualificationError("Archive destination already exists")
            self.cold_checkpoint("copy_budget", operation="unknown")
            if type(result.get("bytes")) is not int or not 0 < result["bytes"] <= self.artifact_remaining():
                raise QualificationError("Cold archive exceeds cumulative remaining artifact budget")
            self.pressure_checkpoint("copy")
            self.docker.call("container", "cp", record["id"] + ":/export/archive.tar", str(destination))
            self.cold_checkpoint("copy_size", operation="unknown")
            if destination.is_symlink() or destination.stat().st_size != result["bytes"]:
                raise QualificationError("Copied archive size differs from the owned helper proof")
            destination.chmod(0o600)
            self.cold_checkpoint("retained", operation="unknown")
            self.retained_bytes()
        self.remove(record)
        return result

    def volume(self, service, role="source"):
        container = self.containers({service}, role)[0]
        self.pressure_checkpoint("source_inspect")
        inspected = self.docker.inspect("container", container["id"])
        verify_resource(container, inspected)
        mounts = [item for item in inspected["Mounts"] if item["Type"] == "volume"]
        if len(mounts) != 1:
            raise QualificationError("Store volume mapping is not exact")
        return next(
            item
            for item in self.journal.value["resources"]
            if item["kind"] == "volume" and item["id"] == mounts[0]["Name"]
        )

    def archive_store(self, service):
        from shadai.qualification.snapshot import digest_file

        self.cold_checkpoint("budget", operation="unknown")
        archive_limit = min(self.artifact_remaining(), EXPORT_ARCHIVE_LIMIT)
        available = archive_limit - EXPORT_METADATA_MARGIN
        if available <= 0:
            raise QualificationError("Cumulative run artifact budget exhausted")
        volume = self.volume(service)
        container = self.containers({service})[0]
        self.pressure_checkpoint("stopped_inspect")
        if self.docker.inspect("container", container["id"])["State"]["Running"]:
            raise QualificationError("A cold snapshot requires verified stopped stores")
        name = service + "-cold.tar"
        project = self.journal.value["projects"]["source"]
        output_name = project + "_export_" + uuid4().hex
        output = self.create_export_resource("volume", output_name, [
            "volume", "create", "--label", LABEL + "run=" + self.journal.value["run_id"],
            "--label", LABEL + "role=source", "--label", "com.docker.compose.project=" + project,
            "--label", "com.docker.compose.volume=archive-export", output_name,
        ])
        record = self.run_owned(
            [
                "-c",
                EXPORT_SNAPSHOT_CODE,
                str(archive_limit),
                "snapshot",
                "export",
                "--archive",
                "/export/archive.tar",
                "--max-bytes",
                str(available),
            ],
            volumes=[(volume, "/volume", True), (output, "/export", False)],
            root=True,
            caps=["DAC_READ_SEARCH"],
            export_name=project + "-export-" + uuid4().hex,
        )
        result = self.helper_result(record, copy_archive=name)
        self.pressure_checkpoint("validate")
        self.cold_checkpoint("hash", operation="unknown")
        if digest_file(self.directory / name) != result["sha256"]:
            raise QualificationError("Copied cold archive does not match the helper manifest")
        self.remove(output, volumes=True)
        return {**result, "archive": name, "source_volume": volume}

    def fresh_restore_volume(self, source, *, service):
        self.pressure_checkpoint("validate")
        archive = self.directory / source["archive"]
        if (
            archive.parent != self.directory
            or archive.is_symlink()
            or not archive.is_file()
            or archive.stat().st_size != source["bytes"]
        ):
            raise QualificationError("Import archive differs from its exact owned size proof")
        self.cold_checkpoint("retained", operation="unknown")
        self.retained_bytes()
        suffix = {
            "postgres": "pg_data",
            "clickhouse": "ch_data",
            "redis": "redis_data",
            "labredis-pressure": "pressure_data",
        }[service]
        project = self.journal.value["projects"]["restore"]
        name = project + "_" + suffix
        self.pressure_checkpoint("volume_absence")
        if self.docker.inspect("volume", name, absent=True) is not None:
            raise QualificationError("Restore volume name already exists; fresh empty volume required")
        role = "pressure" if service == "labredis-pressure" else "restore"
        self.pressure_checkpoint("volume_create")
        self.docker.call(
            "volume",
            "create",
            "--label",
            LABEL + "run=" + self.journal.value["run_id"],
            "--label",
            LABEL + "role=" + role,
            "--label",
            "com.docker.compose.project=" + project,
            "--label",
            "com.docker.compose.volume=" + suffix,
            name,
        )
        self.pressure_checkpoint("volume_capture")
        record = resource_identity(
            "volume", self.docker.inspect("volume", name), self.journal.value["run_id"], role, project
        )
        self.journal.add_resources([record])
        helper = self.run_owned(
            [
                "-m",
                "shadai.qualification",
                "snapshot",
                "import",
                "--archive",
                "/archive.tar",
                "--sha256",
                source["sha256"],
                "--max-bytes",
                str(self.profile["limits"]["max_disk_bytes"]),
            ],
            role="restore",
            volumes=[(record, "/volume", False)],
            root=True,
            caps=["DAC_READ_SEARCH", "CHOWN", "FOWNER"],
            archive=source["archive"],
        )
        self.helper_result(helper)
        return record

    def experiment_cold_restore(self, url):
        with self.cold_diagnostics("writers_stop"):
            return self._experiment_cold_restore(url)

    def _experiment_cold_restore(self, url):
        self.change("stop", WRITERS)
        self.cold_phase("seed_pending", "run", service="inspector")
        fixture = self.inspector("seed_pending")
        self.cold_checkpoint("pel", operation="unknown")
        assert fixture["pel_witnessed"]
        self.cold_phase("redis_persistence", "budget", service="inspector")
        self.remaining()
        self.cold_checkpoint("run", service="inspector")
        persistence = self.inspector("redis_persistence")
        self.cold_checkpoint("complete", operation="unknown", service="inspector")
        self.remaining()
        if (type(persistence) is not dict or any(type(key) is not str for key in persistence)
                or persistence.keys() != {"redis_persistence_complete"}
                or persistence["redis_persistence_complete"] is not True):
            raise QualificationError("Redis persistence completion proof refused")
        self.cold_phase("inventory_source", "run", service="inspector")
        self.inspector("inventory", case="source")
        self.cold_phase("stores_stop", "registry")
        self.change("stop", STORES)
        before = time.monotonic()
        archives = {}
        for service in sorted(STORES):
            self.cold_phase("export", "budget", service=service)
            archives[service] = self.archive_store(service)
        self.cold_phase("manifest", "write")
        atomic_json(
            self.directory / "cold-manifest.json",
            {
                "schema": 1,
                "run_id": self.journal.value["run_id"],
                "config_sha256": self.config_hash,
                "secret_hashes": json.loads((self.directory / "secret-hashes.json").read_text()),
                "archives": archives,
                "pending_fixture": fixture,
            },
        )
        self.cold_phase("secrets", "verify")
        self.verify_secrets()
        for service, archive in archives.items():
            self.cold_phase("import", "validate", service=service)
            self.fresh_restore_volume(archive, service=service)
        self.cold_phase("stores_start", "up")
        primary = None
        try:
            self.compose("up", "-d", "--wait", "--wait-timeout", "180", *sorted(STORES), role="restore", timeout=180)
        except BaseException as exc:
            primary = exc
            self.cold_failure(exc)
            raise
        finally:
            try:
                self.discover("restore")
            except BaseException as secondary:
                self.cold_failure(secondary, secondary=primary is not None)
                raise
        self.cold_phase("inventory_restore", "run", service="inspector")
        self.inspector("inventory", case="restore", role="restore")
        self.cold_phase("inventory_compare", "read_source")
        source = json.loads((self.directory / "source-inventory.json").read_text())
        self.cold_checkpoint("read_restore", operation="unknown")
        restored = json.loads((self.directory / "restore-inventory.json").read_text())
        self.cold_checkpoint("compare", operation="unknown")
        try:
            assert source == restored, "Exact cold source/restore inventories differ before worker startup"
        except AssertionError as exc:
            try:
                self.cold_inventory_failure(exc, source, restored)
            except BaseException:
                pass
            raise
        self.cold_phase("writers_start", "up")
        primary = None
        try:
            self.compose("up", "-d", *sorted(WRITERS), role="restore", timeout=180)
        except BaseException as exc:
            primary = exc
            self.cold_failure(exc)
            raise
        finally:
            try:
                self.discover("restore")
            except BaseException as secondary:
                self.cold_failure(secondary, secondary=primary is not None)
                raise
        self.cold_phase("readiness", "deadline")
        restored_url = self.wait_ready("restore")
        # Reclaimed pending work and a fresh scoped event must both persist after startup.
        self.cold_phase("fresh_send", "send")
        fresh = self.send(restored_url, "restored-fresh", total=10)
        self.cold_phase("fresh_accepted", "verify")
        self.verify_fresh_restore(fresh)
        self.cold_phase("fresh_verify", "drain", service="inspector")
        verification = self.drain("restored-fresh", "restore")
        self.cold_phase("fresh_receipts", "verify")
        self.verify_fresh_restore(fresh, verification)
        self.cold_phase("record", "write")
        self.record(
            "cold_restore",
            exact_inventory_before_workers=True,
            pending_fixture=fixture,
            fresh_load=fresh,
            fresh_verification=verification,
            measured_restore_seconds=time.monotonic() - before,
            production_rpo_rto="not_evaluated",
        )

    @staticmethod
    def verify_fresh_restore(fresh, verification=None):
        identifiers = fresh["accepted_scoped_ids"]
        assert type(fresh["accepted"]) is int and fresh["accepted"] == 10
        assert len(identifiers) == len(set(identifiers)) == 10
        if verification is not None:
            assert verification["expected_logical_events"] == 11
            assert verification["persisted"] == verification["receipts"] == verification["correlation_receipts"] == 11
            assert not any(verification[key] for key in ("missing", "missing_receipts", "missing_correlations"))
            assert verification["restored_pending_fixture_persisted"] is True

    def experiment_redis_pressure(self, url):
        import xml.etree.ElementTree as ET

        phases = []
        (self.directory / "pressure-reports").mkdir(mode=0o700, exist_ok=True)
        (self.directory / "pressure-artifacts").mkdir(mode=0o700, exist_ok=True)
        for mode in ("seed", "assert"):
            with self.pressure_diagnostics(mode):
                role = "source" if mode == "seed" else "restore"
                if mode == "assert":
                    with self.pressure_diagnostics("stop"):
                        self.change("stop", {"labredis-pressure"})
                    with self.pressure_diagnostics("export"):
                        archive = self.archive_store("labredis-pressure")
                    with self.pressure_diagnostics("import"):
                        self.fresh_restore_volume(archive, service="labredis-pressure")
                    with self.pressure_diagnostics("restore"):
                        self.pressure_checkpoint("up")
                        primary = None
                        try:
                            self.compose("up", "-d", "--wait", "--wait-timeout", "60", "labredis-pressure",
                                         role="restore")
                        except BaseException as exc:
                            primary = exc
                            if self.failure is None:
                                self.failure = failure_evidence(exc, "redis_pressure", self.stage)
                            raise
                        finally:
                            try:
                                self.pressure_checkpoint("discover_list")
                                self.discover("restore")
                            except BaseException as secondary:
                                if primary is None:
                                    raise
                                self.pressure_secondary(primary, secondary)
                                if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                                    raise
                                primary.add_note("pressure_restore_discover_failed")
                name = self.journal.value["projects"][role] + "-pressure-" + mode
                service = "pressure-test" if mode == "seed" else "pressure-assert"
                output = "/qualification/pressure-seed.xml" if mode == "seed" else "/reports/pressure-assert.xml"
                self.pressure_checkpoint("name_inspect")
                if self.docker.inspect("container", name, absent=True) is not None:
                    raise QualificationError("Pressure helper name already exists")
                self.pressure_checkpoint("launch")
                self.compose(
                    "run",
                    "--build",
                    "--no-deps",
                    "-d",
                    "--name",
                    name,
                    "-e",
                    "SHADAI_REDIS_PRESSURE_MODE=" + mode,
                    service,
                    "python",
                    "-m",
                    "pytest",
                    "-q",
                    "-m",
                    "redis_pressure",
                    "-p",
                    "no:cacheprovider",
                    "--junitxml=" + output,
                    role=role,
                )
                # Build progress is not an identity; resolve the exact generated name.
                self.pressure_checkpoint("capture")
                inspected = self.docker.inspect("container", name)
                record = resource_identity(
                    "container", inspected, self.journal.value["run_id"], "pressure",
                    self.journal.value["projects"][role],
                )
                image = inspected.get("Image")
                if (record["service"] != service or inspected.get("Name") != "/" + name or
                        type(record["id"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record["id"]) or
                        type(image) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
                    raise QualificationError("Pressure helper identity proof is invalid")
                identifier = record["id"]
                self.journal.add_resources([record])

                def cleanup_pressure():
                    self.pressure_checkpoint("cleanup_inspect")
                    current = self.docker.inspect("container", identifier, absent=True)
                    if current is not None:
                        verify_resource(record, current)
                        if current.get("Name") != "/" + name or current.get("Image") != image:
                            raise QualificationError("Pressure helper name or image changed")
                    self.remove(record)

                primary = None
                try:
                    self.pressure_checkpoint("wait")
                    code = int(self.docker.call("container", "wait", identifier, timeout=180))
                    self.pressure_checkpoint("reinspect")
                    current = self.docker.inspect("container", identifier)
                    verify_resource(record, current)
                    if current.get("Name") != "/" + name or current.get("Image") != image:
                        raise QualificationError("Pressure helper name or image changed")
                except BaseException as exc:
                    primary = exc
                    if self.failure is None:
                        self.failure = failure_evidence(exc, "redis_pressure", self.stage)
                    raise
                finally:
                    try:
                        cleanup_pressure()
                    except BaseException as secondary:
                        if primary is None:
                            raise
                        self.pressure_secondary(primary, secondary)
                        if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                            raise
                        primary.add_note("Pressure helper cleanup refused; owned journal record retained")
                self.pressure_checkpoint("junit")
                relative = ("pressure-artifacts/pressure-seed.xml" if mode == "seed"
                            else "pressure-reports/pressure-assert.xml")
                result = ET.parse(self.directory / relative)
                tests = list(result.iter("testcase"))
                assert code == 0 and tests and not list(result.iter("skipped")) and not list(result.iter("failure"))
                assert not list(result.iter("error"))
                assert {
                    "test_required_pressure_and_aof_phase",
                    "test_real_redis_oom_before_allocation_and_owned_release_recovers",
                } <= {item.get("name") for item in tests}
                phases.append({"phase": mode, "executed_tests": len(tests), "skipped": 0})
        self.record(
            "redis_pressure",
            phases=phases,
            separate_store=True,
            maxmemory_bytes=33554432,
            policy="noeviction",
            aof_cold_clone=True,
        )

    def probe_status(self, record, mode):
        self.probe_checkpoint(mode + "_identity", operation="container_inspect", service=record["service"])
        verify_resource(record, self.docker.inspect("container", record["id"]))
        self.probe_completed()
        command = ["python", "-m", "shadai.workers.probe", mode, "--stage", "ingest"]
        if mode == "readiness":
            command = ["python", "/app/entrypoint.py", *command]
        self.probe_checkpoint(mode, operation="container_exec", service=record["service"])
        result = self.docker.runner(
            ["docker", "--context", self.context, "container", "exec", record["id"], *command],
            capture_output=True,
            text=True,
            timeout=min(8, self.remaining()),
        )
        self.probe_completed()
        if result.returncode != 0 and mode == "readiness" and self.probe_section == "dependencies":
            diagnostic = parse_readiness_diagnostic(getattr(result, "stdout", ""))
            self.probe_reason = diagnostic["reason"]
            self.probe_secondary_reason = diagnostic["secondary_reason"]
        return result.returncode == 0

    def wait_probe_dependencies(self, worker):
        services = {"migrate", "redis", "clickhouse"}
        self.probe_checkpoint("registry")
        records = self.containers(services)
        self.probe_completed()
        self.probe_checkpoint("unique")
        if len(records) != len(services):
            raise QualificationError("Probe dependency identity is not unique")
        self.probe_completed()
        while True:
            self.probe_checkpoint("budget")
            self.remaining()
            self.probe_completed()
            starting = False
            for record in records:
                self.probe_checkpoint("inspect", operation="container_inspect", service=record["service"])
                inspected = self.docker.inspect("container", record["id"])
                self.probe_checkpoint("identity", service=record["service"])
                verify_resource(record, inspected)
                self.probe_completed()
                self.probe_checkpoint("state", service=record["service"])
                state = inspected.get("State")
                if type(state) is not dict:
                    raise QualificationError("Probe dependency state is invalid")
                if record["service"] == "migrate":
                    if (state.get("Status") != "exited" or state.get("Running") is not False or
                            type(state.get("ExitCode")) is not int or state["ExitCode"] != 0):
                        raise QualificationError("Probe migration has not completed successfully")
                else:
                    self.probe_completed()
                    self.probe_checkpoint("health", service=record["service"])
                    health = state.get("Health")
                    if (state.get("Running") is not True or type(health) is not dict or
                            type(health.get("Status")) is not str or
                            health.get("Status") not in {"healthy", "starting"}):
                        raise QualificationError("Probe store health is invalid")
                    starting = starting or health["Status"] == "starting"
                self.probe_completed()
            if not starting:
                self.remaining()
                self.probe_reason = self.probe_secondary_reason = None
                if self.probe_status(worker, "readiness"):
                    break
                if not (type(self.probe_reason) is str and self.probe_reason == "phase_unready"
                        and type(self.probe_secondary_reason) is str and self.probe_secondary_reason == "none"):
                    raise QualificationError("Probe worker is not ready after dependency recovery")
            else:
                self.probe_checkpoint("readiness_identity", operation="container_inspect", service=worker["service"])
                verify_resource(worker, self.docker.inspect("container", worker["id"]))
                self.probe_completed()
            self.probe_checkpoint("wait")
            self.sleep(min(1, self.remaining()))
            self.probe_completed()

    def experiment_probes(self, url):
        with self.probe_diagnostics():
            return self._experiment_probes(url)

    def _experiment_probes(self, url):
        self.probe_checkpoint("registry", service="ingest-worker")
        worker = self.containers({"ingest-worker"})[0]
        self.probe_completed()
        assert self.probe_status(worker, "startup") and self.probe_status(worker, "liveness")
        self.probe_checkpoint("restart", operation="container_inspect", service="ingest-worker")
        before = self.docker.inspect("container", worker["id"])["RestartCount"]
        self.probe_completed()
        self.probe_section = "outage"
        self.change("stop", {"redis"})
        self.probe_checkpoint("wait")
        self.sleep(10)
        self.probe_completed()
        assert self.probe_status(worker, "liveness") and not self.probe_status(worker, "readiness")
        self.probe_checkpoint("restart", operation="container_inspect", service="ingest-worker")
        assert self.docker.inspect("container", worker["id"])["RestartCount"] == before
        self.probe_completed()
        self.change("start", {"redis"})
        self.probe_section = "dependencies"
        self.probe_checkpoint("budget")
        previous_deadlines = self.deadline, self.docker.deadline
        deadline = self.local_deadline(120)
        if self.docker.deadline is not None:
            deadline = min(deadline, self.docker.deadline)
        self.deadline = self.docker.deadline = deadline
        try:
            self.wait_probe_dependencies(worker)
            self.probe_checkpoint("launch_budget")
            self.remaining()
            self.probe_completed()
            self.probe_section = "peer"
            try:
                self.compose("up", "-d", "--no-deps", "probe-ingest-peer")
            except BaseException as exc:
                self.probe_failure(exc)
                raise
            finally:
                self.deadline, self.docker.deadline = previous_deadlines
                with self.probe_diagnostics(secondary=True):
                    self.discover()
        finally:
            self.deadline, self.docker.deadline = previous_deadlines
        self.probe_checkpoint("registry", service="probe-ingest-peer")
        peer = self.containers({"probe-ingest-peer"})[0]
        self.probe_completed()
        self.probe_checkpoint("budget")
        deadline = self.local_deadline(30)
        while time.monotonic() < deadline and not self.probe_status(peer, "startup"):
            self.probe_checkpoint("wait")
            self.sleep(min(1, max(0, deadline - time.monotonic())))
            self.probe_completed()
        assert self.probe_status(peer, "liveness")
        self.probe_section = "suspend"
        self.probe_checkpoint("identity", operation="container_inspect", service="ingest-worker")
        verify_resource(worker, self.docker.inspect("container", worker["id"]))
        self.probe_completed()
        signal_command = (
            "from shadai.workers.probe import read_probe; import os,signal; "
            "v,_=read_probe('ingest'); os.kill(v['pid'],signal.SIGSTOP)"
        )
        self.probe_checkpoint("signal", operation="container_exec", service="ingest-worker")
        self.docker.call("container", "exec", worker["id"], "python", "-c", signal_command)
        try:
            self.probe_checkpoint("wait")
            self.sleep(32)
            self.probe_completed()
            assert not self.probe_status(worker, "liveness") and self.probe_status(peer, "liveness")
        except BaseException as exc:
            self.probe_failure(exc)
            raise
        finally:
            budget_deadline = self.docker.deadline
            self.docker.deadline = time.monotonic() + 10
            try:
                self.probe_section = "resume"
                with self.probe_diagnostics(secondary=True):
                    self.probe_checkpoint("identity", operation="container_inspect", service="ingest-worker")
                    verify_resource(worker, self.docker.inspect("container", worker["id"]))
                    self.probe_completed()
                    self.probe_checkpoint("signal", operation="container_exec", service="ingest-worker")
                    self.docker.call(
                        "container",
                        "exec",
                        worker["id"],
                        "python",
                        "-c",
                        "from shadai.workers.probe import read_probe; import os,signal; "
                        "v,_=read_probe('ingest'); os.kill(v['pid'],signal.SIGCONT)",
                    )
                    self.change("stop", {"probe-ingest-peer"})
            finally:
                self.docker.deadline = budget_deadline
        self.probe_section = "witness"
        self.probe_checkpoint("launch")
        witness = self.run_owned(["-m", "shadai.qualification.probe_witness"])
        self.probe_completed()
        self.probe_checkpoint("report")
        suspended = self.helper_result(witness)
        self.probe_completed()
        self.probe_checkpoint("record")
        self.record(
            "probes",
            dependency_outage_liveness=True,
            readiness_false_on_outage=True,
            restart_count_unchanged=True,
            sigstop_stale_not_masked_by_peer=True,
            suspended_async_io=suspended,
        )
        self.probe_completed()

    def experiment_physical(self, url):
        from shadai.qualification.physical import host_exporter_proof

        with self.physical_diagnostics("inspector"):
            metrics = self.inspector("physical")
        with self.physical_diagnostics("services"):
            records = self.containers(STORES | WRITERS)
            for record in records:
                self.physical_checkpoint("inspect")
                verify_resource(record, self.docker.inspect("container", record["id"]))
            self.physical_checkpoint("stats")
            stats = self.docker.call(
                "stats", "--no-stream", "--format", "{{json .}}", *(item["id"] for item in records))
        rows = [json.loads(line) for line in stats.splitlines()]
        assert len(rows) == len(records)
        volumes = []
        for service in sorted(STORES):
            with self.physical_diagnostics("volume"):
                volume = self.volume(service)
                helper = self.run_owned(
                    [
                        "-c",
                        "import os,json; s=os.statvfs('/volume'); "
                        "print(json.dumps({'size_bytes':s.f_blocks*s.f_frsize,'available_bytes':s.f_bavail*s.f_frsize,"
                        "'filesystem_id':s.f_fsid,'provenance':'statvfs owned volume mount'}))",
                    ],
                    volumes=[(volume, "/volume", True)],
                    root=True,
                    caps=["DAC_READ_SEARCH"],
                )
                volumes.append({"store": service, "volume_id": volume["id"], **self.helper_result(helper)})
        with self.physical_diagnostics("exporter"):
            primary = None
            try:
                self.compose("up", "-d", "node-exporter")
            except BaseException as exc:
                primary = exc
                if self.failure is None:
                    self.failure = failure_evidence(exc, "physical", self.stage)
                raise
            finally:
                try:
                    self.discover()
                except BaseException as secondary:
                    if primary is None:
                        raise
                    self.physical_secondary(primary, secondary)
                    if isinstance(secondary, (KeyboardInterrupt, SystemExit)):
                        raise
                    primary.add_note("physical_exporter_discover_failed")
            exporter = self.containers({"node-exporter"})[0]
            self.physical_checkpoint("inspect")
            verify_resource(exporter, self.docker.inspect("container", exporter["id"]))
            self.physical_checkpoint("observe")
            deadline = self.local_deadline(30)
            while True:
                try:
                    physical = host_exporter_proof(
                        self.context, self.journal.value["projects"]["source"], exporter["id"], deadline=deadline
                    )
                    break
                except QualificationError:
                    if time.monotonic() >= deadline:
                        raise
                    self.sleep(min(1, max(0, deadline - time.monotonic())))
        self.record(
            "physical",
            redis_and_filesystem=metrics,
            containers=rows,
            owned_volumes=volumes,
            host_exporter=physical,
            provenance="Docker stats memory usage/cache policy, not application RSS",
            filesystem_sum=False,
        )

    def clean(self, *, execute=False, remove_volumes=False):
        planned = sorted(
            self.journal.value["resources"], key=lambda item: {"container": 0, "network": 1, "volume": 2}[item["kind"]]
        )
        if not execute:
            return {
                "schema": 1,
                "execute": False,
                "resources": [item for item in planned if item["kind"] != "volume" or remove_volumes],
                "remove_volumes": remove_volumes,
            }
        for record in planned:
            if record["kind"] == "container":
                inspected = self.docker.inspect("container", record["id"], absent=True)
                if inspected is not None:
                    verify_resource(record, inspected)
                    if inspected["State"]["Running"]:
                        self.docker.call("container", "stop", record["id"])
            self.remove(record, volumes=remove_volumes)
        self.journal.phase("cleaned")
        return {"schema": 1, "cleaned": True, "volumes_removed": remove_volumes}
