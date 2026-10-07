"""Closed cold checkpoints at existing boundaries; synthetic evidence only."""

import ast
import asyncio
import copy
import inspect
import json
import textwrap
from itertools import permutations
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_qualification_boundaries import fresh_result, restored_result
from test_qualification_pressure_diagnostics import CANARY, CliModel, PhysicalCliModel

import shadai.qualification.lab as lab_module
from shadai.qualification.fixtures import expected_load_ids
from shadai.qualification.journal import RunJournal, atomic_json
from shadai.qualification.lab import (
    COLD_CHECKPOINTS,
    COLD_SERVICES,
    COLD_STEPS,
    Docker,
    DockerOperationError,
    Laboratory,
    closed_cold_evidence,
    cold_failure_evidence,
    docker_operation,
)
from shadai.qualification.schemas import QualificationError, load_profile

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT_CASES = [(section, step) for section, steps in COLD_STEPS.items() for step in sorted(steps)]


class ColdCli(PhysicalCliModel):
    """Run owned store/archive machinery without a Docker daemon."""

    def __init__(self, lab):
        super().__init__(lab)
        self.invocations, self.actions = [], {}
        self.stores_failure = self.writers_failure = None

    def runner(self, command, **kwargs):
        args = command[3:]
        self.invocations.append({"args": list(args), "kwargs": kwargs.copy()})
        pair = self.lab.docker.checkpoint, docker_operation(args)
        if args[:2] == ["network", "ls"]:
            self.calls.append(tuple(args))
            self.pairs.append(pair)
            return self.response()
        if args[0] == "compose":
            verb = args[7]
            if verb == "run":
                name = args[args.index("--name") + 1]
                role = "restore" if args[2] == self.lab.journal.value["projects"]["restore"] else "source"
                current = self.container("9" * 64, name, role, role, "inspector")
                self.containers[current["Id"]] = current
                self.actions[current["Id"]] = (args[args.index("fixture") + 1], args[args.index("--case") + 1])
            else:
                assert verb == "up"
                stores = "--wait" in args
                error = self.stores_failure if stores else self.writers_failure
                if error is not None:
                    raise error
                project = self.lab.journal.value["projects"]["restore"]
                for index, service in enumerate(sorted(lab_module.STORES if stores else lab_module.WRITERS),
                                                30 if stores else 40):
                    current = self.container(f"{index:064x}", project + "-" + service + "-1",
                                             "restore", "restore", service)
                    if service in lab_module.STORES:
                        suffix = {"postgres": "pg_data", "clickhouse": "ch_data", "redis": "redis_data"}[service]
                        current["Mounts"] = [{"Type": "volume", "Name": project + "_" + suffix}]
                    self.containers[current["Id"]] = current
            self.calls.append(tuple(args))
            self.pairs.append(pair)
            return self.response(CANARY)
        if args[:2] == ["container", "logs"] and args[2] in self.actions:
            self.calls.append(tuple(args))
            self.pairs.append(pair)
            action, case = self.actions[args[2]]
            if action == "seed_pending":
                result = {"pel_witnessed": True, "pending_event_id": "synthetic-pending"}
            elif action == "inventory":
                atomic_json(self.lab.directory / (case + "-inventory.json"), {"synthetic_inventory": [1, 2, 3]})
                result = {"logical_events": 1}
            else:
                assert action == "verify_load" and case == "restored-fresh"
                result = restored_result()
            return self.response(json.dumps(result))
        if args[:2] == ["container", "logs"]:
            return CliModel.runner(self, command, **kwargs)
        return super().runner(command, **kwargs)


def create_cold_lab(tmp_path, monkeypatch, lab_type=Laboratory):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    profile["scenarios"] = ["cold_restore"]
    lab = lab_type(ROOT, tmp_path / "run", profile, "bounded-diagnostic-context")
    lab.journal = RunJournal.create(lab.directory, profile, lab.config_hash, lab.context)
    lab.journal.phase("cold_restore")
    lab.tenant = "synthetic-owned-installation"
    atomic_json(lab.directory / "source.json", {"synthetic_cli_boundary": True})
    atomic_json(lab.directory / "secret-hashes.json", {})
    monkeypatch.setattr(lab_module.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(lab_module.os, "getgid", lambda: 1001, raising=False)
    monkeypatch.setattr(lab_module.time, "monotonic", lambda: 10)
    monkeypatch.setattr(lab, "environment", lambda role: {"CANARY": CANARY})
    monkeypatch.setattr(lab, "verify_secrets", lambda: None)
    monkeypatch.setattr(lab, "wait_ready", lambda role: "http://127.0.0.1:12345")
    monkeypatch.setattr(lab, "send", lambda url, case, total: fresh_result(total))
    cli = ColdCli(lab)
    lab.docker = Docker(lab.context, runner=cli.runner)
    lab.deadline = lab.docker.deadline = 1000
    return lab, cli


def bare_lab(tmp_path):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    profile["scenarios"] = ["cold_restore"]
    lab = Laboratory(ROOT, tmp_path, profile, "bounded-diagnostic-context")
    lab.docker = SimpleNamespace(checkpoint=None, last_completed=None)
    return lab


def assert_closed_failure(lab, checkpoint):
    primary = {key: item for key, item in lab.failure.items() if key != "secondary"}
    assert closed_cold_evidence(primary)
    assert primary["phase"] == "cold_restore"
    assert primary["stage"] == primary["checkpoint"] == checkpoint
    encoded = json.dumps(lab.failure, sort_keys=True)
    assert len(encoded.encode("utf-8")) <= 2048 and CANARY not in encoded
    assert str(lab.directory) not in encoded and "synthetic-pending" not in encoded
    assert lab.cold_section is None and lab.docker.checkpoint is None


def test_healthy_cold_retains_owned_archives_and_eleven_receipts(tmp_path, monkeypatch):
    lab, cli = create_cold_lab(tmp_path, monkeypatch)
    lab.execute_special("unused", set())
    assert lab.failure is None and lab.cold_section is None
    assert lab.docker.checkpoint is lab.docker.last_completed is None
    assert len(lab.scenarios) == 1 and lab.scenarios[0]["status"] == "passed"
    measurements = lab.scenarios[0]["measurements"]
    assert measurements["exact_inventory_before_workers"] is True
    assert measurements["fresh_load"]["accepted"] == 10
    assert measurements["fresh_verification"] == restored_result()
    assert {s + "-cold.tar" for s in lab_module.STORES} <= {p.name for p in lab.directory.iterdir()}
    assert any(checkpoint.startswith("cold_restore_export_") for checkpoint, _ in cli.pairs)
    assert any(checkpoint.startswith("cold_restore_import_") for checkpoint, _ in cli.pairs)
    assert all(call["kwargs"]["timeout"] <= 180 for call in cli.invocations)


@pytest.mark.parametrize("section,step", CHECKPOINT_CASES)
@pytest.mark.parametrize("kind", [QualificationError, AssertionError, KeyboardInterrupt])
def test_every_checkpoint_retains_original_exception(tmp_path, section, step, kind):
    lab, error = bare_lab(tmp_path), kind(CANARY)
    with pytest.raises(kind) as caught:
        with lab.cold_diagnostics(section):
            assert lab.cold_checkpoint(step, operation="container_inspect", service="redis")
            raise error
    assert caught.value is error
    assert_closed_failure(lab, "cold_restore_" + section + "_" + step)
    assert lab.failure["operation"] == "container_inspect" and lab.failure["service"] == "redis"


def test_preentry_budget_does_not_enter_experiment(tmp_path, monkeypatch):
    lab = bare_lab(tmp_path)
    phases, calls = [], []
    lab.journal = SimpleNamespace(phase=phases.append)
    lab.deadline = 0
    monkeypatch.setattr(lab_module.time, "monotonic", lambda: 1)
    monkeypatch.setattr(lab, "experiment_cold_restore", lambda url: calls.append(url))
    with pytest.raises(QualificationError, match="wall budget"):
        lab.execute_special("unused", set())
    assert phases == ["cold_restore"] and calls == [] and lab.deadline == 0
    assert_closed_failure(lab, "cold_restore_entry_budget")


@pytest.mark.parametrize("primary_type", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("secondary_type", [None, ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_inspector_primary_frozen_with_unchanged_cleanup_propagation(
    tmp_path, monkeypatch, primary_type, secondary_type
):
    lab, cli = create_cold_lab(tmp_path, monkeypatch)
    primary = primary_type(CANARY)
    secondary = secondary_type(CANARY) if secondary_type else None
    cli.inspector_failure, cli.inspector_cleanup_failure = primary, secondary
    expected = secondary if secondary is not None else primary
    with pytest.raises(type(expected)) as caught:
        lab.experiment_cold_restore("unused")
    assert caught.value is expected
    assert_closed_failure(lab, "cold_restore_seed_pending_wait")
    assert lab.failure["error_type"] == lab_module.safe_exception_type(primary)
    if secondary is not None:
        assert len(lab.failure["secondary"]) == 1
        assert lab.failure["secondary"][0]["error_type"] == lab_module.safe_exception_type(secondary)
        assert lab.failure["secondary"][0]["checkpoint"] == "cold_restore_seed_pending_remove"


@pytest.mark.parametrize("section", ["stores_start", "writers_start"])
def test_compose_primary_survives_failed_final_discovery(tmp_path, monkeypatch, section):
    lab, cli = create_cold_lab(tmp_path, monkeypatch)
    primary, secondary = ValueError(CANARY), KeyboardInterrupt(CANARY)
    setattr(cli, "stores_failure" if section == "stores_start" else "writers_failure", primary)
    original = cli.runner

    def runner(command, **kwargs):
        if command[3] == "ps" and lab.stage.startswith("cold_restore_" + section):
            raise secondary
        return original(command, **kwargs)

    lab.docker.runner = runner
    with pytest.raises(KeyboardInterrupt) as caught:
        lab.experiment_cold_restore("unused")
    assert caught.value is secondary
    assert_closed_failure(lab, "cold_restore_" + section + "_up")
    assert lab.failure["error_type"] == "ValueError"
    assert lab.failure["secondary"][0]["checkpoint"] == "cold_restore_" + section + "_discover_list"


def test_docker_call_context_frozen_before_cleanup(tmp_path):
    lab = bare_lab(tmp_path)
    error = DockerOperationError("docker_nonzero", 17, operation="volume_inspect",
                                 checkpoint="cold_restore_export_volume_inspect",
                                 last_completed="cold_restore_export_worker_inspect")
    with pytest.raises(DockerOperationError) as caught:
        with lab.cold_diagnostics("export"):
            lab.cold_checkpoint("remove", service="redis")
            raise error
    assert caught.value is error
    assert_closed_failure(lab, "cold_restore_export_volume_inspect")
    assert lab.failure["operation"] == "volume_inspect" and lab.failure["returncode"] == 17
    assert lab.failure["last_completed"] == "cold_restore_export_worker_inspect"


class StringAlias(str):
    def __hash__(self):
        raise AssertionError("virtual string evaluated")

    def __eq__(self, other):
        raise AssertionError("virtual string evaluated")


class DictAlias(dict):
    def items(self):
        raise AssertionError("virtual container evaluated")


@pytest.mark.parametrize("field", ["stage", "cold_operation", "cold_service"])
def test_virtual_scalar_fields_excluded_without_evaluation(tmp_path, field):
    lab = bare_lab(tmp_path)
    with lab.cold_diagnostics("export"):
        lab.cold_checkpoint("validate", service="redis")
        setattr(lab, field, StringAlias(CANARY))
        lab.cold_failure(ValueError(CANARY))
    assert CANARY not in json.dumps(lab.failure)
    assert closed_cold_evidence(lab.failure)


def test_virtual_containers_unknown_fields_and_extra_secondary_excluded(tmp_path):
    lab = bare_lab(tmp_path)
    with lab.cold_diagnostics("export"):
        lab.cold_checkpoint("validate")
        lab.cold_failure(ValueError(CANARY))
        original = lab.failure
        lab.cold_failure(TypeError(CANARY), secondary=True)
        first = lab.failure
        lab.cold_failure(KeyboardInterrupt(CANARY), secondary=True)
        assert lab.failure is first and len(first["secondary"]) == 1
        for poisoned in (DictAlias(original), {**original, "payload": CANARY}, {**original, "returncode": True}):
            lab.failure = lab.cold_primary = poisoned
            lab.cold_failure(ValueError(CANARY), secondary=True)
            assert lab.failure is poisoned


@pytest.mark.parametrize("kind", [ValueError, KeyboardInterrupt, SystemExit])
def test_encoding_failure_cannot_replace_primary(tmp_path, monkeypatch, kind):
    lab = bare_lab(tmp_path)
    original = QualificationError(CANARY)
    monkeypatch.setattr(lab_module, "canonical_bytes", lambda value: (_ for _ in ()).throw(kind(CANARY)))
    with pytest.raises(QualificationError) as caught:
        with lab.cold_diagnostics("entry"):
            raise original
    assert caught.value is original and lab.failure is None


def test_payload_or_virtual_envelope_never_delivered(tmp_path, monkeypatch):
    lab = bare_lab(tmp_path)
    for value in ({"payload": CANARY}, DictAlias(phase="cold_restore"), [CANARY], CANARY):
        monkeypatch.setattr(lab_module, "cold_failure_evidence", lambda *args, value=value: value)
        with lab.cold_diagnostics("entry"):
            lab.cold_failure(ValueError(CANARY))
        assert lab.failure is None


def test_closed_builtin_enums_bound_largest_envelope():
    for checkpoint in COLD_CHECKPOINTS:
        for service in COLD_SERVICES:
            value = cold_failure_evidence(QualificationError(CANARY), checkpoint, "container_inspect", service,
                                          max(COLD_CHECKPOINTS, key=len))
            assert closed_cold_evidence(value)
            assert len(json.dumps({**value, "secondary": [value]}).encode("utf-8")) <= 2048
    assert not closed_cold_evidence(DictAlias())
    assert not closed_cold_evidence({"phase": StringAlias("cold_restore")})


def test_distinct_pending_and_eleven_results_remain_required():
    fresh, receipts = fresh_result(), restored_result()
    assert len(expected_load_ids(fresh, pending="pending")) == 11
    with pytest.raises(QualificationError):
        expected_load_ids(fresh, pending=fresh["accepted_scoped_ids"][0])
    for field in ("expected_logical_events", "persisted", "receipts", "correlation_receipts"):
        with pytest.raises(AssertionError):
            Laboratory.verify_fresh_restore(fresh, {**receipts, field: 10})
    for field in ("missing", "missing_receipts", "missing_correlations"):
        with pytest.raises(AssertionError):
            Laboratory.verify_fresh_restore(fresh, {**receipts, field: ["pending"]})


def private_inventory():
    return {
        "postgres": {name: [[CANARY] * width] for name, width in lab_module.INVENTORY_TABLE_WIDTHS.items()},
        "clickhouse_events": [[CANARY] * 4],
        "redis": {
            CANARY + "string": {"type": "string", "value": CANARY},
            CANARY + "hash": {"type": "hash", "value": {CANARY: CANARY}},
            CANARY + "zset": {"type": "zset", "value": [[CANARY, 1.5]]},
            CANARY + "stream": {"type": "stream", "entries": [[CANARY, {CANARY: CANARY}]],
                "groups": [{"name": CANARY, "pending": 1, "private_future_field": CANARY}],
                "pending": {CANARY: [{"message_id": CANARY, "consumer": CANARY, "times_delivered": 1}]}},
        },
    }


def comparison_statement():
    # Execute the actual production assert/catch, rather than a copied predicate.
    function = ast.parse(textwrap.dedent(inspect.getsource(Laboratory._experiment_cold_restore))).body[0]
    statement, = [node for node in function.body if isinstance(node, ast.Try)
                  and node.body and isinstance(node.body[0], ast.Assert)]
    module = ast.fix_missing_locations(ast.Module(body=[statement], type_ignores=[]))
    return compile(module, "<production-assert>", "exec")


def compare_in_lab(lab, source, restored):
    lab.cold_phase("inventory_compare", "compare")
    exec(comparison_statement(), {"self": lab, "source": source, "restored": restored})


def test_inventory_summary_equal_counts_canaries_and_input_bytes_unchanged():
    source, restored = private_inventory(), private_inventory()
    before = [json.dumps(item, sort_keys=True) for item in (source, restored)]
    summary = lab_module.cold_inventory_comparison(source, restored)
    assert lab_module.closed_inventory_comparison(summary)
    assert summary["stores"] == dict.fromkeys(("postgres", "clickhouse", "redis"), True)
    assert all(item == [True, 1, 1] for item in summary["postgres"].values())
    assert summary["clickhouse"] == [True, 1, 1]
    assert summary["redis"]["keys"] == [True, 4, 4]
    assert all(summary["redis"][name] == [True, 1, 1]
               for name in lab_module.INVENTORY_REDIS_COMPONENTS - {"keys"})
    assert CANARY not in json.dumps(summary)
    assert before == [json.dumps(item, sort_keys=True) for item in (source, restored)]


@pytest.mark.parametrize("table", lab_module.INVENTORY_TABLE_WIDTHS)
@pytest.mark.parametrize("change", ["value", "order", "missing", "empty"])
def test_inventory_postgres_values_order_and_missing_are_distinct(table, change):
    source = private_inventory()
    source["postgres"][table].append(["different"] * lab_module.INVENTORY_TABLE_WIDTHS[table])
    restored = copy.deepcopy(source)
    if change == "value":
        restored["postgres"][table][0][0] = "different"
    elif change == "order":
        restored["postgres"][table].reverse()
    elif change == "missing":
        del restored["postgres"][table]
    else:
        restored["postgres"][table] = []
    summary = lab_module.cold_inventory_comparison(source, restored)
    expected_count = {"missing": -1, "empty": 0}.get(change, 2)
    assert summary["postgres"][table] == [False, 2, expected_count]
    assert summary["stores"] == {"postgres": False, "clickhouse": True, "redis": True}


def test_inventory_postgres_both_missing_and_missing_versus_empty():
    source = private_inventory()
    del source["postgres"]["detections"]
    restored = copy.deepcopy(source)
    assert lab_module.cold_inventory_comparison(source, restored)["postgres"]["detections"] == [True, -1, -1]
    restored["postgres"]["detections"] = []
    assert lab_module.cold_inventory_comparison(source, restored)["postgres"]["detections"] == [False, -1, 0]


@pytest.mark.parametrize("change", ["value", "order", "missing"])
def test_inventory_clickhouse_preserves_rows_and_order(change):
    source = private_inventory()
    source["clickhouse_events"].append(["different"] * 4)
    restored = copy.deepcopy(source)
    if change == "value":
        restored["clickhouse_events"][0][0] = "different"
    elif change == "order":
        restored["clickhouse_events"].reverse()
    else:
        restored["clickhouse_events"].pop()
    summary = lab_module.cold_inventory_comparison(source, restored)
    assert summary["clickhouse"] == [False, 2, 1 if change == "missing" else 2]
    assert summary["stores"]["clickhouse"] is False


@pytest.mark.parametrize("component", sorted(lab_module.INVENTORY_REDIS_COMPONENTS))
@pytest.mark.parametrize("change", ["value", "missing"])
def test_inventory_redis_components_keep_complete_private_bindings(component, change):
    source, restored = private_inventory(), private_inventory()
    kind = {"keys": "string", "strings": "string", "hashes": "hash", "zsets": "zset"}.get(component, "stream")
    key = CANARY + kind
    record = restored["redis"][key]
    if change == "missing":
        del restored["redis"][key]
    elif component == "keys":
        restored["redis"]["other-private-key"] = restored["redis"].pop(key)
    elif component == "strings":
        record["value"] = "different"
    elif component == "hashes":
        record["value"][CANARY] = "different"
    elif component == "zsets":
        record["value"][0][1] = 2.5
    elif component == "stream_entries":
        record["entries"][0][1][CANARY] = "different"
    elif component == "stream_groups":
        record["groups"][0]["private_future_field"] = "different"
    else:
        record["pending"][CANARY][0]["consumer"] = "different"
    summary = lab_module.cold_inventory_comparison(source, restored)
    original_count = 4 if component == "keys" else 1
    assert summary["redis"][component] == [False, original_count,
                                           original_count - 1 if change == "missing" else original_count]
    assert summary["stores"]["redis"] is False and CANARY not in json.dumps(summary)


class CallbackValue:
    calls = 0

    def __eq__(self, other):
        self.calls += 1
        raise AssertionError("unexpected diagnostic comparison")

    def __str__(self):
        self.calls += 1
        raise AssertionError("unexpected diagnostic serialization")


@pytest.mark.parametrize("poison", [CallbackValue(), StringAlias(CANARY), DictAlias(), (CANARY,), b"secret",
                                    float("nan"), float("inf"), float("-inf"), 1 << 4096])
@pytest.mark.parametrize("side", ["source", "restored"])
def test_inventory_poison_rejected_before_any_comparison_or_serialization(poison, side):
    source, restored = private_inventory(), private_inventory()
    target = source if side == "source" else restored
    target["postgres"]["ingest_receipts"][0][0] = poison
    assert lab_module.cold_inventory_comparison(source, restored) is None
    if isinstance(poison, CallbackValue):
        assert poison.calls == 0


@pytest.mark.parametrize("kind", ["cycle", "depth", "characters", "visited", "key-type"])
def test_inventory_combined_limits_omit_summary(kind):
    source, restored = private_inventory(), private_inventory()
    if kind == "cycle":
        source["postgres"]["ingest_receipts"][0][0] = source
    elif kind == "depth":
        value = None
        for _ in range(33):
            value = [value]
        source["postgres"]["ingest_receipts"][0][0] = value
    elif kind == "characters":
        for item in (source, restored):
            item["postgres"]["ingest_receipts"][0][0] = "x" * 524288
    elif kind == "visited":
        for item in (source, restored):
            item["postgres"]["ingest_receipts"][0][0] = [None] * 50000
    else:
        restored["redis"][False] = {"type": "string", "value": "private"}
    assert lab_module.cold_inventory_comparison(source, restored) is None


@pytest.mark.parametrize("kind", ["root", "pg-unknown", "pg-width", "ch-width", "redis-unknown", "redis-extra",
                                    "hash", "zset", "entries", "groups", "pending"])
def test_inventory_complete_producer_shape_required(kind):
    source, restored = private_inventory(), private_inventory()
    if kind == "root":
        restored["payload"] = CANARY
    elif kind == "pg-unknown":
        restored["postgres"]["private_table"] = []
    elif kind == "pg-width":
        restored["postgres"]["ingest_receipts"][0].append(CANARY)
    elif kind == "ch-width":
        restored["clickhouse_events"][0].pop()
    elif kind == "redis-unknown":
        restored["redis"][CANARY + "string"]["type"] = "list"
    elif kind == "redis-extra":
        restored["redis"][CANARY + "string"]["payload"] = CANARY
    elif kind == "hash":
        restored["redis"][CANARY + "hash"]["value"][CANARY] = 1
    elif kind == "zset":
        restored["redis"][CANARY + "zset"]["value"][0][1] = True
    elif kind == "entries":
        restored["redis"][CANARY + "stream"]["entries"][0][1] = [CANARY]
    elif kind == "groups":
        restored["redis"][CANARY + "stream"]["groups"][0] = [CANARY]
    else:
        restored["redis"][CANARY + "stream"]["pending"][CANARY][0] = [CANARY]
    assert lab_module.cold_inventory_comparison(source, restored) is None


@pytest.mark.parametrize("field,value", [
    ("schema", True), ("schema", 1.0), ("stores", {"postgres": 1, "clickhouse": True, "redis": True}),
    ("clickhouse", [True, True, 1]), ("clickhouse", [True, -1, 1]), ("clickhouse", [True, 100001, 1]),
    ("clickhouse", [1, 1, 1]), ("clickhouse", (True, 1, 1)), ("payload", CANARY),
])
def test_inventory_public_output_closed_keys_and_exact_types(field, value):
    summary = lab_module.cold_inventory_comparison(private_inventory(), private_inventory())
    summary[field] = value
    assert not lab_module.closed_inventory_comparison(summary)


@pytest.mark.parametrize("field", ["checkpoint", "error_type"])
@pytest.mark.parametrize("order", list(permutations(("inventory_comparison", "checkpoint", "error_type"))))
@pytest.mark.parametrize("base", [object, str])
def test_closed_cold_evidence_poison_metadata_never_calls_protocol(field, order, base):
    calls = []
    primary = KeyboardInterrupt()

    def refused(name):
        def callback(*args):
            calls.append(name)
            raise primary
        return callback

    poison_type = type("PoisonMetadata", (base,), {
        name: refused(name) for name in ("__eq__", "__ne__", "__hash__", "__str__", "__repr__", "__getattr__")
    })
    poison = poison_type("AssertionError") if base is str else poison_type()
    value = cold_failure_evidence(AssertionError(), "cold_restore_inventory_compare_compare", "unknown", None, None)
    value["inventory_comparison"] = lab_module.cold_inventory_comparison(private_inventory(), private_inventory())
    value[field] = poison
    ordered = {key: value[key] for key in order}
    ordered.update({key: item for key, item in value.items() if key not in order})
    assert closed_cold_evidence(ordered) is False
    assert calls == []


@pytest.mark.parametrize("order", list(permutations(("inventory_comparison", "checkpoint", "error_type"))))
def test_closed_cold_evidence_valid_inventory_independent_of_field_order(order):
    value = cold_failure_evidence(AssertionError(), "cold_restore_inventory_compare_compare", "unknown", None, None)
    summary = lab_module.cold_inventory_comparison(private_inventory(), private_inventory())
    value["inventory_comparison"] = summary
    ordered = {key: value[key] for key in order}
    ordered.update({key: item for key, item in value.items() if key not in order})
    assert closed_cold_evidence(ordered) is True
    assert ordered["inventory_comparison"] is summary
    assert lab_module.canonical_bytes(ordered) == lab_module.canonical_bytes(value)


@pytest.mark.parametrize("kind", ["nested-count", "nested-extra", "unknown-field", "checkpoint", "error_type"])
def test_closed_cold_evidence_rejects_malformed_inventory_metadata(kind):
    value = cold_failure_evidence(AssertionError(), "cold_restore_inventory_compare_compare", "unknown", None, None)
    summary = lab_module.cold_inventory_comparison(private_inventory(), private_inventory())
    value["inventory_comparison"] = summary
    if kind == "nested-count":
        summary["postgres"]["ingest_receipts"][1] = True
    elif kind == "nested-extra":
        summary["stores"]["unknown"] = True
    elif kind == "unknown-field":
        value["payload"] = CANARY
    else:
        value[kind] = "unknown"
    assert closed_cold_evidence(value) is False


def test_inventory_failure_first_primary_then_one_secondary_with_bound_envelope(tmp_path):
    lab = bare_lab(tmp_path)
    source, restored = private_inventory(), private_inventory()
    restored["postgres"]["ingest_receipts"][0][0] = "different"
    with pytest.raises(AssertionError) as caught:
        compare_in_lab(lab, source, restored)
    assert str(caught.value) == "Exact cold source/restore inventories differ before worker startup"
    assert lab.failure["inventory_comparison"]["stores"]["postgres"] is False
    first = lab.failure
    lab.cold_inventory_failure(AssertionError(), restored, source)
    assert lab.failure is first
    lab.cold_failure(KeyboardInterrupt(), secondary=True)
    second = lab.failure
    lab.cold_failure(SystemExit(), secondary=True)
    assert lab.failure is second and len(second["secondary"]) == 1
    assert len(lab_module.canonical_bytes(second)) <= 2048 and CANARY not in json.dumps(second)
    assert closed_cold_evidence({key: value for key, value in second.items() if key != "secondary"})


@pytest.mark.parametrize("kind", ["stage", "type", "summary", "summary-poison", "encoding"])
def test_inventory_optional_refusal_retains_frozen_primary(tmp_path, monkeypatch, kind):
    lab = bare_lab(tmp_path)
    lab.cold_phase("inventory_compare", "compare")
    error = AssertionError(CANARY)
    if kind == "stage":
        lab.cold_checkpoint("read_source")
    elif kind == "type":
        error = ValueError(CANARY)
    elif kind in {"summary", "summary-poison"}:
        monkeypatch.setattr(lab_module, "cold_inventory_comparison", lambda *args:
                            {"payload": CANARY} if kind == "summary" else DictAlias())
    elif kind == "encoding":
        original = lab_module.canonical_bytes
        monkeypatch.setattr(lab_module, "canonical_bytes", lambda value:
                            (_ for _ in ()).throw(KeyboardInterrupt()) if "inventory_comparison" in value
                            else original(value))
    try:
        lab.cold_inventory_failure(error, private_inventory(), private_inventory())
    except BaseException:
        pass
    assert lab.failure["error_type"] == type(error).__name__ and "inventory_comparison" not in lab.failure


@pytest.mark.parametrize("kind", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_inventory_optional_helper_failure_never_replaces_original_assertion(tmp_path, monkeypatch, kind):
    lab = bare_lab(tmp_path)
    original, diagnostic = AssertionError(CANARY), kind(CANARY)

    class Comparison:
        def __eq__(self, other):
            raise original

    def failure(*args):
        raise diagnostic
    monkeypatch.setattr(lab, "cold_inventory_failure", failure)
    with pytest.raises(AssertionError) as caught:
        compare_in_lab(lab, Comparison(), object())
    assert caught.value is original


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_inventory_original_cancellation_bypasses_optional_handler(tmp_path, monkeypatch, kind):
    lab = bare_lab(tmp_path)
    original, calls = kind(CANARY), []

    class Comparison:
        def __eq__(self, other):
            raise original
    monkeypatch.setattr(lab, "cold_inventory_failure", lambda *args: calls.append(args))
    with pytest.raises(kind) as caught:
        compare_in_lab(lab, Comparison(), object())
    assert caught.value is original and calls == []


@pytest.mark.parametrize("truth", [True, False])
def test_inventory_original_comparison_and_truth_evaluated_once(tmp_path, truth):
    lab, calls = bare_lab(tmp_path), []

    class Truth:
        def __bool__(self):
            calls.append("truth")
            return truth

    class Comparison:
        def __eq__(self, other):
            calls.append("compare")
            return Truth()
    if truth:
        compare_in_lab(lab, Comparison(), object())
        assert lab.failure is None
    else:
        with pytest.raises(AssertionError):
            compare_in_lab(lab, Comparison(), object())
        assert "inventory_comparison" not in lab.failure
    assert calls == ["compare", "truth"]


def test_full_cold_inventory_failure_adds_counts_before_writers_without_altering_inputs(tmp_path, monkeypatch):
    lab, cli = create_cold_lab(tmp_path, monkeypatch)
    source, restored = private_inventory(), private_inventory()
    restored["redis"][CANARY + "stream"]["groups"][0]["pending"] = 2
    original = lab.inspector

    def inspector(action, *args, **kwargs):
        result = original(action, *args, **kwargs)
        if action == "inventory":
            case = kwargs["case"]
            atomic_json(lab.directory / (case + "-inventory.json"), source if case == "source" else restored)
        return result
    monkeypatch.setattr(lab, "inspector", inspector)
    with pytest.raises(AssertionError):
        lab.execute_special("unused", set())
    assert lab.failure["inventory_comparison"]["redis"]["stream_groups"] == [False, 1, 1]
    assert not any(call["args"][0] == "compose" and lab_module.WRITERS <= set(call["args"])
                   for call in cli.invocations)
    assert json.loads((lab.directory / "source-inventory.json").read_text()) == source
    assert json.loads((lab.directory / "restore-inventory.json").read_text()) == restored


def test_inventory_comparison_only_allowed_at_assertion_checkpoint():
    summary = lab_module.cold_inventory_comparison(private_inventory(), private_inventory())
    value = cold_failure_evidence(AssertionError(), "cold_restore_inventory_compare_compare", "unknown", None, None)
    value["inventory_comparison"] = summary
    assert closed_cold_evidence(value)
    for field, item in (("checkpoint", "cold_restore_inventory_compare_read_source"),
                        ("error_type", "ValueError")):
        assert not closed_cold_evidence({**value, field: item})


def test_inventory_shared_alias_counted_per_occurrence_and_small_alias_not_a_cycle():
    source, restored = private_inventory(), private_inventory()
    shared = [None] * 50000
    source["postgres"]["ingest_receipts"][0][0] = restored["postgres"]["ingest_receipts"][0][0] = shared
    assert lab_module.cold_inventory_comparison(source, restored) is None
    shared.clear()
    assert lab_module.cold_inventory_comparison(source, restored)["stores"]["postgres"] is True


@pytest.mark.parametrize("boundary", ["visited", "characters", "depth", "integer"])
def test_inventory_exact_combined_limit_and_one_over(boundary):
    source = {"postgres": {"ingest_receipts": [[None]]}, "clickhouse_events": [], "redis": {}}
    restored = copy.deepcopy(source)
    if boundary == "visited":
        # Each input contributes eleven containers/keys plus the N scalar occurrences.
        source["postgres"]["ingest_receipts"][0][0] = [None] * 49989
        restored["postgres"]["ingest_receipts"][0][0] = [None] * 49989
    elif boundary == "characters":
        # Each input's literal root/table keys total 45 characters.
        source["postgres"]["ingest_receipts"][0][0] = "x" * (1048576 - 90)
    elif boundary == "depth":
        nested = None
        for _ in range(28):
            nested = [nested]
        source["postgres"]["ingest_receipts"][0][0] = nested
    else:
        source["postgres"]["ingest_receipts"][0][0] = (1 << 4096) - 1
    assert lab_module.cold_inventory_comparison(source, restored) is not None
    value = source["postgres"]["ingest_receipts"][0][0]
    if boundary == "visited":
        value.append(None)
    elif boundary == "characters":
        source["postgres"]["ingest_receipts"][0][0] = value + "x"
    elif boundary == "depth":
        source["postgres"]["ingest_receipts"][0][0] = [value]
    else:
        source["postgres"]["ingest_receipts"][0][0] = 1 << 4096
    assert lab_module.cold_inventory_comparison(source, restored) is None


@pytest.mark.parametrize("base,value", [(list, []), (dict, {}), (str, "private"), (int, 1), (float, 1.0)])
def test_inventory_subclass_rejected_without_callbacks(base, value):
    calls = []

    def poison(*args):
        calls.append(True)
        raise AssertionError("subclass callback")
    kind = type("Poison", (base,), {"__eq__": poison, "__len__": poison, "__iter__": poison, "__str__": poison})
    source, restored = private_inventory(), private_inventory()
    restored["postgres"]["ingest_receipts"][0][0] = kind(value)
    assert lab_module.cold_inventory_comparison(source, restored) is None and calls == []


@pytest.mark.parametrize("kind", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_inventory_primary_is_frozen_before_optional_summary_failure(tmp_path, monkeypatch, kind):
    lab, observed = bare_lab(tmp_path), []
    source, restored = private_inventory(), private_inventory()
    restored["postgres"]["ingest_receipts"][0][0] = "different"
    original = lab.cold_inventory_failure

    def handler(exc, *args):
        observed.append(exc)
        return original(exc, *args)

    def summary(*args):
        assert lab.failure["error_type"] == "AssertionError"
        raise kind(CANARY)
    monkeypatch.setattr(lab, "cold_inventory_failure", handler)
    monkeypatch.setattr(lab_module, "cold_inventory_comparison", summary)
    with pytest.raises(AssertionError) as caught:
        compare_in_lab(lab, source, restored)
    assert caught.value is observed[0] and "inventory_comparison" not in lab.failure
