"""Closed cold checkpoints at existing boundaries; synthetic evidence only."""

import asyncio
import json
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
