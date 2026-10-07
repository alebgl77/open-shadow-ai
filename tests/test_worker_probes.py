"""Identity, monotonic progress and local liveness fail closed per process."""

import asyncio
import copy
import io
import json
import os
import signal
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from redis.exceptions import ConnectionError

from shadai.workers import probe
from shadai.workers.streams import StreamConsumer

CANARY = "https://user:private-token@secret.example.test/provider?sql=private-token"


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / "proc"
    (root / "77").mkdir(parents=True)
    (root / "sys/kernel/random").mkdir(parents=True)
    (root / "77/stat").write_text("77 (worker name (with parentheses)) " + " ".join(["S", *(["0"] * 18), "123"]))
    (root / "sys/kernel/random/boot_id").write_text(str(uuid4()))
    return root


@pytest.fixture
def value(proc):
    return {
        "schema": 1,
        "stage": "ingest",
        "pid": 77,
        "start_ticks": 123,
        "boot_id": (proc / "sys/kernel/random/boot_id").read_text(),
        "instance_uuid": str(uuid4()),
        "initialized": True,
        "heartbeat_monotonic": 100,
        "last_poll_monotonic": 99,
        "phase": "idle",
        "phase_started_monotonic": 99,
        "last_successful_cycle_monotonic": None,
    }


@pytest.mark.parametrize(
    "field,changed",
    [
        ("start_ticks", 124),
        ("boot_id", "another-boot"),
        ("pid", True),
        ("schema", True),
        ("schema", 2),
        ("initialized", 1),
        ("heartbeat_monotonic", 101),
        ("phase_started_monotonic", float("nan")),
        ("last_poll_monotonic", -1),
        ("phase", "unknown"),
        ("instance_uuid", "invalid"),
    ],
)
def test_probe_identity_reboot_pid_reuse_future_nonfinite_fail(proc, value, field, changed):
    value[field] = changed
    with pytest.raises((ValueError, FileNotFoundError)):
        probe.validate_probe(value, "ingest", proc=proc, now=100)


def test_identity_command_name_parentheses_and_zombie(proc):
    assert probe.identity(77, proc)[0] == 123
    path = proc / "77/stat"
    path.write_text(path.read_text().replace(" S ", " Z "))
    with pytest.raises(ValueError):
        probe.identity(77, proc)


def test_same_stage_healthy_replica_cannot_mask_stopped_heartbeat(monkeypatch, value):
    stopped, healthy = copy.deepcopy(value), copy.deepcopy(value)
    stopped["heartbeat_monotonic"] = 68
    healthy["heartbeat_monotonic"] = 100
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (stopped, 100))
    assert not probe.local_check("liveness", "ingest")
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (healthy, 100))
    assert probe.local_check("liveness", "ingest")


def test_suspended_handler_local_live_but_overlong_unready(monkeypatch, value):
    value["phase"] = "handler"
    value["phase_started_monotonic"] = 1
    value["heartbeat_monotonic"] = 400
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (value, 400))
    assert probe.local_check("liveness", "ingest")
    assert not probe.local_check("readiness", "ingest")


@pytest.mark.parametrize("phase", ["blocked", "failed", "starting"])
def test_dependency_failure_progress_unready_not_restart(monkeypatch, value, phase):
    value["phase"] = phase
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (value, 100))
    assert probe.local_check("liveness", "ingest")
    assert not probe.local_check("readiness", "ingest")


def test_purge_failed_cycle_not_success_and_daily_window(monkeypatch, value):
    value["stage"], value["phase"] = "purge", "sleep"
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (value, 100))
    assert not probe.local_check("readiness", "purge")
    value["last_successful_cycle_monotonic"] = 99
    assert probe.local_check("readiness", "purge")
    value["phase"] = "failed"
    assert not probe.local_check("readiness", "purge")


@pytest.mark.parametrize("value", ["nan", "inf", "0", "31", "invalid"])
def test_probe_budget_invalid(monkeypatch, value):
    monkeypatch.setenv("SHADAI_PROBE_LIVE_SECONDS", value)
    with pytest.raises(ValueError):
        probe.budget("SHADAI_PROBE_LIVE_SECONDS", 30, 10, 30)


@pytest.mark.parametrize(
    "schema,lag,status,expected",
    [
        (False, 0, "healthy", False),
        (True, None, "healthy", False),
        (True, 0, "unknown", False),
        (True, 0, "blocked", False),
        (True, 0, "healthy", True),
    ],
)
async def test_readiness_requires_real_retention_and_each_known_stream(monkeypatch, schema, lag, status, expected):
    from types import SimpleNamespace

    class Context:
        async def __aenter__(self):
            return SimpleNamespace(execute=AsyncMock())

        async def __aexit__(self, *args):
            pass

    engine = SimpleNamespace(connect=lambda: Context(), dispose=AsyncMock())
    redis = SimpleNamespace(
        ping=AsyncMock(),
        aclose=AsyncMock(),
        time=AsyncMock(return_value=(100, 0)),
        xinfo_groups=AsyncMock(return_value=[{"name": "ingest_group", "lag": lag}]),
    )
    monkeypatch.setattr("sqlalchemy.ext.asyncio.create_async_engine", lambda *_: engine)
    monkeypatch.setattr("redis.asyncio.from_url", lambda *args, **kwargs: redis)
    retention = AsyncMock(return_value=schema)
    snapshots = AsyncMock(return_value={"status": status})
    monkeypatch.setattr("shadai.workers.redis_lifecycle.retention_ready", retention)
    monkeypatch.setattr("shadai.utils.operations.stream_snapshot", snapshots)
    monkeypatch.setattr(
        "shadai.database.init_clickhouse", lambda *_: SimpleNamespace(execute=lambda _: [(1,)], disconnect=lambda: None)
    )
    assert await probe.dependencies_ready("ingest") is expected
    assert engine.dispose.await_count == 1 and redis.aclose.await_count == 1
    if expected:
        assert snapshots.await_count == 9


@pytest.mark.skipif(os.name != "posix", reason="Linux private probe inode and mode semantics")
def test_private_probe_file_symlink_hardlink_partial_huge(proc, value, tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    path = root / "ingest.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    assert probe.read_probe("ingest", root=root, proc=proc, now=100)[0] == value
    path.write_text('{"partial":')
    with pytest.raises(ValueError):
        probe.read_probe("ingest", root=root, proc=proc, now=100)
    path.write_text(" " * 4097)
    with pytest.raises(ValueError):
        probe.read_probe("ingest", root=root, proc=proc, now=100)
    path.unlink()
    other = root / "other"
    other.write_text(json.dumps(value))
    other.chmod(0o600)
    path.symlink_to(other)
    with pytest.raises(OSError):
        probe.read_probe("ingest", root=root, proc=proc, now=100)
    path.unlink()
    os.link(other, path)
    with pytest.raises(ValueError):
        probe.read_probe("ingest", root=root, proc=proc, now=100)


class DelayedEmptyRedis:
    """Use the genuine redis-py socket deadline with a bounded synthetic parser."""

    def __init__(self, error=None):
        client = aioredis.from_url("redis://rca.invalid:6379/0", decode_responses=True)
        self.connection = client.connection_pool.make_connection()
        assert self.connection.socket_timeout == 5
        self.error = error
        self.xautoclaim = AsyncMock(return_value=["0-0", [], []])

    async def xreadgroup(self, *args, block, **kwargs):
        async def parser(**unused):
            if self.error:
                raise self.error
            # A server timeout need not be delivered at its exact deadline.
            await asyncio.sleep(block / 1000 + 0.05)
            return []

        self.connection._read_response_from_parser = parser
        return await self.connection.read_response(disconnect_on_error=False)


def process_witness(monkeypatch):
    witness = probe.ProcessProbe("ingest")
    now = time.monotonic()
    witness.data = {"initialized": True, "heartbeat_monotonic": now, "last_poll_monotonic": None,
                    "last_successful_cycle_monotonic": None, "phase": "idle", "phase_started_monotonic": now}
    monkeypatch.setattr(probe, "read_probe", lambda *args, **kwargs: (witness.data, time.monotonic()))
    return witness


async def test_idle_stream_returns_before_real_default_client_deadline(monkeypatch):
    witness = process_witness(monkeypatch)
    consumer = StreamConsumer(DelayedEmptyRedis(), "ingest_group", "deadline-test", ["events:dns"], probe=witness)
    task = asyncio.create_task(consumer.read())
    await asyncio.sleep(0)
    assert witness.data["phase"] == "poll" and witness.data["last_poll_monotonic"] is None
    assert probe.local_check("startup", "ingest") and probe.local_check("liveness", "ingest")
    assert not probe.local_check("readiness", "ingest")
    assert await task == []
    assert witness.data["last_poll_monotonic"] is not None
    assert probe.local_check("readiness", "ingest")


async def test_failed_stream_read_preserves_null_progress_and_unreadiness(monkeypatch):
    witness = process_witness(monkeypatch)
    failure = ConnectionError("synthetic dependency unavailable")
    consumer = StreamConsumer(DelayedEmptyRedis(failure), "ingest_group", "deadline-test", ["events:dns"],
                              probe=witness)
    with pytest.raises(ConnectionError) as caught:
        await consumer.read()
    assert caught.value is failure
    assert witness.data["last_poll_monotonic"] is None and witness.data["phase"] == "failed"
    assert probe.local_check("liveness", "ingest") and not probe.local_check("readiness", "ingest")


@pytest.mark.parametrize("changed,now,stage,reason", [
    ({"initialized": False}, 100, "ingest", "uninitialized"),
    ({"heartbeat_monotonic": 69}, 100, "ingest", "heartbeat_stale"),
    ({"phase": "starting"}, 100, "ingest", "phase_unready"),
    ({"phase": "blocked"}, 100, "ingest", "phase_unready"),
    ({"phase": "failed"}, 100, "ingest", "phase_unready"),
    ({"phase": "handler", "phase_started_monotonic": 1, "heartbeat_monotonic": 400}, 400, "ingest", "handler_stale"),
    ({"last_poll_monotonic": None}, 100, "ingest", "poll_missing"),
    ({"last_poll_monotonic": 9}, 100, "ingest", "poll_stale"),
    ({}, 100, "purge", "purge_cycle_stale"),
    ({"last_successful_cycle_monotonic": 0, "heartbeat_monotonic": 97300}, 97300, "purge", "purge_cycle_stale"),
    ({"phase": "purge", "last_successful_cycle_monotonic": 4000, "heartbeat_monotonic": 4000},
     4000, "purge", "purge_phase_stale"),
])
def test_each_local_readiness_refusal_keeps_boolean_and_records_only_fixed_reason(
        monkeypatch, value, changed, now, stage, reason):
    value.update(changed)
    monkeypatch.setattr(probe, "read_probe", lambda *a, **k: (value, now))
    assert probe.local_check("readiness", stage) is False
    sink = probe.ReadinessDiagnostic()
    assert probe.local_check("readiness", stage, diagnostic=sink) is False
    assert sink.envelope() == {"schema": 1, "reason": reason, "secondary_reason": "none"}
    assert CANARY not in json.dumps(sink.envelope())


@pytest.fixture
def cli_local(monkeypatch, value):
    alarms = []
    monkeypatch.setattr(probe, "read_probe", lambda *a, **k: (value, 100))
    monkeypatch.setattr(signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(signal, "signal", lambda *a: None)
    monkeypatch.setattr(signal, "setitimer", lambda *a: alarms.append(a), raising=False)
    return alarms


@pytest.mark.parametrize("mode", ["startup", "liveness", "readiness"])
def test_healthy_cli_keeps_empty_stdout_and_original_exit_code(cli_local, monkeypatch, capsys, mode):
    dependencies = AsyncMock(return_value=True)
    monkeypatch.setattr(probe, "dependencies_ready", dependencies)
    assert probe.main([mode, "--stage", "ingest"]) == 0
    assert capsys.readouterr() == ("", "")
    assert dependencies.await_count == (1 if mode == "readiness" else 0)
    assert cli_local == ([(0, 5), (0, 0)] if mode == "readiness" else [])


@pytest.mark.parametrize("mode", ["startup", "liveness"])
def test_nonreadiness_cli_failure_never_emits_diagnostic(cli_local, value, capsys, mode):
    value["initialized"] = False
    assert probe.main([mode, "--stage", "ingest"]) == 1
    assert capsys.readouterr() == ("", "") and not cli_local


def test_readiness_cli_failure_preserves_five_second_curfew_and_does_not_probe_dependencies(
        cli_local, value, monkeypatch, capsys):
    value["phase"] = "blocked"
    dependencies = AsyncMock()
    monkeypatch.setattr(probe, "dependencies_ready", dependencies)
    assert probe.main(["readiness", "--stage", "ingest"]) == 1
    output = capsys.readouterr()
    assert output.err == "" and len(output.out.encode()) <= 256
    assert probe.parse_readiness_diagnostic(output.out)["reason"] == "phase_unready"
    assert not dependencies.await_count and cli_local == [(0, 5), (0, 0)]


@pytest.mark.parametrize("cause,expected", [
    (ValueError(CANARY), "invalid_record"),
    (type(CANARY, (RuntimeError,), {})(CANARY), "invalid_record"),
])
def test_readiness_record_exception_and_attacker_class_never_expose_text(
        cli_local, monkeypatch, capsys, cause, expected):
    def invalid(*args, **kwargs):
        raise cause
    monkeypatch.setattr(probe, "read_probe", invalid)
    assert probe.main(["readiness", "--stage", "ingest"]) == 1
    raw = capsys.readouterr()
    assert CANARY not in raw.out and raw.err == ""
    assert probe.parse_readiness_diagnostic(raw.out)["reason"] == expected


def test_readiness_invalid_budget_is_classified_without_exposing_environment(cli_local, monkeypatch, capsys):
    monkeypatch.setenv("SHADAI_PROBE_LIVE_SECONDS", CANARY)
    assert probe.main(["readiness", "--stage", "ingest"]) == 1
    raw = capsys.readouterr()
    assert CANARY not in raw.out and raw.err == ""
    assert probe.parse_readiness_diagnostic(raw.out)["reason"] == "invalid_budget"


@pytest.fixture
def dependency_model(monkeypatch):
    calls = []
    state = SimpleNamespace(retention=True, groups=[{"name": "ingest_group", "lag": 0}], status="healthy",
                            faults={}, calls=calls)
    async def operation(name, result=None):
        calls.append(name)
        if name in state.faults:
            raise state.faults[name]
        return result
    class Context:
        async def __aenter__(self):
            await operation("postgres")
            return SimpleNamespace(execute=lambda sql: operation("postgres_select"))
        async def __aexit__(self, *args):
            calls.append("postgres_context_exit")
    def sync(name, result=None):
        calls.append(name)
        if name in state.faults:
            raise state.faults[name]
        return result
    engine = SimpleNamespace(connect=Context, dispose=lambda: operation("engine_dispose"))
    redis = SimpleNamespace(ping=lambda: operation("redis_ping"), aclose=lambda: operation("redis_close"),
                            time=lambda: operation("redis_time", (100, 0)),
                            xinfo_groups=lambda stream: operation("groups", state.groups))
    database = SimpleNamespace(postgres_url=CANARY, redis_url=CANARY)
    monkeypatch.setattr("shadai.config.load_config", lambda: sync("configuration", SimpleNamespace(database=database)))
    monkeypatch.setattr("sqlalchemy.ext.asyncio.create_async_engine", lambda url: sync("engine", engine))
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: sync("redis_client", redis))
    monkeypatch.setattr("shadai.workers.redis_lifecycle.retention_ready",
                        lambda client: operation("retention", state.retention))
    monkeypatch.setattr("shadai.utils.operations.stream_snapshot",
                        lambda *a: operation("snapshot", {"status": state.status}))
    ch = SimpleNamespace(execute=lambda sql: sync("clickhouse_select"), disconnect=lambda: sync("clickhouse_close"))
    monkeypatch.setattr("shadai.database.init_clickhouse", lambda config: sync("clickhouse", ch))
    return state


@pytest.mark.parametrize("fault,expected", [
    ("configuration", "configuration_error"), ("engine", "postgres_error"),
    ("postgres", "postgres_error"), ("postgres_select", "postgres_error"),
    ("redis_client", "redis_error"), ("redis_ping", "redis_error"), ("retention", "redis_error"),
    ("redis_time", "redis_error"), ("groups", "redis_error"), ("snapshot", "redis_error"),
    ("clickhouse", "clickhouse_error"), ("clickhouse_select", "clickhouse_error"),
])
async def test_each_dependency_exception_is_constant_and_preserves_existing_cleanup(
        dependency_model, fault, expected):
    state = dependency_model
    error = type(CANARY, (RuntimeError,), {})(CANARY)
    state.faults[fault] = error
    sink = probe.ReadinessDiagnostic()
    if fault in {"configuration", "engine"}:
        with pytest.raises(type(error)) as caught:
            await probe.dependencies_ready("ingest", diagnostic=sink)
        assert caught.value is error and not any(x.endswith("close") or x == "engine_dispose" for x in state.calls)
        sink.refuse(sink.current)
    else:
        assert await probe.dependencies_ready("ingest", diagnostic=sink) is False
        assert state.calls[-1] == "engine_dispose"
    assert sink.envelope()["reason"] == expected and CANARY not in json.dumps(sink.envelope())
    assert state.calls.count(fault) == 1


@pytest.mark.parametrize("kind,expected", [
    ("retention", "retention_unready"), ("missing_group", "group_unready"),
    ("duplicate_group", "group_unready"), ("unknown_lag", "group_unready"),
    ("blocked", "stream_unready"), ("unknown", "stream_unready"), ("stale", "stream_unready"),
    ("unknown_stage", "unknown_stage"),
])
async def test_each_dependency_boolean_refusal_remains_false(dependency_model, kind, expected):
    state = dependency_model
    if kind == "retention":
        state.retention = False
    elif kind == "missing_group":
        state.groups = []
    elif kind == "duplicate_group":
        state.groups *= 2
    elif kind == "unknown_lag":
        state.groups[0]["lag"] = None
    else:
        state.status = kind
    sink = probe.ReadinessDiagnostic()
    stage = "invalid-stage" if kind == "unknown_stage" else "ingest"
    assert await probe.dependencies_ready(stage, diagnostic=sink) is False
    assert sink.envelope()["reason"] == expected and state.calls[-2:] == ["redis_close", "engine_dispose"]
    assert "clickhouse" not in state.calls


async def test_dependency_timeout_keeps_original_cleanup_and_false(dependency_model):
    state = dependency_model
    state.faults["redis_ping"] = TimeoutError(CANARY)
    sink = probe.ReadinessDiagnostic()
    assert await probe.dependencies_ready("ingest", diagnostic=sink) is False
    assert sink.envelope()["reason"] == "dependencies_timeout"
    assert state.calls[-2:] == ["redis_close", "engine_dispose"]


@pytest.mark.parametrize("primary", [None, TimeoutError(CANARY), KeyboardInterrupt(CANARY),
                                    SystemExit(CANARY), asyncio.CancelledError(CANARY)])
@pytest.mark.parametrize("secondary", [RuntimeError(CANARY), KeyboardInterrupt(CANARY),
                                      SystemExit(CANARY), asyncio.CancelledError(CANARY)])
async def test_primary_reason_before_finally_and_secondary_cleanup_preserve_exception_flow(
        dependency_model, primary, secondary):
    state = dependency_model
    if primary is None:
        state.retention = False
        expected = "retention_unready"
    else:
        state.faults["redis_ping"] = primary
        expected = "dependencies_timeout" if type(primary) is TimeoutError else "cancelled"
    state.faults["redis_close"] = secondary
    sink = probe.ReadinessDiagnostic()
    with pytest.raises(type(secondary)) as caught:
        await probe.dependencies_ready("ingest", diagnostic=sink)
    assert caught.value is secondary
    assert sink.envelope() == {"schema": 1, "reason": expected, "secondary_reason": "dependency_cleanup_error"}
    assert state.calls[-1] == "redis_close" and "engine_dispose" not in state.calls
    assert CANARY not in json.dumps(sink.envelope())


@pytest.mark.parametrize("failure", ["redis_close", "clickhouse_close", "engine_dispose"])
async def test_cleanup_failure_after_healthy_dependencies_is_not_a_success(dependency_model, failure):
    state = dependency_model
    primary = RuntimeError(CANARY)
    state.faults[failure] = primary
    sink = probe.ReadinessDiagnostic()
    with pytest.raises(RuntimeError) as caught:
        await probe.dependencies_ready("ingest", diagnostic=sink)
    assert caught.value is primary and sink.envelope()["reason"] == "dependency_cleanup_error"
    assert state.calls[-1] == failure


@pytest.mark.parametrize("primary", [KeyboardInterrupt(CANARY), SystemExit(CANARY), asyncio.CancelledError(CANARY)])
async def test_dependency_cancellation_propagates_identical_object_after_same_cleanup(dependency_model, primary):
    state = dependency_model
    state.faults["redis_ping"] = primary
    sink = probe.ReadinessDiagnostic()
    with pytest.raises(type(primary)) as caught:
        await probe.dependencies_ready("ingest", diagnostic=sink)
    assert caught.value is primary and sink.envelope()["reason"] == "cancelled"
    assert state.calls[-2:] == ["redis_close", "engine_dispose"]


@pytest.mark.parametrize("reason", sorted(probe.READINESS_REASONS))
def test_every_reason_emits_only_three_builtin_typed_keys_within_limit(reason, capsys):
    sink = probe.ReadinessDiagnostic()
    sink.refuse(reason)
    sink.cleanup_failed()
    probe.emit_readiness_diagnostic(sink)
    raw = capsys.readouterr()
    assert raw.err == "" and len(raw.out.encode()) <= 256
    assert probe.parse_readiness_diagnostic(raw.out) == sink.envelope()


@pytest.mark.parametrize("raw", [
    None, True, {}, "", b"\xff", " " * 257,
    '{"schema":true,"reason":"poll_stale","secondary_reason":"none"}',
    '{"schema":1.0,"reason":"poll_stale","secondary_reason":"none"}',
    '{"schema":1,"schema":1,"reason":"poll_stale","secondary_reason":"none"}',
    '{"schema":1,"reason":"poll_stale","reason":"poll_stale","secondary_reason":"none"}',
    json.dumps({"schema": 1, "reason": CANARY, "secondary_reason": "none"}),
    json.dumps({"schema": 1, "reason": "poll_stale", "secondary_reason": CANARY}),
    json.dumps({"schema": 1, "reason": "poll_stale", "secondary_reason": "none", "pid": CANARY}),
    CANARY + '{"schema":1,"reason":"poll_stale","secondary_reason":"none"}',
    type("UntrustedString", (str,), {})("{}"),
    type("UntrustedBytes", (bytes,), {})(b"{}"),
])
def test_readiness_parser_refuses_untrusted_shape_types_duplicates_and_mixed_output(raw):
    assert probe.parse_readiness_diagnostic(raw) == {
        "schema": 1, "reason": "diagnostic_unavailable", "secondary_reason": "none"}


def test_mutated_sink_and_malicious_exception_names_cannot_enter_output(capsys):
    attacker = type(CANARY, (RuntimeError,), {})(CANARY)
    attacker.add_note(CANARY)
    sink = probe.ReadinessDiagnostic()
    sink.reason = attacker
    sink.secondary_reason = type("UntrustedString", (str,), {})(CANARY)
    probe.emit_readiness_diagnostic(sink)
    raw = capsys.readouterr()
    assert CANARY not in raw.out and raw.err == ""
    assert probe.parse_readiness_diagnostic(raw.out)["reason"] == "diagnostic_unavailable"


def test_cli_preserves_first_dependency_refusal_when_cleanup_also_fails(
        cli_local, dependency_model, capsys):
    dependency_model.retention = False
    dependency_model.faults["redis_close"] = RuntimeError(CANARY)
    assert probe.main(["readiness", "--stage", "ingest"]) == 1
    raw = capsys.readouterr()
    assert raw.err == "" and CANARY not in raw.out
    assert probe.parse_readiness_diagnostic(raw.out) == {
        "schema": 1, "reason": "retention_unready", "secondary_reason": "dependency_cleanup_error"}
    assert dependency_model.calls[-1] == "redis_close" and "engine_dispose" not in dependency_model.calls
    assert cli_local == [(0, 5), (0, 0)]


def test_diagnostic_output_refusal_cannot_change_failed_health_exit(cli_local, value, monkeypatch, capsys):
    value["phase"] = "blocked"
    class RefusedOutput:
        def write(self, raw):
            raise OSError(CANARY)
    with monkeypatch.context() as scoped:
        scoped.setattr(probe.sys, "stdout", RefusedOutput())
        assert probe.main(["readiness", "--stage", "ingest"]) == 1
    assert capsys.readouterr() == ("", "") and cli_local == [(0, 5), (0, 0)]


@pytest.mark.parametrize("defect", ["closed_stringio", "flush_value_error"])
def test_readiness_best_effort_closed_or_flush_valueerror_keeps_exit_one_and_curfew(
        cli_local, value, monkeypatch, capsys, defect):
    value["phase"] = "blocked"
    calls = []

    class FlushRefused:
        def write(self, raw):
            calls.append("write")
            return len(raw)

        def flush(self):
            calls.append("flush")
            raise ValueError(CANARY)

    stream = io.StringIO() if defect == "closed_stringio" else FlushRefused()
    if defect == "closed_stringio":
        stream.close()
    with monkeypatch.context() as scoped:
        scoped.setattr(probe.sys, "stdout", stream)
        assert probe.main(["readiness", "--stage", "ingest"]) == 1
    assert cli_local == [(0, 5), (0, 0)] and capsys.readouterr() == ("", "")
    assert calls == ([] if defect == "closed_stringio" else ["write", "flush"])


@pytest.mark.parametrize("operation", ["write", "flush"])
@pytest.mark.parametrize("primary", [KeyboardInterrupt(CANARY), SystemExit(7), asyncio.CancelledError(CANARY)])
def test_readiness_best_effort_does_not_swallow_baseexception_from_either_operation(
        cli_local, value, monkeypatch, capsys, operation, primary):
    value["phase"] = "blocked"
    calls = []

    class InterruptedOutput:
        def write(self, raw):
            calls.append("write")
            if operation == "write":
                raise primary
            return len(raw)

        def flush(self):
            calls.append("flush")
            raise primary

    with monkeypatch.context() as scoped:
        scoped.setattr(probe.sys, "stdout", InterruptedOutput())
        with pytest.raises(type(primary)) as caught:
            probe.main(["readiness", "--stage", "ingest"])
    assert caught.value is primary and cli_local == [(0, 5), (0, 0)]
    assert calls == (["write"] if operation == "write" else ["write", "flush"])
    assert capsys.readouterr() == ("", "")


def test_diagnostic_output_cancellation_is_not_swallowed(cli_local, value, monkeypatch, capsys):
    value["phase"] = "blocked"
    primary = KeyboardInterrupt(CANARY)
    class InterruptedOutput:
        def write(self, raw):
            raise primary
    with monkeypatch.context() as scoped:
        scoped.setattr(probe.sys, "stdout", InterruptedOutput())
        with pytest.raises(KeyboardInterrupt) as caught:
            probe.main(["readiness", "--stage", "ingest"])
    assert caught.value is primary and cli_local == [(0, 5), (0, 0)]
    assert capsys.readouterr() == ("", "")
