"""Identity, monotonic progress and local liveness fail closed per process."""

import copy
import json
import os
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from shadai.workers import probe


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
