"""Real disk/process durability and ownership checks; no network delivery claims."""

import hashlib
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from shadai.utils import delivery_spool
from shadai.utils.delivery_spool import DurableSpool, SpoolError, SpoolFullError

PAYLOAD = b'\x00{"event_id":"synthetic-restart-event","events":[]}\xff\n'
CHILD_SCRIPT = """
import json
import os
import sys
from shadai.utils import delivery_spool
from shadai.utils.delivery_spool import DurableSpool

# SQLite semantics only: sandbox ancestor safety is assumed. Leaf/database ACLs stay real.
delivery_spool._private_ancestors = lambda path: None
mode, directory, now, payload_hex = sys.argv[1:]
spool = DurableSpool(directory, clock=lambda: float(now))
payload = bytes.fromhex(payload_hex)
if mode == "before_commit":
    def crash_before_commit(statement):
        if statement.strip().upper() == "COMMIT":
            print(json.dumps({"stage": "before_commit"}), flush=True)
            os._exit(91)
    spool.db.set_trace_callback(crash_before_commit)
    spool.enqueue(payload)
    raise AssertionError("Expected process exit before commit")
if mode == "after_enqueue":
    batch_id = spool.enqueue(payload)
    print(json.dumps({"batch_id": batch_id}), flush=True)
    os._exit(92)
batches = spool.claim(limit=1, lease_seconds=10)
result = {
    "batches": [{"batch_id": batch.batch_id, "payload_hex": batch.payload.hex(),
                 "token": batch.token} for batch in batches],
    "stats": spool.stats(),
}
print(json.dumps(result), flush=True)
if mode == "lost_ack":
    os._exit(93)
spool.close()
"""


@pytest.fixture
def sqlite_with_assumed_safe_ancestors(monkeypatch):
    """Isolate sandbox ancestry only; real SQLite and leaf/database ACL guards remain."""
    monkeypatch.setattr(delivery_spool, "_private_ancestors", lambda path: None)


def child_spool(directory, mode, *, now=1000):
    environment = os.environ.copy()
    source = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", CHILD_SCRIPT, mode, str(directory), str(now), PAYLOAD.hex()],
        env=environment, capture_output=True, text=True, timeout=30, check=False,
    )


def recovered(directory, *, now=1000):
    process = child_spool(directory, "recover", now=now)
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


def test_sandbox_sqlite_crash_before_commit_rolls_back_bytes_and_counters(tmp_path, sqlite_with_assumed_safe_ancestors):
    directory = tmp_path / "before-commit"
    process = child_spool(directory, "before_commit")
    assert process.returncode == 91, process.stderr
    assert json.loads(process.stdout) == {"stage": "before_commit"}
    assert (directory / "delivery.sqlite3").is_file()
    result = recovered(directory)
    assert result["batches"] == []
    assert result["stats"]["batches"] == result["stats"]["payload_bytes"] == 0
    assert result["stats"].get("enqueued", 0) == 0


def test_sandbox_sqlite_crash_after_enqueue_preserves_bytes_and_identity(tmp_path, sqlite_with_assumed_safe_ancestors):
    directory = tmp_path / "after-enqueue"
    process = child_spool(directory, "after_enqueue")
    assert process.returncode == 92, process.stderr
    batch_id = hashlib.sha256(PAYLOAD).hexdigest()
    assert json.loads(process.stdout) == {"batch_id": batch_id}
    result = recovered(directory)
    assert len(result["batches"]) == 1
    assert result["batches"][0]["batch_id"] == batch_id
    assert bytes.fromhex(result["batches"][0]["payload_hex"]) == PAYLOAD
    assert result["stats"]["enqueued"] == result["stats"]["pending"] == 1
    assert result["stats"]["payload_bytes"] == len(PAYLOAD)


def test_sandbox_sqlite_lost_ack_waits_for_lease_then_redelivers(tmp_path, sqlite_with_assumed_safe_ancestors):
    directory = tmp_path / "lost-ack"
    with DurableSpool(directory, clock=lambda: 1000) as spool:
        batch_id = spool.enqueue(PAYLOAD)
    process = child_spool(directory, "lost_ack")
    assert process.returncode == 93, process.stderr
    first = json.loads(process.stdout)["batches"][0]
    blocked = recovered(directory, now=1009)
    assert blocked["batches"] == [] and blocked["stats"]["pending"] == 1
    second = recovered(directory, now=1011)["batches"][0]
    assert first["batch_id"] == second["batch_id"] == batch_id
    assert first["payload_hex"] == second["payload_hex"] == PAYLOAD.hex()
    assert first["token"] != second["token"]


def test_sandbox_sqlite_concurrent_connections_cannot_double_claim(tmp_path, sqlite_with_assumed_safe_ancestors):
    directory = tmp_path / "concurrent"
    with DurableSpool(directory, clock=lambda: 1000) as spool:
        batch_id = spool.enqueue(PAYLOAD)
    barrier = threading.Barrier(2)
    finish = threading.Barrier(2)

    def claim():
        with DurableSpool(directory, clock=lambda: 1000) as spool:
            barrier.wait(timeout=15)
            batches = spool.claim(limit=1, lease_seconds=10)
            finish.wait(timeout=15)
            return batches

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda _: claim(), range(2)))
    assert sorted(len(batches) for batches in claims) == [0, 1]
    claimed = [batch for batches in claims for batch in batches]
    assert [batch.batch_id for batch in claimed] == [batch_id]
    assert claimed[0].payload == PAYLOAD


def test_sandbox_sqlite_stale_owner_cannot_change_resumed_batch(tmp_path, sqlite_with_assumed_safe_ancestors):
    now = [1000]
    directory = tmp_path / "ownership"
    with DurableSpool(directory, clock=lambda: now[0]) as first:
        first.enqueue(PAYLOAD)
        old = first.claim(limit=1, lease_seconds=10)[0]
        with DurableSpool(directory, clock=lambda: now[0]) as second:
            assert second.claim(limit=1) == []
            now[0] = 1011
            current = second.claim(limit=1)[0]
            assert current.batch_id == old.batch_id and current.payload == old.payload
            assert current.token != old.token
            assert first.ack(old) is False
            assert first.retry(old, delay=0) is False
            assert first.quarantine(old, "stale_owner") is False
            assert second.stats()["pending"] == 1
            assert second.ack(current) is True
            assert second.stats()["batches"] == 0
            assert second.stats()["delivered"] == 1


@pytest.mark.parametrize("budget", [{"max_bytes": 8}, {"max_batches": 1}])
def test_sandbox_sqlite_quota_keeps_batch_and_overflow_counter(tmp_path, budget, sqlite_with_assumed_safe_ancestors):
    directory = tmp_path / "quota"
    with DurableSpool(directory, clock=lambda: 1000, **budget) as spool:
        batch_id = spool.enqueue(b"first0")
        with pytest.raises(SpoolFullError, match="spool_budget_exceeded"):
            spool.enqueue(b"last1")
        assert spool.stats()["overflow"] == 1
        assert spool.stats()["batches"] == 1 and spool.stats()["payload_bytes"] == 6
    with DurableSpool(directory, clock=lambda: 1000, **budget) as reopened:
        assert reopened.stats()["overflow"] == 1
        batches = reopened.claim(limit=1)
        assert [(batch.batch_id, batch.payload) for batch in batches] == [(batch_id, b"first0")]
        assert reopened.ack(batches[0]) is True
        assert reopened.claim(limit=1) == []


def test_sandbox_sqlite_expiry_releases_quarantine_budget(tmp_path, sqlite_with_assumed_safe_ancestors):
    now = [1000]
    directory = tmp_path / "expiry"
    with DurableSpool(directory, max_bytes=8, max_batches=1, ttl_seconds=10, clock=lambda: now[0]) as spool:
        spool.enqueue(b"first0")
        batch = spool.claim(limit=1)[0]
        assert spool.quarantine(batch, "terminal_status") is True
        assert spool.stats()["quarantine"] == 1
        with pytest.raises(SpoolFullError):
            spool.enqueue(b"last1")
        now[0] = 1011
        assert spool.claim(limit=1) == []
        stats = spool.stats()
        assert stats["expired"] == 1 and stats["batches"] == stats["payload_bytes"] == 0
        new_id = spool.enqueue(b"last1")
    with DurableSpool(directory, max_bytes=8, max_batches=1, ttl_seconds=10, clock=lambda: now[0]) as reopened:
        assert reopened.stats()["expired"] == reopened.stats()["overflow"] == 1
        assert reopened.stats()["quarantine"] == 0
        assert [(batch.batch_id, batch.payload) for batch in reopened.claim(limit=1)] == [(new_id, b"last1")]


def grant_broad_permissions(path, *, directory, rights="Read"):
    if os.name == "nt":
        executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/icacls.exe"
        permission = "M" if rights == "Modify" else "R"
        result = subprocess.run(
            [str(executable), str(path), "/grant", "*S-1-5-32-545:" + permission, "/Q"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        assert result.returncode == 0, result.stderr
    else:
        path.chmod(0o777 if rights == "Modify" else (0o755 if directory else 0o644))


@pytest.mark.parametrize("directory", [True, False])
def test_real_leaf_dacl_rejects_broad_read_permissions(tmp_path, directory):
    root = tmp_path / "private-leaf"
    if os.name == "nt":
        assert delivery_spool._windows_private(root, create=True) is True
    else:
        root.mkdir(mode=0o700)
    path = root if directory else root / "delivery.sqlite3"
    if not directory:
        path.write_bytes(b"synthetic-private-database")
        if os.name != "nt":
            path.chmod(0o600)
    delivery_spool._check_path(path, directory=directory)
    grant_broad_permissions(path, directory=directory)
    with pytest.raises(SpoolError, match="spool_private_(acl|permissions)_required"):
        delivery_spool._check_path(path, directory=directory)


def test_real_writable_ancestor_is_rejected(tmp_path):
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    grant_broad_permissions(parent, directory=True, rights="Modify")
    with pytest.raises(SpoolError, match="spool_unsafe_parent"):
        delivery_spool._private_ancestors(parent / "spool")


@pytest.mark.parametrize("nested", [False, True])
def test_directory_link_and_link_ancestor_cannot_redirect_spool(tmp_path, nested):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    try:
        directory = link / "nested-spool" if nested else link
        with pytest.raises(SpoolError, match="spool_unsafe_path"):
            DurableSpool(directory)
        assert list(target.iterdir()) == []
    finally:
        if link.is_symlink():
            link.unlink()
        else:
            link.rmdir()
