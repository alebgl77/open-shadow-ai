"""Mandatory two-phase pressure/AOF acceptance for the isolated lab service."""

import hashlib
import json
import os
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import OutOfMemoryError
from redis_pressure_fixture import pressure_connection, sustained_pressure

from shadai.config import RedisQueueSettings
from shadai.utils.delivery_spool import _check_path, _private_ancestors, _private_directory
from shadai.utils.queue_admission import SCHEMA_KEY, STREAMS, admit_records
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.redis_lifecycle import purge, raw_range, reconcile, refs_key, retention_ready
from shadai.workers.replay import replay_deadletters
from shadai.workers.streams import StreamConsumer

pytestmark = [pytest.mark.integration, pytest.mark.redis_pressure,
              pytest.mark.skipif(os.environ.get("SHADAI_REQUIRE_REDIS_PRESSURE") != "1",
                                 reason="Dedicated pressure mode not requested")]


def field_hash(fields):
    digest = hashlib.sha256()
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


def write_manifest(path, value):
    path = path.absolute()
    _private_directory(path.parent)
    _private_ancestors(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf8") as file:
        _check_path(path, directory=False)
        json.dump(value, file, separators=(",", ":"), sort_keys=True)
        file.flush()
        os.fsync(file.fileno())
        _check_path(path, directory=False)


def read_manifest(path):
    _private_ancestors(path)
    _check_path(path, directory=False)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "r", encoding="utf8") as file:
        value = json.loads(file.read(65537))
    if value.get("version") != 1 or value.get("kind") != "redis-pressure-aof":
        raise ValueError("Invalid pressure restore manifest")
    return value


async def exercise_oom(redis):
    assert await redis.dbsize() == 0, "Pressure seed fixture must initially be empty"
    payload = [{"stream": "events:dns", "fields": {"data": "immutable pressure synthetic"}},
               {"stream": "events:proxy", "fields": {"data": "immutable pressure synthetic"}}]
    async with sustained_pressure(redis, prefix="pressure:fill:", chunk_bytes=256 * 1024, max_fill=256) as proof:
        # A refused first allocation/EVAL leaves both destinations unchanged.
        with pytest.raises(OutOfMemoryError):
            await admit_records(redis, payload)
        assert await redis.xlen("events:dns") == await redis.xlen("events:proxy") == 0
    identifiers = await admit_records(redis, payload)
    assert len(identifiers) == 2
    for row, ident in zip(payload, identifiers, strict=True):
        assert (await redis.xrange(row["stream"], ident, ident))[0][1] == row["fields"]
    await redis.delete("events:dns", "events:proxy")
    return proof


async def seed_graph(redis):
    settings = RedisQueueSettings()
    source, group = "events:dns", "ingest_group"
    consumer = StreamConsumer(redis, group, "seed", [source], max_attempts=1, settings=settings)
    await consumer.initialize()
    await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=settings)
    fields = {"data": "synthetic immutable source", "accepted_at": "2000-01-01T00:00:00+00:00"}
    ident = await redis.xadd(source, fields, id="1-0")
    await redis.xreadgroup(group, "seed", {source: ">"})
    assert await consumer.process(source, ident, fields, AsyncMock(side_effect=PermanentMessageError()))
    replay = (await replay_deadletters(redis, group, execute=True, settings=settings))[0]
    pointer = replay["pointer_id"]
    marker = f"replayed:{group}:{pointer}"
    # Separate old, ACKed legacy records exercise post-restore GC under the
    # real TIME cutoff. The graph is explicitly reconciled with stopped writers.
    await redis.xgroup_create("matches", "correlate_group", "0", mkstream=True)
    await redis.xadd("matches", {"event": "old synthetic correlation"}, id="1-0")
    await redis.xreadgroup("correlate_group", "seed", {"matches": ">"})
    await redis.xack("matches", "correlate_group", "1-0")
    await redis.xadd("deadletter:correlate_group", {"stream": "matches", "message_id": "1-0"}, id="2-0")
    await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=settings)
    await redis.xgroup_create("events:browser", group, "0", mkstream=True)
    pending = await redis.xadd("events:browser", {"data": "pending synthetic"}, id="3-0")
    await redis.xreadgroup(group, "crashed", {"events:browser": ">"})
    raw_source = (await raw_range(redis, source, start=ident, end=ident))[0][1]
    raw_pointer = (await raw_range(redis, "deadletter:" + group, start=pointer, end=pointer))[0][1]
    # Wait for the exact fixture writes to reach local AOF; host then stops and
    # restores only this labeled lab volume into a new disposable project.
    waited = await redis.execute_command("WAITAOF", 1, 0, 5000)
    assert waited[0] == 1
    return {"version": 1, "kind": "redis-pressure-aof", "source_id": ident, "pointer_id": pointer,
            "replay_id": replay["replay_id"], "pending_id": pending, "marker": marker,
            "source_sha256": field_hash(raw_source), "pointer_sha256": field_hash(raw_pointer),
            "server_run_id": (await redis.info("server"))["run_id"]}


async def assert_restored(redis, manifest):
    run_id = (await redis.info("server"))["run_id"]
    assert run_id != manifest["server_run_id"], "Restore must start another Redis process"
    assert await retention_ready(redis)
    source, group = "events:dns", "ingest_group"
    raw_source = (await raw_range(redis, source, start=manifest["source_id"], end=manifest["source_id"]))[0][1]
    raw_pointer = (await raw_range(redis, "deadletter:" + group, start=manifest["pointer_id"],
                                   end=manifest["pointer_id"]))[0][1]
    assert field_hash(raw_source) == manifest["source_sha256"]
    assert field_hash(raw_pointer) == manifest["pointer_sha256"]
    assert await redis.hget(refs_key(source), manifest["source_id"]) == "1"
    assert await redis.get(manifest["marker"]) == manifest["replay_id"]
    assert (await redis.xpending("events:browser", group))["pending"] == 1
    assert (await redis.xpending_range("events:browser", group, "-", "+", 1))[0]["message_id"] == manifest["pending_id"]
    original_count = await redis.xlen(source)
    replay = (await replay_deadletters(redis, group, execute=True))[0]
    assert replay["status"] == "already_replayed" and replay["replay_id"] == manifest["replay_id"]
    assert await redis.xlen(source) == original_count
    assert (await raw_range(redis, source, start=manifest["replay_id"], end=manifest["replay_id"]))[0][1] == raw_source
    result = await purge(redis, "correlate_group", execute=True, discard=True)
    assert result["results"][0]["status"] == "pointer_purged"
    assert await redis.xlen("matches") == await redis.xlen("deadletter:correlate_group") == 0
    assert await redis.hget(refs_key("matches"), "1-0") is None
    assert await redis.hget(refs_key("matches"), "__schema") == "1"
    assert await redis.xrange(source, manifest["source_id"], manifest["source_id"])
    # No expiry/trim on any source, or on fixed reference indexes.
    assert await redis.get(SCHEMA_KEY) == "1"
    assert all([await redis.ttl(refs_key(stream)) == -1 for stream in STREAMS])


async def test_required_pressure_and_aof_phase(record_property):
    # In required mode missing credentials/service/settings raises and FAILS;
    # the host prerequisite CLI also exits 2, never a silent green skip.
    redis, mode, path = await pressure_connection()
    try:
        if mode == "seed":
            proof = await exercise_oom(redis)
            for key, value in proof.items():
                record_property(key, value)
            write_manifest(path, {**await seed_graph(redis), "pressure_injection": proof})
        else:
            await assert_restored(redis, read_manifest(path))
    finally:
        await redis.aclose()
