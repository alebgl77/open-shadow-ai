"""Actual Lua admission/retention race tests against an explicitly disposable DB."""

import asyncio
import os
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as aioredis
from queue_integration_fixtures import queue_redis as _queue_redis  # noqa: F401

from shadai.config import RedisQueueSettings, get_config
from shadai.utils.queue_admission import SCHEMA_KEY, QueueAdmissionError, admit_records
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.redis_lifecycle import (
    ACK_SUCCESS,
    DEADLETTER,
    PURGE,
    RECONCILE,
    purge,
    raw_range,
    reconcile,
    refs_key,
)
from shadai.workers.replay import replay_deadletters
from shadai.workers.streams import StreamConsumer

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(os.environ.get("SHADAI_INTEGRATION") != "1", reason="Disposable Redis not requested")]
STREAM, GROUP, DLQ = "events:dns", "ingest_group", "deadletter:ingest_group"


async def initialized(redis, *, settings=None):
    await redis.xgroup_create(STREAM, GROUP, "0", mkstream=True)
    await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=settings)


async def old_pointer(redis, *, source="1-0", pointer="2-0", fields=None):
    fields = fields or {"data": '{"timestamp":"2099-01-01T00:00:00Z","accepted_at":"2099-01-01"}'}
    if not await redis.xrange(STREAM, source, source):
        await redis.xadd(STREAM, fields, id=source)
        await redis.xreadgroup(GROUP, "owner", {STREAM: ">"}, count=500)
        await redis.xack(STREAM, GROUP, source)
    await redis.xadd(DLQ, {"stream": STREAM, "message_id": source, "error_type": "Synthetic", "attempts": "1"},
                     id=pointer)
    await reconcile(redis, execute=True, legacy_writers_stopped=True)
    return source, pointer


async def raw_purge(redis, ident, pointer="", cutoff="9007199254740993-0", source_fields=None, pointer_fields=None):
    original = await raw_range(redis, STREAM, start=ident, end=ident)
    pointers = await raw_range(redis, DLQ, start=pointer, end=pointer) if pointer else []
    fields = original[0][1] if original else []
    pfields = pointers[0][1] if pointers else []
    if source_fields is not None:
        fields = source_fields
    if pointer_fields is not None:
        pfields = pointer_fields
    return await redis.eval(PURGE, 5, STREAM, refs_key(STREAM), SCHEMA_KEY, DLQ,
                            f"replayed:{GROUP}:{pointer}", GROUP, ident, pointer, cutoff,
                            len(fields), *fields, len(pfields), *pfields)


async def test_two_producers_compete_for_last_slot(queue_redis):
    settings = RedisQueueSettings(stream_max_entries=1)
    rows = [{"stream": STREAM, "fields": {"data": "same immutable payload"}}]
    result = await asyncio.gather(admit_records(queue_redis, rows, settings=settings),
                                  admit_records(queue_redis, rows, settings=settings), return_exceptions=True)
    assert sum(isinstance(row, list) for row in result) == 1
    assert sum(isinstance(row, QueueAdmissionError) for row in result) == 1
    assert await queue_redis.xlen(STREAM) == 1


async def test_capacity_accumulates_repeated_destination(queue_redis):
    await queue_redis.xadd(STREAM, {"data": "existing"})
    with pytest.raises(QueueAdmissionError):
        await admit_records(queue_redis, [{"stream": STREAM, "fields": {"data": "a"}},
                                         {"stream": STREAM, "fields": {"data": "b"}}],
                            settings=RedisQueueSettings(stream_max_entries=2))
    assert await queue_redis.xlen(STREAM) == 1


async def test_matches_capacity_keeps_actual_postgres_receipt_uncommitted_and_source_pending(queue_redis):
    """Real PostgreSQL rollback and Redis PEL; ClickHouse calls are isolated here."""
    import subprocess
    import sys
    from types import SimpleNamespace
    from unittest.mock import Mock

    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from shadai.models.event import CanonicalEvent
    from shadai.models.receipts import IngestReceiptORM
    from shadai.utils.queueing import queue_fields
    from shadai.workers.ingest import EventProcessor

    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True)
    config = get_config()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    event = CanonicalEvent(domain="synthetic.example.test", tenant_id=config.tenant_id)
    match = SimpleNamespace(catalog_item_id="synthetic", matched_field="domain", match_confidence=0.6)
    matcher = SimpleNamespace(upstream_match=lambda value: None, match_event=lambda value: match)
    clickhouse = SimpleNamespace(execute=Mock())
    processor = EventProcessor(queue_redis, clickhouse, sessions, matcher,
                               settings=RedisQueueSettings(stream_max_entries=1))
    now = [1000.0]
    consumer = StreamConsumer(queue_redis, GROUP, "owner", [STREAM], clock=lambda: now[0])
    try:
        await consumer.initialize()
        await reconcile(queue_redis, execute=True, legacy_writers_stopped=True)
        [ident] = await admit_records(queue_redis, [{"stream": STREAM,
                                                   "fields": queue_fields(event.model_dump_json())}])
        [(_, [(returned, fields)])] = await consumer.read()
        assert returned == ident
        await queue_redis.xadd("matches", {"event": "synthetic existing"})
        assert not await consumer.process(STREAM, ident, fields, processor)
        assert clickhouse.execute.call_count == 1
        assert await queue_redis.hget(f"retries:{GROUP}:{STREAM}:{ident}", "poison_attempts") == "0"
        assert consumer.counters["retryable_failures"] == 1
        async with sessions() as session:
            assert await session.get(IngestReceiptORM, event.event_id) is None
        assert (await queue_redis.xpending(STREAM, GROUP))["pending"] == 1
        assert await queue_redis.xlen("matches") == 1
        await queue_redis.delete("matches")
        now[0] += 1000
        assert await consumer.process(STREAM, ident, fields, processor)
        assert clickhouse.execute.call_count == 2
        async with sessions() as session:
            assert await session.get(IngestReceiptORM, event.event_id) is not None
        assert (await queue_redis.xpending(STREAM, GROUP))["pending"] == 0
        assert await queue_redis.xlen(STREAM) == 0 and await queue_redis.xlen("matches") == 1
        assert not await queue_redis.exists(f"retries:{GROUP}:{STREAM}:{ident}")
        [(_, matched)] = await queue_redis.xrange("matches")
        assert CanonicalEvent.model_validate_json(matched["event"]).event_id == event.event_id
    finally:
        async with sessions.begin() as session:
            await session.execute(delete(IngestReceiptORM).where(IngestReceiptORM.event_id == event.event_id))
        await engine.dispose()


@pytest.mark.parametrize("bad", ["dlq", "retry", "refs", "schema", "op", "numeric"])
async def test_deadletter_validates_every_key_before_pointer_write(queue_redis, bad):
    await initialized(queue_redis)
    ident = await queue_redis.xadd(STREAM, {"data": "poison"})
    await queue_redis.xreadgroup(GROUP, "owner", {STREAM: ">"})
    retry = f"retries:{GROUP}:{STREAM}:{ident}"
    operation = f"operations:{GROUP}:{STREAM}"
    keys = [STREAM, DLQ, retry, refs_key(STREAM), SCHEMA_KEY, operation]
    selected = {"dlq": DLQ, "retry": retry, "refs": refs_key(STREAM), "schema": SCHEMA_KEY,
                "op": operation, "numeric": operation}[bad]
    await queue_redis.delete(selected)
    if bad == "schema":
        await queue_redis.hset(selected, "wrongtype", "1")
    elif bad == "numeric":
        await queue_redis.hset(selected, "deadlettered", "01")
    else:
        await queue_redis.set(selected, "wrongtype")
    with pytest.raises(Exception):
        await queue_redis.eval(DEADLETTER, len(keys), *keys, GROUP, ident, "Synthetic", "1", "10")
    assert (await queue_redis.xpending(STREAM, GROUP))["pending"] == 1
    assert await queue_redis.xrange(STREAM, ident, ident)
    assert await queue_redis.xlen(DLQ) == 0 if bad != "dlq" else await queue_redis.get(DLQ) == "wrongtype"


@pytest.mark.parametrize("failure", ["full", "wrongtype"])
async def test_second_destination_refuses_entire_batch(queue_redis, failure):
    second = "matches"
    if failure == "full":
        await queue_redis.xadd(second, {"event": "already full"})
    else:
        await queue_redis.set(second, "wrongtype")
    with pytest.raises(QueueAdmissionError):
        await admit_records(queue_redis, [{"stream": STREAM, "fields": {"data": "first"}},
                                         {"stream": second, "fields": {"event": "second"}}],
                            settings=RedisQueueSettings(stream_max_entries=1))
    assert await queue_redis.xlen(STREAM) == 0
    assert (await queue_redis.xlen(second) if failure == "full" else await queue_redis.get(second)) == (
        1 if failure == "full" else "wrongtype")


@pytest.mark.parametrize("endpoint", ["events", "telemetry"])
@pytest.mark.parametrize("failure", ["full", "wrongtype"])
async def test_real_http_refusal_has_no_positive_contact_or_partial_enqueue(
    queue_redis, monkeypatch, endpoint, failure,
):
    from datetime import UTC, datetime
    from types import SimpleNamespace
    from unittest.mock import Mock

    import httpx
    from fastapi import FastAPI

    from shadai.api import agent, ingestion
    from shadai.api.collectors import authenticate_collector
    from shadai.config import get_config
    from shadai.models.event import CanonicalEvent

    monkeypatch.setattr(get_config().redis_queue, "stream_max_entries", 1)
    first, second = ("events:dns", "events:proxy") if endpoint == "events" else ("events:endpoint", "events:browser")
    if failure == "full":
        await queue_redis.xadd(second, {"data": "synthetic full"})
    else:
        await queue_redis.set(second, "wrongtype")
    app = FastAPI()
    app.include_router(ingestion.router)
    app.include_router(agent.router)
    principal = SimpleNamespace(legacy=True, collector_id="legacy:unattributed", require_sources=Mock(),
                                bind=lambda identity: "legacy:unattributed", contact=Mock())
    app.dependency_overrides[authenticate_collector] = lambda: principal
    monkeypatch.setattr(ingestion, "get_redis", AsyncMock(return_value=queue_redis))
    monkeypatch.setattr(agent, "get_redis", AsyncMock(return_value=queue_redis))
    if endpoint == "events":
        body = {"events": [CanonicalEvent(source_type=source, collector_id="synthetic",
                                           tenant_id=get_config().tenant_id).model_dump(mode="json")
                           for source in ("dns", "proxy")]}
        path = "/api/v1/ingest/events"
    else:
        body = {"hostname": "synthetic", "timestamp": datetime.now(UTC).isoformat(),
                "processes": [{"name": "synthetic"}], "extensions": [{"id": "synthetic"}]}
        path = "/api/v1/agent/telemetry"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
        response = await client.post(path, json=body)
    assert response.status_code == 503 and response.headers["Retry-After"] == "5"
    principal.contact.assert_not_called()
    assert await queue_redis.xlen(first) == 0


async def test_dlq_full_keeps_source_pending_without_trimming(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    ident = await queue_redis.xadd(STREAM, {"data": "poison"})
    await queue_redis.xreadgroup(GROUP, "owner", {STREAM: ">"})
    consumer = StreamConsumer(queue_redis, GROUP, "owner", [STREAM], max_attempts=1,
                              settings=RedisQueueSettings(dlq_max_entries=1))
    assert not await consumer.process(STREAM, ident, {}, AsyncMock(side_effect=PermanentMessageError()))
    assert (await queue_redis.xpending(STREAM, GROUP))["pending"] == 1
    assert await queue_redis.xlen(DLQ) == 1 and await queue_redis.xrange(DLQ, "2-0", "2-0")
    assert await queue_redis.xrange(STREAM, ident, ident)


@pytest.mark.parametrize("index", ["missing", "bad_sentinel", "bad_counter", "wrongtype", "schema"])
async def test_corrupt_or_missing_index_cannot_delete_source(queue_redis, index):
    await initialized(queue_redis)
    ident = await queue_redis.xadd(STREAM, {"data": "synthetic"}, id="1-0")
    await queue_redis.xreadgroup(GROUP, "owner", {STREAM: ">"})
    key = refs_key(STREAM)
    if index == "missing":
        await queue_redis.delete(key)
    elif index == "bad_sentinel":
        await queue_redis.hset(key, "__schema", "invalid")
    elif index == "bad_counter":
        await queue_redis.hset(key, ident, "invalid")
    elif index == "wrongtype":
        await queue_redis.delete(key)
        await queue_redis.set(key, "invalid")
    else:
        await queue_redis.set(SCHEMA_KEY, "building")
    assert await queue_redis.eval(ACK_SUCCESS, 3, STREAM, key, SCHEMA_KEY, GROUP, ident) == 1
    assert await queue_redis.xrange(STREAM, ident, ident)
    assert await raw_purge(queue_redis, ident) in {"invalid_state", "invalid_index"}
    assert await queue_redis.xrange(STREAM, ident, ident)


async def test_multiple_refs_protect_until_last_pointer_purge(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    await old_pointer(queue_redis, pointer="3-0")
    assert await queue_redis.hget(refs_key(STREAM), "1-0") == "2"
    await queue_redis.xclaim(STREAM, GROUP, "owner", 0, ["1-0"], force=True)
    assert await queue_redis.eval(ACK_SUCCESS, 3, STREAM, refs_key(STREAM), SCHEMA_KEY, GROUP, "1-0") == 1
    assert await queue_redis.xrange(STREAM, "1-0", "1-0")
    assert await raw_purge(queue_redis, "1-0", "2-0") == "pointer_purged"
    assert await queue_redis.xrange(STREAM, "1-0", "1-0")
    assert await raw_purge(queue_redis, "1-0", "3-0") == "pointer_purged"
    assert not await queue_redis.xrange(STREAM, "1-0", "1-0")
    assert await queue_redis.hget(refs_key(STREAM), "__schema") == "1"
    assert await queue_redis.hget(refs_key(STREAM), "1-0") is None


@pytest.mark.parametrize("extra", ["unread", "pending", "source_zero", "missing_owner", "too_many", "dlq_pending"])
async def test_gc_checks_all_current_groups_atomically(queue_redis, extra):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    if extra in {"unread", "pending"}:
        await queue_redis.xgroup_create(STREAM, "extra", "0")
        if extra == "pending":
            await queue_redis.xreadgroup("extra", "reader", {STREAM: ">"})
    elif extra == "source_zero":
        await queue_redis.xgroup_destroy(STREAM, GROUP)
    elif extra == "missing_owner":
        await queue_redis.xgroup_create(STREAM, "other", "$" )
        await queue_redis.xgroup_destroy(STREAM, GROUP)
    elif extra == "too_many":
        for index in range(16):
            await queue_redis.xgroup_create(STREAM, f"extra-{index}", "$")
    else:
        await queue_redis.xgroup_create(DLQ, "audit", "0")
        await queue_redis.xreadgroup("audit", "reader", {DLQ: ">"})
    assert await raw_purge(queue_redis, "1-0", "2-0") in {"source_in_use", "pointer_in_use"}
    assert await queue_redis.xlen(DLQ) == 1 and await queue_redis.xlen(STREAM) == 1
    if extra in {"unread", "pending", "dlq_pending"}:
        selected, group, ident = (DLQ, "audit", "2-0") if extra == "dlq_pending" else (STREAM, "extra", "1-0")
        if extra == "unread":
            await queue_redis.xreadgroup(group, "reader", {selected: ">"})
        await queue_redis.xack(selected, group, ident)
        assert await raw_purge(queue_redis, "1-0", "2-0") == "pointer_purged"


async def test_archived_group_scan_does_not_miss_new_group(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    archived = (await raw_range(queue_redis, STREAM, start="1-0", end="1-0"))[0][1]
    await queue_redis.xgroup_create(STREAM, "created_after_archive", "0")
    assert await raw_purge(queue_redis, "1-0", "2-0", source_fields=archived) == "source_in_use"


async def test_gc_uses_redis_creation_not_event_time_and_exact_large_ids(queue_redis):
    await initialized(queue_redis)
    # A future payload timestamp cannot protect an ancient Redis entry.
    await old_pointer(queue_redis)
    result = await purge(queue_redis, GROUP, execute=True, discard=True)
    assert result["results"][0]["status"] == "pointer_purged"
    old = "9007199254740992-0"
    await queue_redis.xadd(STREAM, {"data": "ancient event timestamp"}, id=old)
    await queue_redis.xreadgroup(GROUP, "owner", {STREAM: ">"})
    await queue_redis.xack(STREAM, GROUP, old)
    assert await raw_purge(queue_redis, old, cutoff="9007199254740993-0") == "source_purged"
    new = "9007199254740993-0"
    await queue_redis.xadd(STREAM, {"data": "ancient event timestamp"}, id=new)
    await queue_redis.xreadgroup(GROUP, "owner", {STREAM: ">"})
    await queue_redis.xack(STREAM, GROUP, new)
    assert await raw_purge(queue_redis, new, cutoff="9007199254740993-0") == "too_young"


async def test_changed_archive_record_never_drops_any_source_or_pointer(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    assert await raw_purge(queue_redis, "1-0", "2-0", source_fields=[b"data", b"changed"]) == "changed_source"
    assert await raw_purge(queue_redis, "1-0", "2-0", pointer_fields=[b"stream", b"matches"]) == "changed_pointer"
    assert await queue_redis.xlen(DLQ) == await queue_redis.xlen(STREAM) == 1


async def test_reconcile_refuses_invalid_legacy_pointer_without_mutation(queue_redis):
    await initialized(queue_redis)
    await queue_redis.xadd(DLQ, {"stream": "unapproved", "message_id": "1-0"})
    before = await queue_redis.hgetall(refs_key(STREAM))
    with pytest.raises(Exception):
        await reconcile(queue_redis, execute=True, legacy_writers_stopped=True)
    assert await queue_redis.get(SCHEMA_KEY) == "1" and await queue_redis.hgetall(refs_key(STREAM)) == before
    assert (RECONCILE.index("redis.call('SET', KEYS[1], 'building')") <
            RECONCILE.index("redis.call('SET', KEYS[1], '1')"))


class BarrierRedis:
    def __init__(self, redis):
        self.redis, self.read, self.resume = redis, asyncio.Event(), asyncio.Event()

    def __getattr__(self, name):
        return getattr(self.redis, name)

    async def xrange(self, *args, **kwargs):
        result = await self.redis.xrange(*args, **kwargs)
        if args[0] == DLQ:
            self.read.set()
            await self.resume.wait()
        return result


async def test_replay_rereads_pointer_after_purge_race(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    barrier = BarrierRedis(queue_redis)
    replay = asyncio.create_task(replay_deadletters(barrier, GROUP, execute=True))
    await asyncio.wait_for(barrier.read.wait(), 5)
    try:
        assert await raw_purge(queue_redis, "1-0", "2-0") == "pointer_purged"
    finally:
        barrier.resume.set()
    rows = await asyncio.wait_for(replay, 5)
    assert rows[0]["status"] == "missing_pointer"
    assert await queue_redis.xlen(STREAM) == 0


async def test_replay_lost_reply_returns_same_id_and_marker(queue_redis):
    await initialized(queue_redis)
    await old_pointer(queue_redis)
    first = await replay_deadletters(queue_redis, GROUP, execute=True)
    second = await replay_deadletters(queue_redis, GROUP, execute=True)
    assert second[0]["status"] == "already_replayed" and second[0]["replay_id"] == first[0]["replay_id"]
    assert await queue_redis.xlen(STREAM) == 2
    assert await queue_redis.get(f"replayed:{GROUP}:2-0") == first[0]["replay_id"]


async def test_ordered_duplicate_binary_source_fields_archive_roundtrip(queue_redis, tmp_path):
    from cryptography.fernet import Fernet

    from shadai.workers.redis_lifecycle import verify_archive

    binary = aioredis.from_url(queue_redis.queue_test_url, decode_responses=False)
    try:
        await initialized(queue_redis)
        await binary.execute_command("XADD", STREAM, "1-0", b"duplicate", b"\xff", b"duplicate", b"two")
        await queue_redis.xgroup_setid(STREAM, GROUP, "1-0")
        path, key = tmp_path / "private" / "retained.fernet", Fernet.generate_key()
        result = await purge(binary, GROUP, stream=STREAM, execute=True, archive=path, encryption_key=key)
        document, digest = verify_archive(path, key)
        assert result["results"][0]["status"] == "source_purged"
        assert result["archive_sha256"] == digest
        from shadai.workers.redis_lifecycle import unpack_fields
        assert unpack_fields(document["records"][0]["source_fields"]) == [b"duplicate", b"\xff", b"duplicate", b"two"]
    finally:
        await binary.aclose()
