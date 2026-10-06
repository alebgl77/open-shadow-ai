from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.utils.queue_admission import QUEUE_ADMIT
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.ingest import EventProcessor
from shadai.workers.streams import RECORD_RETRY, StreamConsumer


class Transaction:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self

    async def __aexit__(self, error, *args):
        if error is None:
            self.session.receipts.update(self.session.pending)
        self.session.pending.clear()


class Session:
    def __init__(self):
        self.receipts, self.pending = set(), set()
        self.execute = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def begin(self):
        return Transaction(self)

    async def get(self, model, key):
        return key in self.receipts

    def add(self, receipt):
        self.pending.add(receipt.event_id)


async def test_reclaims_pending_before_reading_new():
    redis = AsyncMock()
    redis.xautoclaim.return_value = ["12-0", [("1-0", {"data": "x"})], []]
    redis.xreadgroup.return_value = []
    consumer = StreamConsumer(redis, "group", "worker", ["events:dns"])
    assert await consumer.read() == [("events:dns", [("1-0", {"data": "x"})])]
    assert consumer.cursors["events:dns"] == "12-0"
    redis.xreadgroup.assert_awaited_once()  # Pending failures must not starve fresh work.


async def test_no_ack_on_failure_then_deadletter_before_ack():
    calls = []
    redis = AsyncMock()
    redis.hgetall.return_value = {}
    attempts = iter([[1, 1], [2, 2]])
    def evaluate(script, *args):
        if script == RECORD_RETRY:
            return next(attempts)
        calls.append("atomic_deadletter_ack")
        return 1
    redis.eval.side_effect = evaluate
    consumer = StreamConsumer(redis, "ingest_group", "w", ["events:dns"], max_attempts=2)
    handler = AsyncMock(side_effect=PermanentMessageError("secret-should-not-be-logged"))
    assert not await consumer.process("events:dns", "1-0", {}, handler)
    assert calls == []
    assert await consumer.process("events:dns", "1-0", {}, handler)
    assert calls == ["atomic_deadletter_ack"]
    assert "secret" not in str(redis.eval.call_args)


async def test_deadletter_failure_keeps_pending():
    redis = AsyncMock()
    redis.hgetall.return_value = {}
    redis.eval.side_effect = [[5, 5], RuntimeError()]
    with pytest.raises(RuntimeError):
        await StreamConsumer(redis, "ingest_group", "w", ["events:dns"]).process("events:dns", "1-0", {},
                                                             AsyncMock(side_effect=PermanentMessageError()))
    redis.xack.assert_not_called()


async def test_persist_enqueue_commit_ack_order_and_idempotency():
    calls = []
    redis = AsyncMock()
    redis.hgetall.return_value = {}
    def evaluate(script, *args):
        if script == QUEUE_ADMIT:
            calls.append("enqueue")
            return ["ok", "3-0"]
        calls.append("ack")
        return 1
    redis.eval.side_effect = evaluate
    session = Session()
    ch = SimpleNamespace(execute=lambda *args: calls.append("persist"))
    item = CatalogItemRead(
        catalog_item_id="openai", canonical_name="OpenAI", category="ai_platform", domains=["openai.com"]
    )
    processor = EventProcessor(redis, ch, lambda: session, CatalogMatcher(build_catalog_index([item])))
    event = CanonicalEvent(tenant_id="test-org", domain="openai.com")
    data = {"data": event.model_dump_json()}
    consumer = StreamConsumer(redis, "ingest_group", "w", ["events:dns"])
    await consumer.process("events:dns", "1-0", data, processor)
    await consumer.process("events:dns", "2-0", data, processor)
    assert calls == ["persist", "enqueue", "ack", "ack"]
    assert event.event_id in session.receipts


async def test_enqueue_failure_does_not_commit_receipt_or_ack():
    redis = AsyncMock()
    redis.hgetall.return_value = {}
    redis.incr.return_value = 1
    redis.eval.return_value = [1, 0]
    redis.eval.side_effect = lambda script, *args: ["denied", "full"] if script == QUEUE_ADMIT else [1, 0]
    session = Session()
    item = CatalogItemRead(catalog_item_id="x", canonical_name="x", category="ai", domains=["ai.test"])
    processor = EventProcessor(
        redis, SimpleNamespace(execute=lambda *args: None), lambda: session, CatalogMatcher(build_catalog_index([item]))
    )
    event = CanonicalEvent(tenant_id="test-org", domain="ai.test")
    consumer = StreamConsumer(redis, "ingest_group", "w", ["events:dns"])
    await consumer.process("events:dns", "1-0", {"data": event.model_dump_json()}, processor)
    assert not session.receipts
    redis.xack.assert_not_called()


async def test_clickhouse_failure_never_enqueues_or_acks():
    redis = AsyncMock()
    redis.hgetall.return_value = {}
    redis.incr.return_value = 1
    redis.eval.return_value = [1, 0]
    session = Session()

    def fail(*args):
        raise RuntimeError()

    processor = EventProcessor(
        redis, SimpleNamespace(execute=fail), lambda: session, CatalogMatcher(build_catalog_index([]))
    )
    event = CanonicalEvent(tenant_id="test-org")
    consumer = StreamConsumer(redis, "ingest_group", "w", ["events:dns"])
    await consumer.process("events:dns", "1-0", {"data": event.model_dump_json()}, processor)
    assert not session.receipts
    redis.xadd.assert_not_called()
    redis.xack.assert_not_called()


async def test_empty_catalog_never_consumes_queued_work(monkeypatch):
    from shadai.engine.catalog_loader import CatalogIndex
    from shadai.workers.ingest import run_ingest_worker

    redis = AsyncMock()
    engine = SimpleNamespace(dispose=AsyncMock())
    ch = SimpleNamespace(disconnect=lambda: None)
    consumer = AsyncMock()
    session = Session()
    monkeypatch.setattr("shadai.workers.ingest.aioredis.from_url", lambda *a, **k: redis)
    monkeypatch.setattr("shadai.workers.ingest.create_async_engine", lambda *a, **k: engine)
    monkeypatch.setattr("shadai.workers.ingest.async_sessionmaker", lambda *a, **k: lambda: session)
    monkeypatch.setattr("shadai.workers.ingest.init_clickhouse", lambda *a: ch)
    monkeypatch.setattr("shadai.workers.ingest.StreamConsumer", lambda *a, **k: consumer)
    monkeypatch.setattr("shadai.workers.ingest.load_database_catalog", AsyncMock(return_value=CatalogIndex()))
    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def no_probe(*args):
        yield SimpleNamespace(mark_initialized=lambda: None)
    monkeypatch.setattr("shadai.workers.ingest.ProcessProbe", no_probe)
    with pytest.raises(RuntimeError, match="No active catalog"):
        await run_ingest_worker("test")
    consumer.read.assert_not_called()
    redis.xack.assert_not_called()
    engine.dispose.assert_awaited_once()
    redis.aclose.assert_awaited_once()
