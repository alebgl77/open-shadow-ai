"""Real Redis Lua/reclaim/replay acceptance; opt-in disposable services only."""

import os
from unittest.mock import AsyncMock

import pytest
from queue_integration_fixtures import queue_redis as _queue_redis  # noqa: F401

from shadai.config import load_config
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.redis_lifecycle import reconcile
from shadai.workers.replay import replay_deadletters
from shadai.workers.streams import StreamConsumer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("SHADAI_INTEGRATION") != "1", reason="Disposable Redis not requested"),
]


async def test_real_redis_extended_outage_poison_atomicity_and_replay(queue_redis):
    config = load_config()
    redis = queue_redis
    stream, group = "events:dns", "ingest_group"
    dlq, marker = "deadletter:" + group, ""
    now = [1_800_000_000.0]
    consumer = StreamConsumer(redis, group, "recovered", [stream], reclaim_ms=0, clock=lambda: now[0])
    retry_keys = []
    try:
        await consumer.initialize()
        await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=config.redis_queue)
        fields = {"data": '{"event_id":"immutable-synthetic"}', "accepted_at": "2026-10-06T00:00:00+00:00"}
        message_id = await redis.xadd(stream, fields)
        retry_key = f"retries:{group}:{stream}:{message_id}"
        retry_keys.append(retry_key)
        await redis.xreadgroup(group, "crashed", {stream: ">"}, count=1)
        failed = AsyncMock(side_effect=OSError("synthetic datastore offline"))
        for _ in range(8):
            rows = await consumer.read()
            assert rows[0][1][0] == (message_id, fields)
            assert not await consumer.process(stream, message_id, fields, failed)
            now[0] += 301
        assert await redis.xlen(dlq) == 0
        assert (await redis.xpending(stream, group))["pending"] == 1
        assert 0 < await redis.ttl(retry_key) <= 604800
        failed.side_effect = None
        assert await consumer.process(stream, message_id, fields, failed)
        assert await redis.xlen(stream) == 0

        poison_id = await redis.xadd(stream, fields)
        retry_keys.append(f"retries:{group}:{stream}:{poison_id}")
        await redis.xreadgroup(group, "worker", {stream: ">"}, count=1)
        poison = AsyncMock(side_effect=PermanentMessageError("synthetic invalid envelope"))
        for attempt in range(5):
            done = await consumer.process(stream, poison_id, fields, poison)
            assert done is (attempt == 4)
            now[0] += 301
        assert (await redis.xpending(stream, group))["pending"] == 0
        assert (await redis.xrange(stream, poison_id, poison_id))[0][1] == fields
        pointers = await redis.xrange(dlq)
        assert len(pointers) == 1 and pointers[0][1]["message_id"] == poison_id

        marker = f"replayed:{group}:{pointers[0][0]}"
        first = (await replay_deadletters(redis, group, execute=True, settings=config.redis_queue))[0]
        second = (await replay_deadletters(redis, group, execute=True, settings=config.redis_queue))[0]
        assert first["status"] == "replayed" and second["status"] == "already_replayed"
        assert first["replay_id"] == second["replay_id"]
        assert (await redis.xrange(stream, first["replay_id"], first["replay_id"]))[0][1] == fields
        assert await redis.xlen(stream) == 2
        await redis.xdel(stream, poison_id)
        await redis.delete(marker)
        missing = await replay_deadletters(redis, group, execute=True, settings=config.redis_queue)
        assert missing[0]["status"] == "missing_source"
    finally:
        await redis.delete(stream, dlq, *([marker] if marker else []), *retry_keys)
