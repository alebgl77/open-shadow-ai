"""Explicit disposable Redis DB, never an implicit flush of configured stores."""

import os
from urllib.parse import urlsplit

import pytest
import redis.asyncio as aioredis

from shadai.utils.queue_admission import GROUP_STREAMS, SCHEMA_KEY, STREAMS
from shadai.workers.redis_lifecycle import refs_key


@pytest.fixture(name="queue_redis")
async def queue_redis():
    endpoint = os.environ.get("SHADAI_REDIS_QUEUE_TEST_URL", "")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname or parsed.path != "/14":
        pytest.fail("Explicit disposable Redis queue fixture URL selecting DB 14 is required")
    redis = aioredis.from_url(endpoint, decode_responses=True)
    owned = False
    try:
        if await redis.dbsize() != 0:
            pytest.fail("Queue fixture DB 14 must initially be empty; refusing to delete existing state")
        owned = True
        redis.queue_test_url = endpoint
        yield redis
    finally:
        # Cleanup only the fixed stream graph and its derived keys. No FLUSHDB,
        # no global maxmemory change, no keys outside this disposable DB.
        if owned:
            fixed = [*STREAMS, SCHEMA_KEY, *(refs_key(s) for s in STREAMS),
                     *("deadletter:" + group for group in GROUP_STREAMS)]
            derived = []
            for group in GROUP_STREAMS:
                for prefix in ("retries", "replayed", "operations"):
                    derived.extend([key async for key in redis.scan_iter(match=f"{prefix}:{group}:*")])
            await redis.delete(*fixed, *derived)
        await redis.aclose()
