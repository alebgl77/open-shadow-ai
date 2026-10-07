"""Real Redis/process publication, atomic ACK/retry/DLQ/replay. Opt-in services."""

import asyncio
import json
import os
import subprocess
import sys
from unittest.mock import AsyncMock

import pytest
from queue_integration_fixtures import queue_redis as _queue_redis  # noqa: F401

from shadai.config import load_config
from shadai.utils import operations
from shadai.utils.queue_admission import SCHEMA_KEY
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.redis_lifecycle import reconcile, refs_key
from shadai.workers.replay import replay_deadletters
from shadai.workers.streams import ACK_SUCCESS, StreamConsumer

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(os.environ.get('SHADAI_INTEGRATION') != '1', reason='Disposable Redis not requested')]

CHILD = """
import asyncio, json, os, sys, time
import redis.asyncio as aioredis
import structlog

structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
from shadai.utils import operations
from shadai.workers.streams import StreamConsumer

async def run():
    group, stream, message_id = sys.argv[1:]
    operations.STAGES = {'synthetic': (group, (stream,))}
    redis = aioredis.from_url(os.environ['SHADAI_OPERATIONS_REDIS_URL'], decode_responses=True)
    clock = [time.time()]
    consumer = StreamConsumer(redis, group, 'synthetic-process', [stream], operational=True, clock=lambda: clock[0])
    try:
        await consumer.operations.pulse()
        await consumer.operations.pulse('last_poll_at')
        async def offline(data): raise OSError('synthetic unavailable')
        async def accepted(data): pass
        assert not await consumer.process(stream, message_id, {}, offline)
        clock[0] += 301
        await consumer.process(stream, message_id, {}, accepted)
        await consumer.process(stream, message_id, {}, accepted) # lost ACK response/retry
        print(json.dumps(consumer.stats()))
    finally:
        await redis.aclose()
asyncio.run(run())
"""


async def test_real_cross_process_counts_poison_replay_and_no_partial_ack_on_bad_publication(monkeypatch, queue_redis):
    config = load_config()
    redis = queue_redis
    group, stream = 'ingest_group', 'events:dns'
    dlq = 'deadletter:' + group
    monkeypatch.setattr(operations, 'STAGES', {'synthetic': (group, (stream,))})
    key = operations.operation_key(group, stream)
    retries, markers = [], []
    consumer = StreamConsumer(redis, group, 'reader', [stream], operational=True, max_attempts=2)
    try:
        await consumer.initialize()
        await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=config.redis_queue)
        fields = {'data': '{"event_id":"synthetic-immutable"}', 'accepted_at': '2026-10-06T00:00:00+00:00'}
        identifier = await redis.xadd(stream, fields)
        retries.append(f'retries:{group}:{stream}:{identifier}')
        await redis.xreadgroup(group, 'crashed', {stream: '>'}, count=1)
        environment = {**os.environ, 'SHADAI_OPERATIONS_REDIS_URL': redis.queue_test_url}
        process = await asyncio.to_thread(subprocess.run, [sys.executable, '-c', CHILD, group, stream, identifier],
                                          env=environment, capture_output=True, text=True, timeout=30, check=False)
        assert process.returncode == 0, 'Isolated worker subprocess failed'
        assert json.loads(process.stdout)['duplicate_ack'] == 1
        snapshot = await operations.pipeline_snapshot(redis)
        row = snapshot['stages'][0]['streams'][0]
        assert row['counters']['acknowledged'] == 1 and row['counters']['retryable_failures'] == 1
        assert row['pending'] == 0 and row['undelivered'] == 0 and row['retained_entries'] == 0
        assert row['status'] == 'idle' and row['worker_state_fresh']

        poison_id = await redis.xadd(stream, fields)
        retries.append(f'retries:{group}:{stream}:{poison_id}')
        await redis.xreadgroup(group, 'reader', {stream: '>'}, count=1)
        clock = [consumer.clock()]
        consumer.clock = lambda: clock[0]
        handler = AsyncMock(side_effect=PermanentMessageError('synthetic invalid'))
        assert not await consumer.process(stream, poison_id, fields, handler)
        clock[0] += 301
        assert await consumer.process(stream, poison_id, fields, handler)
        # Duplicate processing cannot inflate actual DLQ transitions.
        clock[0] += 301
        await consumer.process(stream, poison_id, fields, handler)
        clock[0] += 301
        await consumer.process(stream, poison_id, fields, handler)
        rows = await redis.xrange(dlq)
        assert len(rows) == 1
        marker = f'replayed:{group}:{rows[0][0]}'
        markers.append(marker)
        from shadai.workers import replay
        monkeypatch.setitem(replay.GROUP_STREAMS, group, (stream,))
        first = await replay_deadletters(redis, group, execute=True, operational=True)
        second = await replay_deadletters(redis, group, execute=True, operational=True)
        assert first[0]['status'] == 'replayed' and second[0]['status'] == 'already_replayed'
        row = (await operations.pipeline_snapshot(redis))['stages'][0]['streams'][0]
        assert row['counters']['deadlettered'] == 1 and row['counters']['replayed'] == 1
        assert row['counters']['rejected_attempts'] == 4
        assert (await redis.xrange(stream, first[0]['replay_id'], first[0]['replay_id']))[0][1] == fields

        await redis.xreadgroup(group, 'reader', {stream: '>'}, count=1)
        await redis.hset(key, 'acknowledged', 'malformed')
        with pytest.raises(Exception):
            await redis.eval(ACK_SUCCESS, 4, stream, refs_key(stream), SCHEMA_KEY, key, group, first[0]['replay_id'])
        assert (await redis.xpending(stream, group))['pending'] == 1
        assert await redis.xrange(stream, first[0]['replay_id'], first[0]['replay_id'])
    finally:
        await redis.delete(stream, dlq, key, *retries, *markers)
