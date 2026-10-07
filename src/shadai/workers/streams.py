"""Reclaim work with bounded retry state; infrastructure failures remain pending."""

import random
import time
from collections import Counter
from contextlib import nullcontext

import structlog
from redis.exceptions import ResponseError

from shadai.utils.operations import WorkerOperations, operation_key
from shadai.utils.queue_admission import SCHEMA_KEY, queue_settings
from shadai.utils.queueing import PermanentMessageError
from shadai.workers.redis_lifecycle import ACK_SUCCESS, DEADLETTER, RETENTION_LUA, refs_key

logger = structlog.get_logger()

RECORD_RETRY = RETENTION_LUA + """
local permanent, next_at = tonumber(ARGV[2]), tonumber(ARGV[1])
local field = permanent == 1 and 'rejected_attempts' or 'retryable_failures'
if not type_ok(KEYS[1], 'hash') or (permanent ~= 0 and permanent ~= 1) or
   not next_at or next_at < 0 or next_at == math.huge or not op_ok(KEYS[2], field) then
    return redis.error_reply('Invalid retry state')
end
for _,name in ipairs({'attempts','poison_attempts'}) do
    local value = redis.call('HGET', KEYS[1], name)
    if value and not uint(value, 65535) then return redis.error_reply('Invalid retry counter') end
end
if KEYS[2] then
    record_operation(KEYS[2], field)
end
local attempts = math.min(65535, tonumber(redis.call('HGET', KEYS[1], 'attempts') or '0') + 1)
local poison = math.min(65535, tonumber(redis.call('HGET', KEYS[1], 'poison_attempts') or '0') + tonumber(ARGV[2]))
redis.call('HSET', KEYS[1], 'attempts', attempts, 'poison_attempts', poison, 'next_at', ARGV[1])
redis.call('EXPIRE', KEYS[1], 604800)
return {attempts, poison}
"""


def permanent_error(exc: Exception) -> bool:
    # Only explicit input validation is permanent; bugs/driver ValueErrors or
    # TypeErrors retain data just like datastore failures.
    return isinstance(exc, PermanentMessageError)


class StreamConsumer:
    def __init__(self, redis, group, consumer, streams, *, max_attempts=5, reclaim_ms=60000, clock=time.time,
                 operational=False, settings=None, probe=None):
        self.redis, self.group, self.consumer, self.streams = redis, group, consumer, streams
        self.max_attempts, self.reclaim_ms = max_attempts, reclaim_ms
        self.cursors = {stream: "0-0" for stream in streams}
        self.registered_streams = set()
        self.clock = clock
        self.counters = Counter()
        self.settings, self.probe = queue_settings(settings), probe
        self.operations = WorkerOperations(redis, group, streams) if operational else None

    async def initialize(self):
        for stream in self.streams:
            try:
                await self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    async def read(self):
        async with self.probe.phase('poll') if self.probe else nullcontext():
            rows = await self._read()
        if self.probe:
            self.probe.poll()
        return rows

    async def _read(self):
        recovered = []
        for stream in self.streams:
            if stream not in self.registered_streams:
                registered = await self.redis.xgroup_createconsumer(stream, self.group, self.consumer)
                if type(registered) is not int or registered not in (0, 1):
                    raise ValueError("Invalid consumer registration result")
                self.registered_streams.add(stream)
            response = await self.redis.xautoclaim(
                stream,
                self.group,
                self.consumer,
                self.reclaim_ms,
                start_id=self.cursors[stream],
                count=50,
            )
            self.cursors[stream] = response[0]
            if response[1]:
                recovered.append((stream, response[1]))
                self.counters["reclaimed"] += len(response[1])
        # Repeated failing backlog must not starve fresh, healthy observations.
        fresh = await self.redis.xreadgroup(
            self.group, self.consumer, {stream: ">" for stream in self.streams}, count=50,
            # Leave a margin below redis-py's five-second socket deadline.
            block=1 if recovered else 1000,
        )
        if self.operations:
            await self.operations.pulse('last_poll_at')
        return recovered + (fresh or [])

    async def process(self, stream, message_id, data, handler):
        async with self.probe.phase('handler') if self.probe else nullcontext():
            result = await self._process(stream, message_id, data, handler)
        if self.probe and not result:
            self.probe.set_phase('blocked')
        return result

    async def _process(self, stream, message_id, data, handler):
        retry_key = f"retries:{self.group}:{stream}:{message_id}"
        metrics_key = (operation_key(self.group, stream),) if self.operations else ()
        state = await self.redis.hgetall(retry_key)
        next_at = state.get("next_at", 0)
        if isinstance(next_at, (str, bytes, int, float)) and float(next_at) > self.clock():
            self.counters["backoff_deferred"] += 1
            return False
        try:
            await handler(data)
        except Exception as exc:
            prior = state.get("attempts", 0)
            prior = int(prior) if isinstance(prior, (str, bytes, int, float)) else 0
            delay = min(300, 2 ** min(prior + 1, 8)) * random.uniform(0.75, 1.0)
            permanent = permanent_error(exc)
            attempts, poison_attempts = await self.redis.eval(
                RECORD_RETRY, 1 + len(metrics_key), retry_key, *metrics_key,
                str(self.clock() + delay), str(int(permanent)),
            )
            self.counters["processing_failures"] += 1
            logger.warning(
                "message_processing_failed",
                stream=stream,
                message_id=message_id,
                error_type=type(exc).__name__,
                attempts=attempts,
                permanent=permanent,
            )
            if not permanent or poison_attempts < self.max_attempts:
                self.counters["retryable_failures"] += int(not permanent)
                return False
            # Keep the original in its source stream for controlled operator replay.
            # Do not copy unvalidated payloads or exception text into logs/dead letters.
            acknowledged = await self.redis.eval(
                DEADLETTER, 5 + len(metrics_key), stream, f"deadletter:{self.group}", retry_key,
                refs_key(stream), SCHEMA_KEY, *metrics_key,
                self.group, message_id, type(exc).__name__, str(attempts), str(self.settings.dlq_max_entries),
            )
            if acknowledged == -1:
                self.counters["deadletter_capacity_deferred"] += 1
                return False
            self.counters["deadlettered" if acknowledged else "duplicate_ack"] += 1
        else:
            acknowledged = await self.redis.eval(ACK_SUCCESS, 3 + len(metrics_key), stream,
                                                 refs_key(stream), SCHEMA_KEY, *metrics_key, self.group, message_id)
            await self.redis.delete(retry_key)
            self.counters["succeeded" if acknowledged else "duplicate_ack"] += 1
        return True

    def stats(self) -> dict[str, int]:
        return dict(self.counters)
