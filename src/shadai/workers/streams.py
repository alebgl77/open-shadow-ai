"""Reclaim work with bounded retry state; infrastructure failures remain pending."""

import random
import time
from collections import Counter

import structlog
from redis.exceptions import ResponseError

from shadai.utils.operations import COUNT_OPERATION, WorkerOperations, operation_key
from shadai.utils.queueing import PermanentMessageError

logger = structlog.get_logger()

# Atomic topology check prevents deleting work owned by an additional consumer group.
# Internal streams have exactly one owner group; dead letters retain the original.
ACK_SUCCESS = COUNT_OPERATION + """
local groups = redis.call('XINFO', 'GROUPS', KEYS[1])
if KEYS[2] then
    local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
    if #pending > 0 then record_operation(KEYS[2], 'acknowledged') end
end
local ack = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
if ack > 0 and #groups == 1 then
    redis.call('XDEL', KEYS[1], ARGV[2])
end
return ack
"""

# A wrong-type DLQ must fail before acknowledgement. Retain the original source.
DEADLETTER = COUNT_OPERATION + """
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending == 0 then return 0 end
if KEYS[4] then
    -- Fail before creating a pointer if publication state has the wrong type.
    check_operation(KEYS[4], 'deadlettered')
end
redis.call('XADD', KEYS[2], 'MAXLEN', '~', 10000, '*',
           'stream', KEYS[1], 'message_id', ARGV[2], 'error_type', ARGV[3], 'attempts', ARGV[4])
if KEYS[4] then record_operation(KEYS[4], 'deadlettered') end
redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
redis.call('DEL', KEYS[3])
return 1
"""

RECORD_RETRY = COUNT_OPERATION + """
if KEYS[2] then
    record_operation(KEYS[2], tonumber(ARGV[2]) == 1 and 'rejected_attempts' or 'retryable_failures')
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
                 operational=False):
        self.redis, self.group, self.consumer, self.streams = redis, group, consumer, streams
        self.max_attempts, self.reclaim_ms = max_attempts, reclaim_ms
        self.cursors = {stream: "0-0" for stream in streams}
        self.clock = clock
        self.counters = Counter()
        self.operations = WorkerOperations(redis, group, streams) if operational else None

    async def initialize(self):
        for stream in self.streams:
            try:
                await self.redis.xgroup_create(stream, self.group, id="0", mkstream=True)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    async def read(self):
        recovered = []
        for stream in self.streams:
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
            block=1 if recovered else 5000,
        )
        if self.operations:
            await self.operations.pulse('last_poll_at')
        return recovered + (fresh or [])

    async def process(self, stream, message_id, data, handler):
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
                DEADLETTER, 3 + len(metrics_key), stream, f"deadletter:{self.group}", retry_key, *metrics_key,
                self.group, message_id, type(exc).__name__, str(attempts),
            )
            self.counters["deadlettered" if acknowledged else "duplicate_ack"] += 1
        else:
            acknowledged = await self.redis.eval(ACK_SUCCESS, 1 + len(metrics_key), stream, *metrics_key,
                                                 self.group, message_id)
            await self.redis.delete(retry_key)
            self.counters["succeeded" if acknowledged else "duplicate_ack"] += 1
        return True

    def stats(self) -> dict[str, int]:
        return dict(self.counters)
