"""Redis Streams delivery: reclaim idle pending work, bounded failures and dead-letter pointers."""

import structlog
from redis.exceptions import ResponseError

logger = structlog.get_logger()

# Atomic topology check prevents deleting work owned by an additional consumer group.
# Internal streams have exactly one owner group; dead letters retain the original.
ACK_SUCCESS = """
local ack = redis.call('XACK', KEYS[1], ARGV[1], ARGV[2])
local groups = redis.call('XINFO', 'GROUPS', KEYS[1])
if ack > 0 and #groups == 1 then
    redis.call('XDEL', KEYS[1], ARGV[2])
end
return ack
"""


class StreamConsumer:
    def __init__(self, redis, group, consumer, streams, *, max_attempts=5, reclaim_ms=60000):
        self.redis, self.group, self.consumer, self.streams = redis, group, consumer, streams
        self.max_attempts, self.reclaim_ms = max_attempts, reclaim_ms
        self.cursors = {stream: "0-0" for stream in streams}

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
        if recovered:
            return recovered
        return await self.redis.xreadgroup(
            self.group, self.consumer, {stream: ">" for stream in self.streams}, count=50, block=5000
        )

    async def process(self, stream, message_id, data, handler):
        retry_key = f"retries:{self.group}:{stream}:{message_id}"
        succeeded = False
        try:
            await handler(data)
            succeeded = True
        except Exception as exc:
            attempts = await self.redis.incr(retry_key)
            logger.warning(
                "message_processing_failed",
                stream=stream,
                message_id=message_id,
                error_type=type(exc).__name__,
                attempts=attempts,
            )
            if attempts < self.max_attempts:
                return False
            # Keep the original in its source stream for controlled operator replay.
            # Do not copy unvalidated payloads or exception text into logs/dead letters.
            await self.redis.xadd(
                f"deadletter:{self.group}",
                {
                    "stream": stream,
                    "message_id": message_id,
                    "error_type": type(exc).__name__,
                    "attempts": str(attempts),
                },
            )
        if succeeded:
            await self.redis.eval(ACK_SUCCESS, 1, stream, self.group, message_id)
        else:
            await self.redis.xack(stream, self.group, message_id)
        await self.redis.delete(retry_key)
        return True
