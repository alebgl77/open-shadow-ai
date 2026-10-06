"""Admission protocol adapter for existing payload/privacy unit test doubles.

Real Redis scripts and race/capacity semantics are tested independently. This
adapter retains existing capture assertions without adding a runtime fallback.
"""

from unittest.mock import AsyncMock

from shadai.utils.queue_admission import QUEUE_ADMIT


def admission_fake(redis, pipe=None):
    async def evaluate(script, numkeys, *values):
        assert script == QUEUE_ADMIT
        keys, args = values[:numkeys], values[numkeys:]
        count, pos = int(args[0]), 3
        for _ in range(count):
            destination, pairs = int(args[pos]), int(args[pos+1])
            pos += 2
            fields = dict(zip(args[pos:pos+2*pairs:2], args[pos+1:pos+2*pairs:2], strict=True))
            pos += 2*pairs
            if pipe is not None:
                pipe.xadd(keys[destination-1], fields)
            else:
                await redis.xadd(keys[destination-1], fields)
        if pipe is not None:
            await pipe.execute()
        return ["ok", *(f"{i+1}-0" for i in range(count))]
    redis.eval = AsyncMock(side_effect=evaluate)
    return redis
