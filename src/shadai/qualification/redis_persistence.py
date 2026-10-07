"""Bounded private Redis INFO validation and quiescent AOF checkpoint."""

import asyncio
import math
import re
import time

from shadai.qualification.schemas import QualificationError

MAX_SECONDS = 120
MAX_SAMPLES = 480
SAMPLE_INTERVAL = 0.25
MAX_INTEGER = (1 << 63) - 1
FLAGS = ("loading", "aof_enabled", "rdb_bgsave_in_progress", "aof_rewrite_in_progress", "aof_rewrite_scheduled")
COUNTERS = ("aof_rewrites", "aof_buffer_length", "aof_pending_bio_fsync")
STATUSES = ("aof_last_bgrewrite_status", "aof_last_write_status")
# Redis 7.4.11 src/aof.c, bgrewriteaofCommand. redis-py also decodes these to True.
REWRITE_ACKS = ("Background append only file rewriting started", "Background append only file rewriting scheduled")


def parse_info(value):
    """Validate every field before any state comparison or key lookup."""
    __tracebackhide__ = True
    if type(value) is not dict:
        raise QualificationError("Redis persistence sample refused")
    characters, occurrences = 0, 0
    active = set()

    def visit(item, depth, *, key=False):
        __tracebackhide__ = True
        nonlocal characters, occurrences
        occurrences += 1
        if occurrences > 4096 or depth > 8:
            raise QualificationError("Redis persistence sample refused")
        kind = type(item)
        if key and kind is not str:
            raise QualificationError("Redis persistence sample refused")
        if kind is str:
            if len(item) > (128 if key else 4096):
                raise QualificationError("Redis persistence sample refused")
            characters += len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise QualificationError("Redis persistence sample refused")
        elif kind is float:
            if not math.isfinite(item):
                raise QualificationError("Redis persistence sample refused")
        elif kind is dict or kind is list:
            if len(item) > 256 or id(item) in active:
                raise QualificationError("Redis persistence sample refused")
            active.add(id(item))
            try:
                if kind is dict:
                    for name, child in item.items():
                        visit(name, depth + 1, key=True)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise QualificationError("Redis persistence sample refused")
        if characters > 65536:
            raise QualificationError("Redis persistence sample refused")

    visit(value, 0)
    for key in FLAGS:
        if type(value.get(key)) is not int or value[key] not in (0, 1):
            raise QualificationError("Redis persistence sample refused")
    for key in COUNTERS:
        if type(value.get(key)) is not int or not 0 <= value[key] <= MAX_INTEGER:
            raise QualificationError("Redis persistence sample refused")
    for key in STATUSES:
        if type(value.get(key)) is not str or value[key] not in ("ok", "err"):
            raise QualificationError("Redis persistence sample refused")
    if type(value.get("run_id")) is not str or re.fullmatch(r"[0-9a-f]{40}", value["run_id"]) is None:
        raise QualificationError("Redis persistence sample refused")
    return value


async def redis_persistence(redis, *, clock=time.monotonic, sleep=asyncio.sleep):
    """Rewrite exactly once and prove its completed generation in the same process."""
    deadline, samples, run_id = clock() + MAX_SECONDS, 0, None

    def remaining():
        if clock() >= deadline:
            raise QualificationError("Redis persistence deadline exhausted")

    async def sample():
        nonlocal samples, run_id
        remaining()
        if samples >= MAX_SAMPLES:
            raise QualificationError("Redis persistence sample budget exhausted")
        samples += 1
        # One INFO command gives an atomic view of both identity and persistence.
        info = parse_info(await redis.info("server", "persistence"))
        remaining()
        if run_id is None:
            run_id = info["run_id"]
        if (info["run_id"] != run_id or info["loading"] != 0 or info["aof_enabled"] != 1
                or info["aof_last_write_status"] != "ok"):
            raise QualificationError("Redis persistence state refused")
        return info

    def idle(info):
        return not any(info[key] for key in (
            "rdb_bgsave_in_progress", "aof_rewrite_in_progress", "aof_rewrite_scheduled"
        ))

    async def pause():
        remaining()
        await sleep(min(SAMPLE_INTERVAL, deadline - clock()))
        remaining()

    # The outer timeout also bounds a hung transport or acknowledgement.
    async with asyncio.timeout(MAX_SECONDS):
        while True:
            before = await sample()
            if idle(before):
                break
            await pause()
        generation = before["aof_rewrites"]
        if generation == MAX_INTEGER:
            raise QualificationError("Redis persistence generation refused")
        remaining()
        ack = await redis.bgrewriteaof()
        remaining()
        if ack is not True and (type(ack) is not str or ack not in REWRITE_ACKS):
            raise QualificationError("Redis persistence acknowledgement refused")
        while True:
            after = await sample()
            current = after["aof_rewrites"]
            if current < generation or current > generation + 1:
                raise QualificationError("Redis persistence generation refused")
            if current == generation + 1 and idle(after):
                if after["aof_last_bgrewrite_status"] != "ok":
                    raise QualificationError("Redis persistence rewrite failed")
                if after["aof_buffer_length"] == 0 and after["aof_pending_bio_fsync"] == 0:
                    return {"redis_persistence_complete": True}
            await pause()
