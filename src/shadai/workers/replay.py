"""Bounded operator DLQ inspection/replay, default dry-run; original metadata stays private."""

from __future__ import annotations

import argparse
import asyncio
import json
import re

import redis.asyncio as aioredis

from shadai.api.ingestion import SOURCE_TYPES
from shadai.config import load_config, validate_security
from shadai.utils.operations import COUNT_OPERATION, operation_key

GROUP_STREAMS = {"ingest_group": tuple("events:" + source for source in SOURCE_TYPES),
                 "correlate_group": ("matches",)}
STREAM_ID = re.compile(r"^[0-9]{1,20}-[0-9]{1,20}$")

# Dedup pointer replays atomically. Only server-side stream fields are copied.
REPLAY = COUNT_OPERATION + """
if redis.call('EXISTS', KEYS[3]) == 1 then return {'already_replayed', redis.call('GET', KEYS[3])} end
local original = redis.call('XRANGE', KEYS[1], ARGV[1], ARGV[1], 'COUNT', 1)
if #original == 0 then return {'missing_source', ''} end
local fields = original[1][2]
if KEYS[4] then check_operation(KEYS[4], 'replayed') end
local id = redis.call('XADD', KEYS[1], '*', unpack(fields))
redis.call('SET', KEYS[3], id, 'EX', 31536000)
if KEYS[4] then record_operation(KEYS[4], 'replayed') end
return {'replayed', id}
"""


async def replay_deadletters(redis, group: str, *, start: str = "0-0", end: str = "+", limit: int = 100,
                             execute: bool = False, operational: bool = False) -> list[dict]:
    if group not in GROUP_STREAMS or not 1 <= limit <= 500:
        raise ValueError("Invalid replay group or limit")
    if not STREAM_ID.fullmatch(start) or (end != "+" and not STREAM_ID.fullmatch(end)):
        raise ValueError("Invalid dead-letter ID selector")
    dlq = "deadletter:" + group
    pointers = await redis.xrange(dlq, min=start, max=end, count=limit)
    results = []
    for pointer_id, pointer in pointers:
        stream, message_id = pointer.get("stream"), pointer.get("message_id")
        row = {"pointer_id": pointer_id}
        if stream not in GROUP_STREAMS[group] or not isinstance(message_id, str) or not STREAM_ID.fullmatch(message_id):
            row["status"] = "invalid_pointer"
        elif not execute:
            original = await redis.xrange(stream, min=message_id, max=message_id, count=1)
            row["status"] = "ready" if original else "missing_source"
        else:
            marker = f"replayed:{group}:{pointer_id}"
            keys = (operation_key(group, stream),) if operational else ()
            status, replay_id = await redis.eval(REPLAY, 3 + len(keys), stream, dlq, marker, *keys, message_id)
            row.update({"status": status, "replay_id": replay_id})
        if row["status"] != "invalid_pointer":
            row.update({"stream": stream, "message_id": message_id})
        results.append(row)
    return results


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--group", choices=tuple(GROUP_STREAMS), required=True)
    parser.add_argument("--start", default="0-0", help="First DLQ ID, inclusive")
    parser.add_argument("--end", default="+", help="Last DLQ ID, inclusive")
    parser.add_argument("--limit", type=int, default=100, help="1-500 pointers")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Explicitly re-enqueue original records")
    mode.add_argument("--dry-run", action="store_true", help="Inspect availability only (default)")
    return parser


async def run(args):
    config = load_config()
    validate_security(config)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    try:
        rows = await replay_deadletters(redis, args.group, start=args.start, end=args.end,
                                       limit=args.limit, execute=args.execute, operational=True)
        for row in rows:
            print(json.dumps(row, separators=(",", ":")))
        return int(any(row["status"] in {"missing_source", "invalid_pointer"} for row in rows))
    finally:
        await redis.aclose()


def main(argv=None):
    args = argument_parser().parse_args(argv)
    try:
        return asyncio.run(run(args))
    except Exception as exc:
        # Operator output contains identifiers and reason classes, never event payloads.
        print(json.dumps({"status": "replay_failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
