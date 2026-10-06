"""Bounded deployment operational state, shared by workers and API processes.

Redis stream lengths count retained records. Only consumer-group lag measures
undelivered records; older Redis versions legitimately report no lag value.
Worker counters measure queue operations, not unique events or capture loss.
"""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

from redis.exceptions import ResponseError

SOURCES = ('dns', 'proxy', 'endpoint', 'browser', 'oauth', 'directory', 'instrumented', 'casb', 'network')
STAGES = {'ingest': ('ingest_group', tuple('events:' + source for source in SOURCES)),
          'correlation': ('correlate_group', ('matches',))}
STATE_TTL = 86400
FRESH_SECONDS = 90
BLOCKED_SECONDS = 300
COUNTERS = ('acknowledged', 'retryable_failures', 'rejected_attempts', 'deadlettered', 'replayed')


def operation_key(group: str, stream: str) -> str:
    if not any(group == expected and stream in streams for expected, streams in STAGES.values()):
        raise ValueError('Unsupported operational stream')
    return f'operations:{group}:{stream}'


# Used inside delivery Lua after a successful state transition. Counters and ACK
# share a Redis transaction, including the case where the response is lost.
COUNT_OPERATION = """
local function check_operation(key, field)
    local value = redis.call('HGET', key, field)
    if value and (not tonumber(value) or tonumber(value) < 0 or
                  tonumber(value) % 1 ~= 0 or tonumber(value) >= 1000000000000000000) then
        error('Invalid operational counter')
    end
end
local function record_operation(key, field)
    check_operation(key, field)
    local now = redis.call('TIME')
    local seconds = string.format('%.6f', tonumber(now[1]) + tonumber(now[2]) / 1000000)
    redis.call('HSETNX', key, 'since', seconds)
    redis.call('HINCRBY', key, field, 1)
    if field == 'acknowledged' or field == 'deadlettered' or field == 'replayed' then
        redis.call('HSET', key, 'last_progress_at', seconds)
    else
        redis.call('HSET', key, 'last_failure_at', seconds)
    end
    redis.call('EXPIRE', key, 86400)
end
"""
PULSE = """
local now = redis.call('TIME')
local seconds = string.format('%.6f', tonumber(now[1]) + tonumber(now[2]) / 1000000)
for _, key in ipairs(KEYS) do
    redis.call('HSETNX', key, 'since', seconds)
    redis.call('HSET', key, ARGV[1], seconds)
    redis.call('EXPIRE', key, 86400)
end
return 1
"""


class WorkerOperations:
    """Fixed aggregate group keys; no process, collector or personal labels."""

    def __init__(self, redis, group, streams):
        self.redis = redis
        self.keys = tuple(operation_key(group, stream) for stream in streams)

    async def pulse(self, field='last_seen_at'):
        if field not in ('last_seen_at', 'last_poll_at'):
            raise ValueError('Unsupported operational pulse')
        await self.redis.eval(PULSE, len(self.keys), *self.keys, field)

    async def heartbeat(self):
        while True:
            try:
                await self.pulse()
            except Exception:
                # Monitoring cannot ACK/discard delivery work. On outage the
                # existing timestamp expires/stales; readers see unknown.
                pass
            await asyncio.sleep(10)


def number(value):
    try:
        parsed = float(value)
        return parsed if 0 <= parsed < 1e20 else None
    except (ValueError, TypeError, OverflowError):
        return None


def integer(value):
    parsed = number(value)
    return int(parsed) if parsed is not None and parsed.is_integer() else None


def date(value):
    parsed = number(value)
    try:
        return datetime.fromtimestamp(parsed, UTC).isoformat() if parsed is not None else None
    except (ValueError, OverflowError, OSError):
        return None


async def stream_snapshot(redis, group, stream, now):
    state = await redis.hgetall(operation_key(group, stream))
    try:
        groups = await redis.xinfo_groups(stream)
        retained = await redis.xlen(stream)
    except ResponseError as exc:
        if 'no such key' not in str(exc).lower():
            raise
        groups, retained = [], None
    selected = next((item for item in groups if item.get('name') == group), None)
    pending = integer(selected.get('pending')) if selected else None
    lag = integer(selected.get('lag')) if selected else None
    oldest = None
    if pending:
        rows = await redis.xpending_range(stream, group, '-', '+', 1)
        if rows:
            queued = number(rows[0].get('message_id', '').split('-')[0])
            oldest = max(0, now - queued / 1000) if queued is not None else None
    seen, poll, progress, since = (number(state.get(field)) for field in
                                  ('last_seen_at', 'last_poll_at', 'last_progress_at', 'since'))
    fresh = seen is not None and 0 <= now - seen <= FRESH_SECONDS
    # Counters absent in a fresh initialized epoch mean zero operations in that
    # epoch; expired/missing publications are unknown, never a lifetime zero.
    counters = {field: (integer(state.get(field, 0)) if fresh and since is not None else None)
                for field in COUNTERS}
    if not fresh:
        status = 'stale' if seen is not None else 'unknown'
    elif pending is None or lag is None:
        status = 'unknown'
    elif pending + lag == 0:
        status = 'idle' if poll is not None and now - poll <= FRESH_SECONDS else 'unknown'
    elif now - (progress if progress is not None else since or now) > BLOCKED_SECONDS:
        status = 'blocked'
    else:
        status = 'processing'
    return {'stream': stream, 'status': status, 'group_present': selected is not None,
            'retained_entries': retained, 'pending': pending, 'undelivered': lag,
            'oldest_pending_age_seconds': oldest, 'worker_state_fresh': fresh,
            'last_worker_seen_at': date(seen), 'last_poll_at': date(poll),
            'last_progress_at': date(progress), 'last_failure_at': date(state.get('last_failure_at')),
            'counters_since': date(since), 'counters': counters}


async def pipeline_snapshot(redis, *, now=None):
    now = time.time() if now is None else now
    stages = []
    for stage, (group, streams) in STAGES.items():
        rows = await asyncio.gather(*(stream_snapshot(redis, group, stream, now) for stream in streams))
        deadletters = await redis.xlen('deadletter:' + group)
        statuses = {row['status'] for row in rows}
        status = next((value for value in ('blocked', 'stale', 'unknown', 'processing', 'idle')
                       if value in statuses), 'unknown')
        stages.append({'stage': stage, 'group': group, 'status': status,
                       'deadletter_retained': deadletters, 'streams': rows})
    return {'scope': 'deployment', 'as_of': date(now), 'backend_available': True, 'stages': stages,
            'capture_loss': None}


def unavailable_pipeline():
    return {'scope': 'deployment', 'as_of': datetime.now(UTC).isoformat(),
            'backend_available': False, 'stages': [], 'capture_loss': None}


async def read_pipeline(redis):
    try:
        return await asyncio.wait_for(pipeline_snapshot(redis), timeout=5)
    except Exception:
        return unavailable_pipeline()
