"""Stateful outage/backoff and controlled replay tests with a disposable Redis model."""

import json
from collections import defaultdict
from unittest.mock import AsyncMock

import pytest

from shadai.utils.queueing import PermanentMessageError
from shadai.workers.replay import REPLAY, replay_deadletters
from shadai.workers.streams import ACK_SUCCESS, DEADLETTER, RECORD_RETRY, StreamConsumer


class MemoryRedis:
    def __init__(self):
        self.streams = defaultdict(dict)
        self.pending = set()
        self.state = {}
        self.markers = {}
        self.groups = {"events:dns": ["ingest_group"]}
        self.sequence = 100
        self.expiry = {}
        self.fresh = []
        self.refs = defaultdict(dict)
        self.schema = "1"

    async def hgetall(self, key):
        return dict(self.state.get(key, {}))

    async def delete(self, key):
        self.state.pop(key, None)

    async def xrange(self, stream, min="-", max="+", count=100):
        return [(identifier, fields) for identifier, fields in self.streams[stream].items()
                if (min == "-" or tuple(map(int, identifier.split("-"))) >= tuple(map(int, min.split("-"))))
                and (max == "+" or tuple(map(int, identifier.split("-"))) <= tuple(map(int, max.split("-"))))][:count]

    async def eval(self, script, numkeys, *values):
        if script == RECORD_RETRY:
            key, next_at, permanent = values
            row = self.state.setdefault(key, {})
            attempts = min(int(row.get("attempts", 0)) + 1, 65535)
            poison = min(int(row.get("poison_attempts", 0)) + int(permanent), 65535)
            row.update({"attempts": str(attempts), "poison_attempts": str(poison), "next_at": next_at})
            self.expiry[key] = 604800
            return [attempts, poison]
        if script == DEADLETTER:
            stream, dlq, retry_key, refkey, schema, group, message_id, error_type, attempts, cap = values
            if (stream, message_id) not in self.pending:
                return 0
            if dlq in self.markers:  # Wrong type simulates Redis atomic-script failure.
                raise RuntimeError("WRONGTYPE")
            if len(self.streams[dlq]) >= int(cap):
                return -1
            self.refs[refkey][message_id] = self.refs[refkey].get(message_id, 0) + 1
            self.sequence += 1
            self.streams[dlq][f"{self.sequence}-0"] = {
                "stream": stream, "message_id": message_id, "error_type": error_type, "attempts": attempts,
            }
            self.pending.remove((stream, message_id))
            self.state.pop(retry_key, None)
            return 1
        if script == ACK_SUCCESS:
            stream, refkey, schema, group, message_id = values
            if (stream, message_id) not in self.pending:
                return 0
            self.pending.remove((stream, message_id))
            if len(self.groups.get(stream, [])) == 1 and self.schema == "1" and not self.refs[refkey].get(message_id):
                self.streams[stream].pop(message_id, None)
            return 1
        if script == REPLAY:
            stream, dlq, marker, refkey, schema, pointer_id, message_id, cap, maxbytes, expected = values
            pointer = self.streams[dlq].get(pointer_id)
            if pointer is None:
                return ["missing_pointer", ""]
            if [item for pair in pointer.items() for item in pair] != json.loads(expected):
                return ["changed_pointer", ""]
            if marker in self.markers:
                return ["already_replayed", self.markers[marker]]
            if message_id not in self.streams[stream]:
                return ["missing_source", ""]
            if len(self.streams[stream]) >= int(cap):
                return ["full", ""]
            self.sequence += 1
            replay_id = f"{self.sequence}-0"
            self.streams[stream][replay_id] = dict(self.streams[stream][message_id])
            self.markers[marker] = replay_id
            return ["replayed", replay_id]
        raise AssertionError("Unexpected script")

    async def xautoclaim(self, stream, *args, **kwargs):
        return ["0-0", [(identifier, self.streams[stream][identifier])
                         for source, identifier in sorted(self.pending) if source == stream], []]

    async def xreadgroup(self, *args, **kwargs):
        fresh, self.fresh = self.fresh, []
        return fresh


@pytest.mark.parametrize("exception", [OSError, TimeoutError, RuntimeError, ValueError, TypeError])
async def test_datastore_and_unexpected_failures_over_five_reclaims_resume_good_work(exception):
    redis, now = MemoryRedis(), [100.0]
    fields = {"data": '{"event_id":"stable-id"}', "accepted_at": "2026-10-06T00:00:00+00:00"}
    redis.streams["events:dns"]["1-0"] = fields
    redis.pending.add(("events:dns", "1-0"))
    consumer = StreamConsumer(redis, "ingest_group", "test", ["events:dns"], clock=lambda: now[0])
    handler = AsyncMock(side_effect=exception("private failure message"))
    for _ in range(9):
        assert not await consumer.process("events:dns", "1-0", fields, handler)
        now[0] += 301
    assert ("events:dns", "1-0") in redis.pending and not redis.streams["deadletter:ingest_group"]
    assert redis.state["retries:ingest_group:events:dns:1-0"]["poison_attempts"] == "0"
    handler.side_effect = None
    assert await consumer.process("events:dns", "1-0", fields, handler)
    assert not redis.pending and not redis.state
    assert consumer.stats()["retryable_failures"] == 9 and consumer.stats()["succeeded"] == 1


async def test_poison_isolated_without_consuming_budget_during_prior_outage():
    redis, now = MemoryRedis(), [100.0]
    redis.streams["events:dns"]["1-0"] = {"data": "invalid JSON"}
    redis.pending.add(("events:dns", "1-0"))
    consumer = StreamConsumer(redis, "ingest_group", "test", ["events:dns"], clock=lambda: now[0], max_attempts=2)
    handler = AsyncMock(side_effect=OSError())
    for _ in range(6):
        assert not await consumer.process("events:dns", "1-0", {}, handler)
        now[0] += 301
    handler.side_effect = PermanentMessageError("contains private raw line")
    assert not await consumer.process("events:dns", "1-0", {}, handler)
    now[0] += 301
    assert await consumer.process("events:dns", "1-0", {}, handler)
    assert not redis.pending and redis.streams["events:dns"]["1-0"] == {"data": "invalid JSON"}
    [pointer] = redis.streams["deadletter:ingest_group"].values()
    assert pointer["error_type"] == "PermanentMessageError"
    assert "private" not in str(pointer) and "invalid JSON" not in str(pointer)


async def test_backoff_no_hotloop_and_valid_fresh_message_not_starved():
    redis, now = MemoryRedis(), [100.0]
    redis.pending.add(("events:dns", "1-0"))
    redis.streams["events:dns"]["1-0"] = {"data": "old"}
    consumer = StreamConsumer(redis, "ingest_group", "test", ["events:dns"], clock=lambda: now[0])
    failing = AsyncMock(side_effect=OSError())
    assert not await consumer.process("events:dns", "1-0", {}, failing)
    assert not await consumer.process("events:dns", "1-0", {}, failing)
    failing.assert_awaited_once()
    redis.fresh = [("events:dns", [("2-0", {"data": "fresh"})])]
    rows = await consumer.read()
    assert rows[1] == ("events:dns", [("2-0", {"data": "fresh"})])
    assert consumer.stats()["backoff_deferred"] == 1
    assert set(redis.expiry.values()) == {604800}


async def test_wrongtype_deadletter_cannot_ack_original():
    redis = MemoryRedis()
    redis.pending.add(("events:dns", "1-0"))
    redis.markers["deadletter:ingest_group"] = "wrong-type"
    consumer = StreamConsumer(redis, "ingest_group", "test", ["events:dns"], max_attempts=1)
    with pytest.raises(RuntimeError, match="WRONGTYPE"):
        await consumer.process("events:dns", "1-0", {}, AsyncMock(side_effect=PermanentMessageError()))
    assert ("events:dns", "1-0") in redis.pending


async def test_duplicate_ack_cannot_inflate_success_counter():
    redis = MemoryRedis()
    consumer = StreamConsumer(redis, "ingest_group", "test", ["events:dns"])
    assert await consumer.process("events:dns", "already-acked", {}, AsyncMock())
    assert consumer.stats() == {"duplicate_ack": 1}


async def test_replay_is_bounded_safe_same_fields_and_ack_lost_repeat_idempotent():
    redis = MemoryRedis()
    fields = {"data": '{"event_id":"same","timestamp":"old"}', "accepted_at": "original-acceptance"}
    redis.streams["events:dns"]["1-0"] = fields
    redis.streams["deadletter:ingest_group"] = {
        "2-0": {"stream": "events:dns", "message_id": "1-0"},
        "3-0": {"stream": "events:dns", "message_id": "missing"},
        "4-0": {"stream": "arbitrary-sensitive-payload", "message_id": "1-0"},
        "5-0": {"stream": "events:dns", "message_id": "99-0"},
    }
    dry = await replay_deadletters(redis, "ingest_group", limit=1)
    assert dry[0]["status"] == "ready" and len(redis.streams["events:dns"]) == 1
    first = await replay_deadletters(redis, "ingest_group", execute=True)
    second = await replay_deadletters(redis, "ingest_group", execute=True)
    assert first[0]["status"] == "replayed" and second[0]["status"] == "already_replayed"
    assert first[0]["replay_id"] == second[0]["replay_id"]
    assert len(redis.streams["events:dns"]) == 2
    assert redis.streams["events:dns"][first[0]["replay_id"]] == fields
    assert first[3]["status"] == "missing_source"
    assert "arbitrary-sensitive" not in str(first) and "old" not in str(first)
    assert redis.streams["events:dns"]["1-0"] == fields


@pytest.mark.parametrize("options", [{"group": "admin"}, {"group": "ingest_group", "limit": 501},
                                     {"group": "ingest_group", "start": "unsafe"}])
async def test_replay_rejects_injection_before_redis(options):
    redis = AsyncMock()
    with pytest.raises(ValueError):
        await replay_deadletters(redis, **options)
    redis.xrange.assert_not_called()
