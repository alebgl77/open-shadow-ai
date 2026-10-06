"""Producer acknowledgment and archive failure acceptance, without external services."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis.exceptions import ResponseError

from shadai.api import agent, ingestion
from shadai.api.collectors import authenticate_collector
from shadai.collectors.entra import InventoryDelivery
from shadai.collectors.syslog_receiver import SyslogCollector
from shadai.config import RedisQueueSettings
from shadai.models.event import CanonicalEvent
from shadai.parsers.proxy.squid import SquidAccessLogParser
from shadai.utils.queue_admission import QueueAdmissionError, admission_arguments, admit_records, bounded_batches
from shadai.workers import redis_lifecycle as lifecycle


def record(stream="events:dns", value="synthetic"):
    return {"stream": stream, "fields": {"data": value}}


async def test_inventory_never_prints_unrecognized_schema_contents(monkeypatch):
    redis = AsyncMock()
    redis.time.return_value = (1000, 0)
    redis.xinfo_groups.return_value = []
    redis.xlen.return_value = 0
    redis.exists.return_value = 1
    redis.get.return_value = "synthetic text that is not operational schema"
    monkeypatch.setattr(lifecycle, "purge", AsyncMock(return_value={"status": "inspected"}))
    monkeypatch.setattr(lifecycle, "retention_ready", AsyncMock(return_value=False))
    result = await lifecycle.inventory(redis, "ingest_group", stream="events:dns")
    assert result["schema"] == "invalid" and "synthetic text" not in json.dumps(result)


@pytest.mark.parametrize("records", [[record("unsupported")], [record()] * 501,
                                   [{"stream": "matches", "fields": {str(i): "x" for i in range(33)}}],
                                   [{"stream": "matches", "fields": {"x": 1}}]])
async def test_bad_batch_never_calls_redis(records):
    redis = AsyncMock()
    with pytest.raises(QueueAdmissionError):
        await admit_records(redis, records)
    redis.eval.assert_not_called()


@pytest.mark.parametrize("response", [None, [], ["ok"], ["ok", "1-0", "2-0"], ["denied", "full"],
                                    ["denied", "destination"], ["ok", "malformed"]])
async def test_only_complete_positive_ids_confirm_delivery(response):
    redis = AsyncMock()
    redis.eval.return_value = response
    with pytest.raises(QueueAdmissionError):
        await admit_records(redis, [record()])


def test_batch_bytes_count_utf8_and_every_destination():
    settings = RedisQueueSettings(admission_max_batch_bytes=100)
    with pytest.raises(QueueAdmissionError):
        admission_arguments([record(value="é" * 50)], settings)
    rows = [record(value="é" * 20)] * 5
    chunks = list(bounded_batches(rows, settings=settings))
    assert all(len(admission_arguments(chunk, settings)[1]) > 0 for chunk in chunks)
    assert sum(map(len, chunks)) == 5


@pytest.mark.parametrize("endpoint", ["events", "telemetry"])
@pytest.mark.parametrize("error", [["denied", "full"], ["denied", "destination"], ResponseError("secret-payload")])
def test_actual_http_queue_refusal_never_contacts_collector(monkeypatch, endpoint, error):
    app = FastAPI()
    app.include_router(ingestion.router)
    app.include_router(agent.router)
    principal = SimpleNamespace(legacy=True, collector_id="legacy:unattributed", require_sources=Mock(),
                                bind=lambda identity: "legacy:unattributed", contact=Mock())
    app.dependency_overrides[authenticate_collector] = lambda: principal
    redis = AsyncMock()
    if isinstance(error, Exception):
        redis.eval.side_effect = error
    else:
        redis.eval.return_value = error
    monkeypatch.setattr(ingestion, "get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr(agent, "get_redis", AsyncMock(return_value=redis))
    if endpoint == "events":
        payload = {"events": [CanonicalEvent(tenant_id="test-org", collector_id="synthetic").model_dump(mode="json")]}
        path = "/api/v1/ingest/events"
    else:
        payload = {"hostname": "synthetic", "timestamp": datetime.now(UTC).isoformat(),
                   "processes": [{"name": "synthetic"}], "extensions": [{"id": "synthetic"}]}
        path = "/api/v1/agent/telemetry"
    response = TestClient(app).post(path, json=payload)
    assert response.status_code == 503 and response.headers["Retry-After"] == "5"
    assert response.json() == {"detail": "Queue temporarily unavailable"}
    principal.contact.assert_not_called()
    redis.pipeline.assert_not_called()


async def test_entra_retains_exact_rejected_chunk_and_cannot_replace_inventory():
    redis = AsyncMock()
    redis.eval.side_effect = [["ok", *(f"{i+1}-0" for i in range(500))], ["denied", "full"]]
    delivery = InventoryDelivery(redis, RedisQueueSettings())
    delivery.retain([CanonicalEvent(source_type="oauth", tenant_id="test-org") for _ in range(501)])
    with pytest.raises(QueueAdmissionError):
        await delivery.flush()
    rejected = json.dumps(delivery.pending[0], separators=(",", ":")).encode()
    with pytest.raises(RuntimeError):
        delivery.retain([])
    redis.eval.side_effect = None
    redis.eval.return_value = ["ok", "502-0"]
    assert await delivery.flush() == 501 and not delivery.pending
    # The retry's flattened Lua fields equal those in the rejected chunk.
    assert list(json.loads(rejected)[0]["fields"].items()) == list(zip(
        redis.eval.call_args.args[-4::2], redis.eval.call_args.args[-3::2], strict=True))


class HeldSpool:
    def __init__(self, payload):
        self.batch = SimpleNamespace(payload=payload)
        self.claimed = False
        self.ack = Mock(side_effect=self._ack)
        self.retry = Mock(side_effect=lambda batch: setattr(self, "claimed", False))

    def _ack(self, batch):
        self.batch = None

    def claim(self, **kwargs):
        if self.batch is None or self.claimed:
            return []
        self.claimed = True
        return [self.batch]


@pytest.mark.parametrize("error", [TimeoutError("lost reply"), ["denied", "full"], ["ok"]])
async def test_spool_keeps_immutable_bytes_until_complete_positive_delivery(error):
    payload = json.dumps([record("events:proxy")], separators=(",", ":")).encode()
    spool = HeldSpool(payload)
    redis = AsyncMock()
    if isinstance(error, Exception):
        redis.eval.side_effect = error
    else:
        redis.eval.return_value = error
    collector = SyslogCollector("synthetic", SquidAccessLogParser(), redis, spool=spool)
    assert await collector.flush_spool(limit=1) == 0
    spool.ack.assert_not_called()
    assert spool.batch.payload == payload
    redis.eval.side_effect = None
    redis.eval.return_value = ["ok", "1-0"]
    assert await collector.flush_spool(limit=1) == 1
    spool.ack.assert_called_once()


def archive_document():
    return {"version": 1, "kind": "redis-retention", "group": "ingest_group", "stream": "events:dns",
            "cutoff": "9007199254740993-0", "records": [{"stream": "events:dns", "source_id": "1-0",
            "pointer_id": "", "source_fields": lifecycle.pack_fields([b"duplicate", b"\xff", b"duplicate", b"two"]),
            "pointer_fields": []}]}


def test_archive_authenticates_exact_ordered_binary_fields_and_refuses_overwrite(tmp_path, monkeypatch):
    # Native ACL behavior is separately covered by the spool suite. Keep these
    # cryptography/ordering tests portable, including restrictive sandbox hosts.
    monkeypatch.setattr(lifecycle, "_private_directory", lambda path: path.mkdir(exist_ok=True))
    monkeypatch.setattr(lifecycle, "_private_ancestors", lambda path: None)
    monkeypatch.setattr(lifecycle, "_check_path", lambda *args, **kwargs: None)
    path, key = tmp_path / "private" / "archive.fernet", Fernet.generate_key()
    digest = lifecycle.write_archive(path, archive_document(), key)
    document, verified = lifecycle.verify_archive(path, key)
    assert document == archive_document() and verified == digest
    with pytest.raises(FileExistsError):
        lifecycle.write_archive(path, document, key)
    with pytest.raises(InvalidToken):
        lifecycle.verify_archive(path, Fernet.generate_key())
    path.write_bytes(path.read_bytes()[:-1] + b"x")
    with pytest.raises(InvalidToken):
        lifecycle.verify_archive(path, key)


@pytest.mark.parametrize("failure", ["private", "write", "fsync", "verification"])
async def test_archive_failure_prevents_every_redis_delete(tmp_path, monkeypatch, failure):
    redis = AsyncMock()
    redis.time.return_value = (2_000_000, 0)
    monkeypatch.setattr(lifecycle, "raw_range", AsyncMock(return_value=[("1-0", [b"data", b"synthetic"])]))
    writer = Mock(side_effect=OSError(failure))
    if failure == "verification":
        writer.side_effect = None
        writer.return_value = "0" * 64
        monkeypatch.setattr(lifecycle, "verify_archive", Mock(side_effect=InvalidToken()))
    monkeypatch.setattr(lifecycle, "write_archive", writer)
    with pytest.raises((OSError, InvalidToken)):
        await lifecycle.purge(redis, "ingest_group", stream="events:dns", execute=True,
                              archive=tmp_path / "archive", encryption_key=Fernet.generate_key(), limit=1)
    redis.eval.assert_not_called()


async def test_real_archive_fsync_failure_happens_before_redis_delete(tmp_path, monkeypatch):
    redis = AsyncMock()
    redis.time.return_value = (2_000_000, 0)
    monkeypatch.setattr(lifecycle, "raw_range", AsyncMock(return_value=[("1-0", [b"data", b"synthetic"])]))
    monkeypatch.setattr(lifecycle, "_private_directory", lambda path: path.mkdir(exist_ok=True))
    monkeypatch.setattr(lifecycle, "_private_ancestors", lambda path: None)
    monkeypatch.setattr(lifecycle, "_check_path", lambda *args, **kwargs: None)
    def failed_fsync(descriptor):
        raise OSError("synthetic fsync failure")
    monkeypatch.setattr(lifecycle.os, "fsync", failed_fsync)
    path, key = tmp_path / "private" / "archive", Fernet.generate_key()
    with pytest.raises(OSError):
        await lifecycle.purge(redis, "ingest_group", stream="events:dns", execute=True,
                              archive=path, encryption_key=key, limit=1)
    assert path.exists() and Fernet(key).decrypt(path.read_bytes())
    redis.eval.assert_not_called()


async def test_oversized_entra_record_remains_pending_without_false_success():
    redis = AsyncMock()
    delivery = InventoryDelivery(redis, RedisQueueSettings(admission_max_batch_bytes=1))
    delivery.retain([CanonicalEvent(source_type="oauth")])
    before = json.dumps(delivery.pending).encode()
    with pytest.raises(QueueAdmissionError):
        await delivery.flush()
    assert json.dumps(delivery.pending).encode() == before
    redis.eval.assert_not_called()


@pytest.mark.parametrize("options", [{}, {"archive": "x", "discard": True}])
async def test_purge_requires_explicit_retention_decision_before_redis(options):
    redis = AsyncMock()
    with pytest.raises(ValueError):
        await lifecycle.purge(redis, "ingest_group", execute=True, **options)
    redis.time.assert_not_called()


async def test_legacy_reconciliation_requires_explicit_stopped_writers():
    redis = AsyncMock()
    with pytest.raises(ValueError):
        await lifecycle.reconcile(redis, execute=True)
    redis.eval.assert_not_called()


def test_local_archive_verification_never_connects_to_redis(tmp_path, monkeypatch):
    import asyncio

    from shadai.config import get_config

    expected = archive_document()
    monkeypatch.setattr(lifecycle, "verify_archive", lambda *args: (expected, "1" * 64))
    connector = Mock(side_effect=AssertionError("Redis not permitted"))
    monkeypatch.setattr(lifecycle.aioredis, "from_url", connector)
    args = SimpleNamespace(action="verify-archive", path=tmp_path / "archive")
    assert asyncio.run(lifecycle.run(args))["count"] == 1
    assert get_config().security.encryption_key
    connector.assert_not_called()


def test_legacy_children_keep_actual_endpoint_snapshot_identity_across_retries(monkeypatch):
    from shadai_agent import main as client

    app = FastAPI()
    app.include_router(agent.router)
    collector = ["sensor-original"]
    principal = SimpleNamespace(legacy=False, collector_id=collector[0], require_sources=Mock(), contact=Mock())
    app.dependency_overrides[authenticate_collector] = lambda: principal
    observed = []
    async def evaluate(script, count, *args):
        values = args[count:]
        number, pos = int(values[0]), 3
        rows = []
        for _ in range(number):
            pairs = int(values[pos+1])
            pos += 2
            fields = dict(zip(values[pos:pos+2*pairs:2], values[pos+1:pos+2*pairs:2], strict=True))
            pos += 2*pairs
            rows.append(json.loads(fields["data"]))
        observed.append(rows)
        return ["ok", *(f"{i+1}-0" for i in range(number))]
    redis = SimpleNamespace(eval=evaluate)
    monkeypatch.setattr(agent, "get_redis", AsyncMock(return_value=redis))
    snapshot = {"hostname": "synthetic", "timestamp": datetime.now(UTC).isoformat(), "agent_version": "legacy",
                "processes": [{"name": f"p{i}", "username": "same"} for i in range(500)],
                "extensions": [{"id": f"ext{i}", "browser": "chrome"} for i in range(500)]}
    original = json.dumps(snapshot, indent=2).encode()
    children = client.delivery_payloads(original)
    assert len(children) == 2
    wire = TestClient(app)
    def post(url, **kwargs):
        return wire.post("/api/v1/agent/telemetry", content=kwargs["data"],
                         headers={"Content-Type": "application/json"})
    monkeypatch.setattr(client.requests, "post", post)
    assert client.send_once("https://synthetic.test", original, {}, True) == 1000
    assert client.send_once("https://synthetic.test", original, {}, True) == 1000
    for first, retry in zip(observed[:2], observed[2:4], strict=True):
        assert [row["event_id"] for row in first] == [row["event_id"] for row in retry]
        instant = datetime.fromisoformat(snapshot["timestamp"])
        assert all(datetime.fromisoformat(row["timestamp"]) == instant and
                   datetime.fromisoformat(row["normalized_at"]) == instant
                   and row["tenant_id"] == "test-org" and row["collector_id"] == "sensor-original" for row in retry)
    principal.collector_id = "another-enrolled-sensor"
    assert client.send_once("https://synthetic.test", original, {}, True) == 1000
    assert {row["event_id"] for rows in observed[:2] for row in rows}.isdisjoint(
        {row["event_id"] for rows in observed[4:] for row in rows})
