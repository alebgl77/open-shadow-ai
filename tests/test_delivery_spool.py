"""Durable client recovery and metadata privacy; ancestor safety is checked separately."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from shadai_agent import delivery_spool as vendored
from shadai_agent import main as agent

from shadai.collectors.network import DeliveryError, DurableEventTransport, EventTransport
from shadai.collectors.syslog_receiver import SyslogCollector, SyslogUDPProtocol
from shadai.models.event import CanonicalEvent
from shadai.parsers.proxy.squid import SquidAccessLogParser
from shadai.utils import delivery_spool
from shadai.utils.delivery_spool import DurableSpool, SpoolError, SpoolFullError
from shadai.utils.queueing import PermanentMessageError, prepare_queued_event, queue_fields


@pytest.fixture
def spool(tmp_path, monkeypatch):
    # This isolates DB/client semantics from unsafe inherited sandbox ancestors.
    # Native leaf/database DACL checks still run. Dedicated ACL smoke has no mocks.
    monkeypatch.setattr(delivery_spool, "_private_ancestors", lambda path: None)
    value = DurableSpool(tmp_path / "private-spool")
    yield value
    value.close()


def test_standalone_vendor_is_exact_stdlib_copy():
    assert Path(vendored.__file__).read_bytes() == Path(delivery_spool.__file__).read_bytes()
    assert "shadai." not in Path(vendored.__file__).read_text()


def test_spool_binding_survives_restart_and_rejects_reassigned_credentials(spool):
    spool.bind("target", "https://api.test")
    spool.bind("collector", "registered-collector")
    spool.enqueue(b"retained")
    spool.close()
    with DurableSpool(spool.directory) as restarted:
        restarted.bind("collector", "registered-collector")
        with pytest.raises(SpoolError, match="binding_mismatch"):
            restarted.bind("collector", "other-collector")
        [batch] = restarted.claim()
        assert batch.payload == b"retained"


def test_invalid_budgets_fail_before_touching_storage(tmp_path):
    for options in ({"max_bytes": 0}, {"max_batches": 100001}, {"ttl_seconds": 366 * 86400}):
        with pytest.raises(ValueError):
            DurableSpool(tmp_path / "absent", **options)
    assert not (tmp_path / "absent").exists()


def test_real_sqlite_disk_full_is_explicit_and_retains_previous_bytes(spool):
    spool.enqueue(b"original")
    pages = spool.db.execute("PRAGMA page_count").fetchone()[0]
    spool.db.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(SpoolError, match="spool_storage_failure"):
        spool.enqueue(b"x" * 1024 * 1024)
    [batch] = spool.claim()
    assert batch.payload == b"original"
    assert spool.stats()["storage_failures"] == 1
    assert spool.stats()["enqueued"] == 1


def test_quarantine_shares_budget_and_counts_events_not_batches(spool):
    spool.max_bytes = 10
    spool.max_batches = 1
    spool.enqueue(b"bad", event_count=3)
    [batch] = spool.claim()
    spool.quarantine(batch, "delivery_http_422")
    with pytest.raises(SpoolFullError):
        spool.enqueue(b"new", event_count=2)
    stats = spool.stats()
    assert stats["quarantine"] == 1 and stats["quarantined_events"] == 3
    assert stats["overflow_events"] == 2 and not spool.claim()


def test_operator_can_raise_budget_above_defaults_with_individual_batch_bound(spool):
    spool.close()
    with DurableSpool(spool.directory, max_bytes=1024 * 1024 * 1024, max_batches=10_000,
                      ttl_seconds=30 * 86400) as enlarged:
        assert enlarged.ttl_seconds == 30 * 86400
        with pytest.raises(SpoolFullError, match="batch_size_exceeded"):
            enlarged.enqueue(b"x" * (delivery_spool.MAX_PAYLOAD_BYTES + 1), event_count=10)
        assert enlarged.stats()["overflow_events"] == 10 and enlarged.stats()["batches"] == 0


def test_large_backlog_claim_page_is_bounded_by_bytes_without_claiming_remainder(spool):
    size = 1024 * 1024
    for number in range(20):
        spool.enqueue(bytes([number]) + b"x" * (size - 1))
    claimed = spool.claim(limit=64)
    assert len(claimed) == 16
    assert sum(len(batch.payload) for batch in claimed) <= delivery_spool.MAX_CLAIM_BYTES
    remaining = spool.claim(limit=64)
    assert len(remaining) == 4
    assert len({batch.batch_id for batch in claimed + remaining}) == 20


def test_success_status_with_invalid_ack_body_retains_agent_batch(spool, monkeypatch):
    payload = b'{"hostname":"synthetic","processes":[]}'
    spool.enqueue(payload)
    monkeypatch.setattr(agent.requests, "post", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {}))
    config = SimpleNamespace(server_url="https://api.test", api_key="synthetic", ca_bundle="")
    agent.drain_spool(spool, config)
    assert spool.stats()["pending"] == 1 and spool.stats()["retried"] == 1


def test_expiry_durable_count_has_event_cardinality(spool):
    now = [100.0]
    spool.clock = lambda: now[0]
    spool.ttl_seconds = 5
    spool.enqueue(b"batch", event_count=7)
    now[0] = 105
    assert not spool.claim()
    assert spool.stats()["expired_events"] == 7
    spool.close()
    with DurableSpool(spool.directory, clock=lambda: now[0]) as restarted:
        assert restarted.stats()["expired_events"] == 7


def test_snapshot_wire_allowlist_discards_raw_paths_and_ignored_data():
    header = {"hostname": "ws", "timestamp": datetime.now(UTC).isoformat(), "agent_version": "test"}
    [batch] = agent.split_batches(header, {
        "processes": [{"name": "ollama", "path": "/secret/prompt", "command": "private prompt", "pid": 123}],
        "model_files": [{"path": "/private/model.gguf"}],
        "containers": [{"name": "local", "image": "ollama:latest", "mounts": "/secret/path"}],
        "local_ai_hits": [{"process_name": "ollama", "tool_name": "Ollama", "url": "/secret"}],
    })
    encoded = json.dumps(batch)
    assert "secret" not in encoded and "model_files" not in encoded and "prompt" not in encoded
    assert batch["processes"] == [{"name": "ollama"}]


@pytest.mark.parametrize("status", [301, 403, 422])
def test_agent_nonretry_status_quarantines_original(spool, monkeypatch, status):
    spool.enqueue(b'{"hostname":"test","processes":[]}', event_count=0)
    monkeypatch.setattr(agent.requests, "post", lambda *a, **k: SimpleNamespace(status_code=status))
    config = SimpleNamespace(server_url="https://api.test", api_key="private-key", ca_bundle="")
    assert agent.drain_spool(spool, config) == 0
    assert spool.stats()["quarantine"] == 1
    assert b"private-key" not in (spool.directory / "delivery.sqlite3").read_bytes()


def test_agent_401_rotation_resumes_same_bytes_after_restart(spool, monkeypatch):
    payload = b'{"hostname":"test","timestamp":"2026-10-06T12:00:00+00:00","processes":[{"name":"synthetic"}]}'
    spool.enqueue(payload)
    calls = []
    def post(*args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(status_code=401 if kwargs["headers"]["X-API-Key"] == "old" else 200,
                               json=lambda: {"received": 1})
    monkeypatch.setattr(agent.requests, "post", post)
    config = SimpleNamespace(server_url="https://api.test", api_key="old", ca_bundle="")
    agent.drain_spool(spool, config)
    spool.close()
    with DurableSpool(spool.directory, clock=lambda: delivery_spool.time.time() + 300) as restarted:
        config.api_key = "new"
        assert agent.drain_spool(restarted, config) == 1
        assert restarted.stats()["batches"] == 0
    assert [call["data"] for call in calls] == [payload, payload]
    assert all(call["allow_redirects"] is False and call["verify"] is True for call in calls)


@pytest.mark.parametrize('received', [0, 1, True, None, '2'])
def test_partial_or_malformed_agent_ack_retains_exact_payload_after_restart(spool, monkeypatch, received):
    payload = b'{"processes":[{"name":"one"}],"containers":[{"name":"two"}]}'
    batch_id = spool.enqueue(payload, event_count=2)
    monkeypatch.setattr(agent.requests, 'post', lambda *a, **k:
                        SimpleNamespace(status_code=200, json=lambda: {'received': received}))
    config = SimpleNamespace(server_url='https://api.test', api_key='synthetic', ca_bundle='')
    assert agent.drain_spool(spool, config) == 0
    assert spool.stats().get('delivered_events', 0) == 0 and spool.stats()['queued_events'] == 2
    spool.close()
    with DurableSpool(spool.directory, clock=lambda: delivery_spool.time.time() + 300) as restarted:
        [retained] = restarted.claim()
        assert retained.batch_id == batch_id and retained.payload == payload


@pytest.mark.parametrize('payload,received', [
    (b'{"processes":[],"extensions":[]}', 0),
    (b'{"processes":[{}],"containers":[{}],"local_ai_hits":[{}],"extensions":[{}],"model_files":[{}]}', 4),
])
def test_agent_exact_combined_ack_excludes_ignored_sections(monkeypatch, payload, received):
    monkeypatch.setattr(agent.requests, 'post', lambda *a, **k:
                        SimpleNamespace(status_code=200, json=lambda: {'received': received}))
    assert agent.send_once('https://api.test', payload, {}, True) == received


def test_network_delayed_scoped_binding_is_durable_before_uncertain_post_and_blocks_legacy_restart(spool):
    sent = []
    config_calls = [503, 200]
    def answer(request):
        if request.method == 'GET':
            status = config_calls.pop(0)
            return httpx.Response(status, json={'collector_id': 'sensor', 'legacy': False,
                                               'allowed_source_types': ['network'], 'ingestion_max_age_days': 90})
        assert spool.has_binding('collector')  # Actual disk bind precedes POST.
        sent.append(request.content)
        raise httpx.ReadError('synthetic lost acknowledgement')
    client = httpx.Client(transport=httpx.MockTransport(answer))
    wire = EventTransport('https://api.test', 'key', client=client, retries=0, key_loader=lambda: 'key')
    durable = DurableEventTransport(wire, spool)
    assert not wire.discover_binding('sensor')
    payload = b'{"events":[{"event_id":"unchanged"}]}'
    durable.send(payload)
    assert spool.has_binding('collector') and sent == [payload]
    spool.close()
    with DurableSpool(spool.directory, clock=lambda: delivery_spool.time.time() + 300) as restarted:
        posted = []
        legacy_client = httpx.Client(transport=httpx.MockTransport(lambda request:
            posted.append(request) or httpx.Response(200, json={'legacy': True, 'ingestion_max_age_days': 90})))
        legacy = EventTransport('https://api.test', 'legacy', client=legacy_client, retries=0)
        replay = DurableEventTransport(legacy, restarted)
        legacy.expected_collector_id = 'sensor'
        with pytest.raises(DeliveryError, match='collector_binding_mismatch'):
            replay.drain()
        assert all(request.method == 'GET' for request in posted)
        assert restarted.stats()['queued_events'] == 1
        # Failed claim is delayed, but exact bytes/ID remain on disk.
        assert restarted.db.execute('SELECT payload FROM batches').fetchone()[0] == payload


def test_network_delayed_discovery_enforces_ttl_before_post(spool):
    requests = []
    client = httpx.Client(transport=httpx.MockTransport(lambda request:
        requests.append(request) or httpx.Response(200, json={'legacy': False, 'collector_id': 'sensor',
            'allowed_source_types': ['network'], 'ingestion_max_age_days': 1})))
    wire = EventTransport('https://api.test', 'key', client=client, retries=0)
    wire.expected_collector_id = 'sensor'
    durable = DurableEventTransport(wire, spool)
    with pytest.raises(DeliveryError, match='spool_ttl_exceeds_server_age'):
        durable.send(b'{"events":[{}]}')
    assert all(request.method == 'GET' for request in requests)
    assert spool.stats()['queued_events'] == 1


def test_network_post_401_retains_same_id_for_rotated_scoped_key_after_restart(spool):
    payload = b'{"events":[{"event_id":"same-after-rotation"}]}'
    sent = []
    def response(request):
        if request.method == 'GET':
            return httpx.Response(200, json={'legacy': False, 'collector_id': 'sensor',
                'allowed_source_types': ['network'], 'ingestion_max_age_days': 90})
        sent.append(request.content)
        return httpx.Response(401 if request.headers['X-API-Key'] == 'expired' else 202)
    with httpx.Client(transport=httpx.MockTransport(response)) as client:
        wire = EventTransport('https://api.test', 'expired', client=client)
        transport = DurableEventTransport(wire, spool)
        wire.expected_collector_id = 'sensor'
        transport.send(payload)
        assert spool.stats()['pending'] == 1 and spool.stats()['quarantine'] == 0
        assert wire.verified_key is None
        spool.close()
        with DurableSpool(spool.directory, clock=lambda: delivery_spool.time.time() + 300) as restarted:
            rotated = EventTransport('https://api.test', 'rotated', client=client)
            rotated.expected_collector_id = 'sensor'
            replay = DurableEventTransport(rotated, restarted)
            replay.drain()
            assert restarted.stats()['batches'] == 0 and restarted.has_binding('collector')
    assert sent == [payload, payload]


def test_agent_discovers_scoped_binding_and_heartbeat_failure_is_independent(spool, monkeypatch):
    config = SimpleNamespace(server_url="https://api.test", api_key="private-key", ca_bundle="",
                             collector_id="")
    monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {
        "legacy": False, "collector_id": "registered-agent", "allowed_source_types": ["endpoint"],
        "ingestion_max_age_days": 90,
    }))
    assert agent.discover_binding(config, spool) is True
    assert config.collector_id == "registered-agent"
    sent = []
    monkeypatch.setattr(agent.requests, "post", lambda *a, **k: sent.append((a, k)) or
                        SimpleNamespace(status_code=401))
    before = spool.stats()
    agent.send_heartbeat(config, before)
    assert spool.stats() == before
    [(_, request)] = sent
    assert request["json"]["queue_events"] == 0 and request["allow_redirects"] is False
    assert request["json"]["collector_id"] == "registered-agent" and "private-key" not in str(request["json"])


def test_agent_ttl_must_fit_discovered_server_age(spool, monkeypatch):
    config = SimpleNamespace(server_url="https://api.test", api_key="key", ca_bundle="", collector_id="")
    monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {
        "legacy": True, "ingestion_max_age_days": 1,
    }))
    with pytest.raises(agent.AgentDeliveryError, match="ttl_exceeds_server_age"):
        agent.discover_binding(config, spool)
    assert spool.stats()["batches"] == 0


def test_agent_collection_follows_authenticated_source_scopes(spool, monkeypatch):
    from shadai_agent.config import AgentConfig

    config = AgentConfig(server_url="https://api.test", api_key="synthetic")
    monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {
        "legacy": False, "collector_id": "endpoint-sensor", "allowed_source_types": ["endpoint"],
    }))
    assert agent.discover_binding(config, spool)
    assert config.collect_processes and config.collect_containers and config.collect_local_ai
    assert config.collect_extensions is False


def test_previously_scoped_spool_cannot_fall_back_to_legacy_identity(spool, monkeypatch):
    spool.bind("collector", "registered-agent")
    config = SimpleNamespace(server_url="https://api.test", api_key="synthetic", ca_bundle="", collector_id="")
    monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=200,
                                                                            json=lambda: {"legacy": True}))
    with pytest.raises(agent.AgentDeliveryError, match="binding_mismatch"):
        agent.discover_binding(config, spool)


def test_agent_first_start_offline_spools_before_binding_then_replays_original(tmp_path, monkeypatch):
    from shadai_agent.config import AgentConfig

    directory = tmp_path / "first-offline-agent"
    monkeypatch.setattr(vendored, "_private_ancestors", lambda path: None)
    monkeypatch.setattr(delivery_spool, "_private_ancestors", lambda path: None)
    config = AgentConfig(server_url="https://api.test", api_key="synthetic-key", spool_dir=str(directory),
                         poll_interval_seconds=0, collect_containers=False, collect_local_ai=False,
                         collect_extensions=False)
    monkeypatch.setattr(agent, "load_agent_config", lambda: config)
    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent, "_running", True)
    def collect_once():
        agent._running = False
        return [{"name": "ollama", "path": "/never-persist", "username": "synthetic"}]
    monkeypatch.setattr(agent, "collect_processes", collect_once)
    monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=503))
    posted = []
    monkeypatch.setattr(agent.requests, "post", lambda *a, **k: posted.append(k) or
                        SimpleNamespace(status_code=200, json=lambda: {"received": 1}))
    agent.main()
    assert posted == []
    with DurableSpool(directory) as restarted:
        [original] = restarted.claim()
        assert b"never-persist" not in original.payload
        restarted.retry(original, delay=0)
        monkeypatch.setattr(agent.requests, "get", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {
            "legacy": False, "collector_id": "scoped-agent", "allowed_source_types": ["endpoint"],
        }))
        assert agent.discover_binding(config, restarted)
        assert agent.drain_spool(restarted, config) == 1
        assert posted[0]["data"] == original.payload
        assert restarted.stats()["queued_events"] == 0


def test_network_first_offline_cli_preserves_all_metadata_before_auth_resolution(spool, tmp_path, monkeypatch):
    from shadai.collectors import network

    metadata = {"ts": datetime.now(UTC).timestamp(), "uid": "first-offline", "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20", "id.resp_p": 443, "server_name": "api.openai.com"}
    source = tmp_path / "synthetic-tls.jsonl"
    source.write_text(json.dumps(metadata), encoding="utf-8")
    online, posted = [False], []
    def handle(request):
        if request.method == "GET":
            if not online[0]:
                return httpx.Response(503)
            return httpx.Response(200, json={"legacy": False, "collector_id": "sensor",
                                           "allowed_source_types": ["network"], "ingestion_max_age_days": 90})
        posted.append(request.content)
        return httpx.Response(202)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        def factory(*args, **kwargs):
            return EventTransport(*args, **kwargs, client=client)
        monkeypatch.setattr(network, "EventTransport", factory)
        assert network.main(["--format", "zeek-tls", "--input", str(source), "--sensor-id", "sensor",
                             "--api-url", "https://api.test", "--spool-dir", str(spool.directory)]) == 1
        assert posted == [] and spool.stats()["queued_events"] == 1
        spool.clock = lambda: delivery_spool.time.time() + 300
        [original] = spool.claim()
        spool.retry(original, delay=0)
        online[0] = True
        wire = EventTransport("https://api.test", "synthetic", client=client, retries=0,
                              key_loader=lambda: "synthetic")
        wire.discover_binding("sensor")
        DurableEventTransport(wire, spool).drain()
        assert posted == [original.payload] and spool.stats()["queued_events"] == 0


async def test_syslog_tcp_handler_reaps_connection_after_cancellation(spool):
    import asyncio

    collector = SyslogCollector("synthetic", SquidAccessLogParser(), SimpleNamespace(), spool=spool)
    entered = asyncio.Event()
    async def read():
        entered.set()
        await asyncio.Future()
    reader = SimpleNamespace(readline=read)
    writer = SimpleNamespace(get_extra_info=lambda field: None, close=lambda: None, wait_closed=AsyncMock())
    task = asyncio.create_task(collector._handle_tcp_connection(reader, writer))
    await entered.wait()
    assert task in collector.connections
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert not collector.connections
    writer.wait_closed.assert_awaited_once()


def test_network_outage_preserves_every_batch_and_restart_replays_exact_bytes(spool):
    calls, online = [], [False]
    def handle(request):
        calls.append(request.content)
        if not online[0]:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(202)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        wire = EventTransport("https://api.test", "x" * 32, client=client, retries=0)
        transport = DurableEventTransport(wire, spool)
        payloads = [b'{"events":[{"event_id":"one"}]}', b'{"events":[{"event_id":"two"}]}']
        for payload in payloads:
            transport.send(payload)
        assert spool.stats()["queued_events"] == 2
        transport.close()
        online[0] = True
        with DurableSpool(spool.directory, clock=lambda: delivery_spool.time.time() + 300) as restarted:
            replay = DurableEventTransport(wire, restarted)
            replay.drain()
            assert restarted.stats()["delivered_events"] == 2
            assert restarted.stats()["batches"] == 0
    assert calls[:2] == payloads and set(calls[2:]) == set(payloads)


def test_network_rotation_to_different_collector_cannot_deliver_backlog(spool):
    key, requests_seen = ["old"], []
    def handle(request):
        token = request.headers["X-API-Key"]
        if request.method == "GET":
            return httpx.Response(200, json={"legacy": False, "collector_id": "wrong" if token == "wrong" else
                                           "sensor", "allowed_source_types": ["network"]})
        requests_seen.append(request.content)
        return httpx.Response(202)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        wire = EventTransport("https://api.test", key[0], client=client, retries=0, key_loader=lambda: key[0])
        assert wire.discover_binding("sensor")
        durable = DurableEventTransport(wire, spool)
        key[0] = "wrong"
        payload = b'{"events":[{"event_id":"original"}]}'
        with pytest.raises(DeliveryError, match="collector_binding_mismatch"):
            durable.send(payload)
        spool.clock = lambda: delivery_spool.time.time() + 300
        with pytest.raises(DeliveryError, match="collector_binding_mismatch"):
            durable.drain()
        assert requests_seen == [] and spool.stats()["queued_events"] == 1
        key[0] = "rotated-correctly"
        spool.clock = lambda: delivery_spool.time.time() + 600
        durable.drain()
        assert requests_seen == [payload] and spool.stats()["queued_events"] == 0


async def test_syslog_redis_outage_retains_only_prepared_metadata_and_survives_restart(spool):
    pipe = SimpleNamespace(xadd=lambda *args: None, execute=AsyncMock(side_effect=OSError("offline")))
    redis = SimpleNamespace(pipeline=lambda **kwargs: pipe)
    collector = SyslogCollector("test-squid", SquidAccessLogParser(), redis, spool=spool)
    event = CanonicalEvent(tenant_id="test-org", source_type="proxy", domain="api.openai.com",
                           url_path="/private/prompt", user_agent="private-ua", process_path="private-exe")
    assert await collector.push_events([event]) == 1
    assert collector.counters["delivery_failures"] == 1
    spool.clock = lambda: delivery_spool.time.time() + 300
    [batch] = spool.claim()
    queued = json.loads(batch.payload)
    assert b"private" not in batch.payload
    original = queued[0]["fields"]
    assert json.loads(original["data"])["event_id"] == str(event.event_id)
    assert original["accepted_at"]
    spool.retry(batch, delay=0)
    spool.close()
    pipe.execute.side_effect = None
    with DurableSpool(spool.directory, clock=spool.clock) as restarted:
        collector.spool = restarted
        assert await collector.flush_spool() == 1
        assert restarted.stats()["pending"] == 0


def test_udp_task_budget_counts_drop_without_claiming_delivery():
    collector = SimpleNamespace(counters={"udp_task_drops": 0}, _process_line=AsyncMock())
    protocol = SyslogUDPProtocol(collector)
    protocol.tasks = set(range(1000))
    protocol.datagram_received(b"synthetic metadata", ("127.0.0.1", 1234))
    assert collector.counters["udp_task_drops"] == 1
    collector._process_line.assert_not_called()


def test_accepted_backlog_uses_internal_acceptance_but_external_stale_is_rejected():
    from shadai.api.ingestion import prepare_event
    from shadai.config import get_config

    accepted = datetime.now(UTC) - timedelta(days=get_config().retention.ingestion_max_age_days + 3)
    event = CanonicalEvent(tenant_id="test-org", timestamp=accepted - timedelta(days=1))
    queued = queue_fields(event.model_dump_json(), accepted_at=accepted)
    prepared = prepare_queued_event(queued)
    assert prepared.event_id == event.event_id and prepared.timestamp == event.timestamp
    with pytest.raises(ValueError, match="retention"):
        prepare_event(event, trusted_collector=True)
    with pytest.raises(PermanentMessageError):
        prepare_queued_event({**queued, "accepted_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()})
