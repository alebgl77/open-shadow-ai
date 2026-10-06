"""Network metadata boundaries, truthful scoring and typed tenant-scoped reads."""

import json
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import uuid4

import pytest
from clickhouse_driver.util.escape import escape_params
from fastapi.testclient import TestClient
from pydantic import ValidationError
from queue_fakes import admission_fake

from shadai.api import network
from shadai.api.ingestion import SOURCE_TYPES, prepare_event
from shadai.config import get_config
from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.correlator import Correlator, _derive_entity_type
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import NETWORK_PROTOCOLS, CanonicalEvent
from shadai.security.auth import get_current_user
from shadai.workers.ingest import STREAMS, EventProcessor


def observation(protocol="DNS", host="service.example.test", **fields):
    values = {
        "source_type": "network", "protocol": protocol, "collector_id": "sensor-1", "tenant_id": "test-org",
        "domain": host if protocol == "DNS" else "", "sni": host if protocol in ("TLS", "QUIC") else "",
        "url_host": host if protocol == "HTTP" else "",
    }
    return CanonicalEvent(**(values | fields))


def catalog_item(item_id="service", **fields):
    return CatalogItemRead(
        catalog_item_id=item_id, canonical_name=item_id, category="ai_platform", **fields
    )


def service_matcher():
    return CatalogMatcher(build_catalog_index([catalog_item(domains=["service.example.test"])]))


@pytest.mark.parametrize("protocol", NETWORK_PROTOCOLS)
def test_normalized_protocol_hosts_and_addresses_use_existing_columns(protocol):
    event = observation(protocol, "BÜCHER.Example.Test.", src_ip="2001:0DB8::1", dst_ip="192.0.2.2")
    assert event.domain == "xn--bcher-kva.example.test"
    assert event.src_ip == "2001:db8::1" and event.dst_ip == "192.0.2.2"
    assert event.evidence_type == "observation"
    assert event.user_id == event.device_id == event.username == event.hostname == ""
    assert "network" in SOURCE_TYPES and "events:network" in STREAMS
    assert _derive_entity_type("network", "ai_platform") == "api_service"
    assert _derive_entity_type("network", "llm_chat") == "saas_app"
    assert set(event.to_clickhouse_dict()) == set(CanonicalEvent.model_fields) - {"privacy_stamp"}
    event.privacy_stamp = "a" * 64
    assert "privacy_stamp" not in event.to_clickhouse_dict()


@pytest.mark.parametrize("host", [
    "https://service.test", "service.test/path", "service.test?secret=x", "user@service.test", "service.test:443",
    "service.test\n", " bad.test", "bad..test", "bad.test..", "bad_name.test", "-bad.test", "bad-.test",
    "a" * 64 + ".test",
    "a." * 127 + "test", "192.0.2.1", "2001:db8::1", "xn--abc.test", "１９２。０。２。１",
])
def test_network_hostname_rejects_urls_malformed_dns_and_ip_attribution(host):
    with pytest.raises(ValidationError):
        observation(host=host)


def test_idna_dns_root_separator_is_normalized():
    assert observation(host="bücher.example.test。").domain == "xn--bcher-kva.example.test"


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize("value", ["not-an-ip", "999.1.1.1", "192.0.2.1:443", "fe80::1%private-interface"])
def test_network_address_validation(field, value):
    with pytest.raises(ValidationError):
        observation(**{field: value})


@pytest.mark.parametrize("fields", [
    {"evidence_type": "usage"}, {"evidence_type": "inventory"}, {"provider": "claimed-provider"},
    {"model": "claimed-model", "model_provenance": "reported"}, {"model_provenance": "reported"},
    {"measurement_provenance": "instrumented"}, {"input_tokens": 0}, {"output_tokens": 1}, {"cost_usd": 0},
    {"user_id": "192.0.2.1"}, {"username": "alice"}, {"device_id": "device"}, {"hostname": "device"},
    {"identity_provider": "entra"}, {"identity_object_id": "alice"}, {"identity_sid": "sid"},
    {"process_name": "ollama"}, {"local_port": 11434}, {"extension_id": "ai"}, {"oauth_app_id": "app"},
    {"oauth_scopes": ["scope"]}, {"url_path": "/chat?secret=x"}, {"user_agent": "private-client"},
    {"raw_ref": "packet-body"}, {"collector_id": ""}, {"parser_version": "x" * 256},
    {"protocol": "tls"}, {"protocol": "TCP"}, {"packet_body": "secret"},
])
def test_network_observations_reject_identity_content_and_usage_claims(fields):
    with pytest.raises(ValidationError):
        observation(**fields)


@pytest.mark.parametrize(("protocol", "fields"), [
    ("DNS", {"sni": "service.example.test"}), ("DNS", {"url_host": "service.example.test"}),
    ("TLS", {"domain": "other.test"}), ("TLS", {"url_host": "service.example.test"}),
    ("QUIC", {"domain": "other.test"}), ("HTTP", {"sni": "service.example.test"}),
    ("HTTP", {"domain": "other.test"}), ("TLS", {"sni": "", "domain": "service.example.test"}),
    ("HTTP", {"url_host": "", "domain": "service.example.test"}),
])
def test_conflicting_protocol_host_fields_are_rejected(protocol, fields):
    with pytest.raises(ValidationError):
        observation(protocol, **fields)


@pytest.mark.parametrize("protocol", NETWORK_PROTOCOLS)
def test_nameless_and_unknown_observations_never_match_from_addresses(protocol):
    matcher = service_matcher()
    assert matcher.match_event(observation(protocol, "", dst_ip="192.0.2.2", dst_port=443)) is None
    assert matcher.match_event(observation(protocol, "service.example.test.attacker.test")) is None
    assert matcher.match_event(observation(protocol, "unknown.test")) is None


@pytest.mark.parametrize("protocol", NETWORK_PROTOCOLS)
def test_equal_catalog_hosts_remain_unattributed(protocol):
    items = [catalog_item("a", domains=["shared.test"]), catalog_item("z", domains=["shared.test"])]
    for order in (items, list(reversed(items))):
        result = CatalogMatcher(build_catalog_index(order)).resolve_event(observation(protocol, "shared.test"))
        assert result.match is None and result.ambiguous


@pytest.mark.parametrize("protocol", NETWORK_PROTOCOLS)
@pytest.mark.parametrize("parent", [False, True])
def test_confidence_is_service_association_only_without_repeated_packet_boost(protocol, parent):
    event = observation(protocol, "sub.service.example.test" if parent else "service.example.test")
    match = service_matcher().match_event(event)
    expected = (0.50 if parent else 0.60) if protocol == "DNS" else (0.55 if parent else 0.65)
    assert match.match_confidence == expected
    correlator = Correlator(None)
    detection = correlator._create_detection(
        event, catalog_item(), match.matched_field, expected, event.timestamp, event.timestamp, None
    )
    for _ in range(105):
        correlator._update_detection(
            detection, event, match.matched_field, expected, event.timestamp, event.timestamp, None
        )
    assert detection.confidence_score == expected
    assert detection.shadow_ai_status == "suspected"
    assert detection.total_events_count == 106
    assert detection.evidence_bundle["network"]["protocol_counts"][protocol] == 106
    assert not any(f["factor"] == "high_volume" for f in detection.evidence_bundle["confidence_factors"])


@pytest.mark.parametrize("reverse", [False, True])
def test_protocols_are_one_source_strongest_confidence_is_preserved_and_context_is_bounded(reverse):
    protocols = list(NETWORK_PROTOCOLS)
    if reverse:
        protocols.reverse()
    events = [observation(protocol) for protocol in protocols]
    matcher, correlator = service_matcher(), Correlator(None)
    first, rest = events[0], events[1:]
    match = matcher.match_event(first)
    detection = correlator._create_detection(
        first, catalog_item(), match.matched_field, match.match_confidence, first.timestamp, first.timestamp, None
    )
    extra = [observation(protocols[i % 4], src_ip="192.0.2.1", dst_ip="2001:db8::2") for i in range(20)]
    for event in rest + extra:
        match = matcher.match_event(event)
        correlator._update_detection(
            detection, event, match.matched_field, match.match_confidence, event.timestamp, event.timestamp, None
        )
    evidence = detection.evidence_bundle["network"]
    assert detection.source_types == ["network"] and detection.confidence_score == 0.65
    assert detection.impacted_users_count == detection.impacted_devices_count == 0
    assert all(isinstance(value, str) for value in evidence["sample_values"])
    assert evidence["protocol_counts"] == dict.fromkeys(NETWORK_PROTOCOLS, 6)
    assert len(evidence["network_observations"]) == 10
    assert [value["event_id"] for value in evidence["network_observations"]] == [str(e.event_id) for e in extra[-10:]]
    assert set(evidence["network_observations"][0]) == {
        "timestamp", "protocol", "domain", "src_ip", "dst_ip", "dst_port", "collector_id", "event_id"
    }
    assert not any(
        f["factor"] in {"high_volume", "multi_source"} for f in detection.evidence_bundle["confidence_factors"]
    )


def test_existing_source_corroboration_survives_without_network_volume():
    correlator, now = Correlator(None), datetime.now(UTC)
    event = observation()
    detection = correlator._create_detection(event, catalog_item(), "domain", 0.6, now, now, None)
    for _ in range(110):
        correlator._update_detection(detection, event, "domain", 0.6, now, now, None)
    proxy = CanonicalEvent(source_type="proxy", domain=event.domain, timestamp=now)
    correlator._update_detection(detection, proxy, "domain", 0.85, now, now, None)
    assert detection.confidence_score == 0.95
    assert detection.source_types == ["network", "proxy"]


def test_network_evidence_drops_unknown_legacy_context():
    correlator, event = Correlator(None), observation()
    detection = correlator._create_detection(
        event, catalog_item(), "domain", 0.6, event.timestamp, event.timestamp, None
    )
    detection.evidence_bundle["network"]["network_observations"][0]["packet_body"] = "secret"
    correlator._update_detection(detection, event, "domain", 0.6, event.timestamp, event.timestamp, None)
    assert len(detection.evidence_bundle["network"]["network_observations"]) == 1
    assert "secret" not in json.dumps(detection.evidence_bundle)


@pytest.mark.parametrize("fields", [
    lambda: {"tenant_id": "other-org"},
    lambda: {"timestamp": datetime.now(UTC) + timedelta(minutes=10)},
    lambda: {"timestamp": datetime.now(UTC) - timedelta(days=366)},
])
def test_network_common_boundary_enforces_tenant_and_dates(fields):
    with pytest.raises(ValueError):
        prepare_event(observation(**fields()))


def test_naive_network_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        observation(timestamp=datetime.now().replace(tzinfo=None))


def test_network_ingest_api_requires_key_and_enqueues_only_valid_metadata(monkeypatch):
    from shadai.main import app

    pipe = SimpleNamespace(xadd=Mock(), execute=AsyncMock())
    monkeypatch.setattr(
        "shadai.api.ingestion.get_redis",
        AsyncMock(return_value=admission_fake(SimpleNamespace(pipeline=Mock(return_value=pipe)), pipe))
    )
    client = TestClient(app)
    event = observation("TLS", "SERVICE.Example.Test.").model_dump(mode="json")
    event.update(catalog_match_id="forged", match_confidence=1, match_field="domain")
    for headers in ({}, {"X-API-Key": "wrong"}):
        assert client.post("/api/v1/ingest/events", json={"events": [event]}, headers=headers).status_code == 401
    response = client.post(
        "/api/v1/ingest/events", json={"events": [event]},
        headers={"X-API-Key": get_config().security.agent_api_key},
    )
    assert response.status_code == 202 and response.json()["received"] == 1
    stream, payload = pipe.xadd.call_args.args
    assert stream == "events:network"
    record = json.loads(payload["data"])
    assert record["domain"] == record["sni"] == "service.example.test"
    assert record["catalog_match_id"] == "" and record["match_confidence"] == 0
    pipe.execute.assert_awaited_once()
    pipe.xadd.reset_mock()
    event["src_ip"] = "bad-ip"
    assert client.post(
        "/api/v1/ingest/events", json={"events": [event]},
        headers={"X-API-Key": get_config().security.agent_api_key},
    ).status_code == 422
    pipe.xadd.assert_not_called()


@pytest.mark.parametrize("fields", [
    {"protocol": "TCP"}, {"evidence_type": "usage"}, {"model_provenance": "reported"},
    {"sni": "conflicting.test"}, {"tenant_id": "foreign-org"},
    {"timestamp": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
])
def test_invalid_network_batch_is_atomic_and_ingestion_errors_do_not_echo_content(monkeypatch, fields):
    from shadai.main import app

    redis = admission_fake(AsyncMock())
    monkeypatch.setattr("shadai.api.ingestion.get_redis", redis)
    valid = observation().model_dump(mode="json")
    invalid = observation().model_dump(mode="json") | fields
    response = TestClient(app).post(
        "/api/v1/ingest/events", json={"events": [valid, invalid]},
        headers={"X-API-Key": get_config().security.agent_api_key},
    )
    assert response.status_code == 422
    redis.assert_not_awaited()
    assert "conflicting.test" not in response.text


def test_network_batch_keeps_existing_500_event_limit(monkeypatch):
    from shadai.main import app

    redis = admission_fake(AsyncMock())
    monkeypatch.setattr("shadai.api.ingestion.get_redis", redis)
    event = observation().model_dump(mode="json")
    response = TestClient(app).post(
        "/api/v1/ingest/events", json={"events": [event] * 501},
        headers={"X-API-Key": get_config().security.agent_api_key},
    )
    assert response.status_code == 422
    redis.assert_not_awaited()


async def test_network_worker_persists_real_match_before_insert_and_suppresses_replay():
    session = MagicMock()
    session.__aenter__.return_value = session
    session.begin.return_value = session
    session.execute = AsyncMock()
    session.get = AsyncMock(side_effect=[None, True, None])
    rows, redis = [], admission_fake(AsyncMock())
    processor = EventProcessor(
        redis, SimpleNamespace(execute=lambda query, values: rows.extend(values)), lambda: session, service_matcher()
    )
    event = prepare_event(observation("QUIC"))
    await processor({"data": event.model_dump_json()})
    await processor({"data": event.model_dump_json()})
    await processor({"data": prepare_event(observation("QUIC", "")).model_dump_json()})
    assert len(rows) == 2
    assert rows[0]["catalog_match_id"] == "service" and rows[0]["match_confidence"] == 0.65
    assert rows[1]["catalog_match_id"] == ""
    redis.xadd.assert_awaited_once()
    assert session.add.call_count == 2


@pytest.fixture
def network_client(monkeypatch):
    from shadai.main import app

    calls = []
    event_id = uuid4()

    def execute(query, params):
        calls.append((query, params, threading.get_ident()))
        if "GROUP BY collector_id" in query:
            return [("sensor-1", datetime(2026, 1, 1), 3)]
        if "countIf(domain" in query:
            return [(3, 2, 1, 1, 1, 1, 0)]
        if query.startswith("SELECT count()"):
            return [(3,)]
        return [
            (event_id, datetime(2026, 1, 1), "TLS", "service.example.test", "service.example.test", "",
             "192.0.2.1", "192.0.2.2", 443, "sensor-1", "v1", "service"),
            (uuid4(), datetime(2026, 1, 1), "QUIC", "", "", "", "192.0.2.1", "192.0.2.2", 443, "sensor-1", "v1", ""),
        ]

    monkeypatch.setattr(network, "get_clickhouse", lambda: SimpleNamespace(execute=execute))
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role="analyst")
    yield TestClient(app), calls
    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.parametrize("server_timezone", ["UTC", "America/New_York"])
def test_network_window_retains_fractional_utc_bounds_through_driver_escaping(monkeypatch, server_timezone):
    frozen = datetime(2026, 10, 6, 22, 35, 58, 654321, tzinfo=UTC)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return frozen

    monkeypatch.setattr(network, "datetime", FrozenDatetime)
    query, params = network._window(48, "TLS")
    assert params == {
        "tenant": "test-org", "start": "2026-10-04 22:35:58.654321",
        "end": "2026-10-06 22:35:58.654321", "protocol": "TLS",
    }
    context = SimpleNamespace(server_info=SimpleNamespace(get_timezone=lambda: server_timezone))
    escaped = escape_params(params, context)
    assert escaped["start"] == "'2026-10-04 22:35:58.654321'"
    assert escaped["end"] == "'2026-10-06 22:35:58.654321'"
    assert "toDateTime64('2026-10-04 22:35:58.654321', 6, 'UTC')" in query % escaped
    assert "toDateTime64('2026-10-06 22:35:58.654321', 6, 'UTC')" in query % escaped
    assert "tenant_id = %(tenant)s" in query and "protocol = %(protocol)s" in query
    assert "LIMIT 1 BY event_id" in query


def test_network_overview_real_counts_bounded_sensor_summary_and_sql_scope(network_client):
    client, calls = network_client
    response = client.get("/api/v1/network/overview?hours=48")
    assert response.status_code == 200, response.text
    data = response.json()
    assert {key: data[key] for key in (
        "hours", "total_observations", "named_observations", "matched_observations", "unmatched_observations"
    )} == {
        "hours": 48, "total_observations": 3, "named_observations": 2,
        "matched_observations": 1, "unmatched_observations": 2,
    }
    assert data["protocols"] == {"DNS": 1, "TLS": 1, "QUIC": 1, "HTTP": 0}
    assert data["sensors"] == [{"collector_id": "sensor-1", "last_seen": "2026-01-01T00:00:00Z", "observations": 3}]
    assert any("imported" in limitation for limitation in data["limitations"])
    assert "LIMIT 100" in calls[1][0]
    for query, params, _thread in calls:
        assert "tenant_id = %(tenant)s" in query and params["tenant"] == "test-org"
        assert "source_type = 'network'" in query and "LIMIT 1 BY event_id" in query
        assert "timestamp >= toDateTime64(%(start)s, 6, 'UTC')" in query
        assert "timestamp <= toDateTime64(%(end)s, 6, 'UTC')" in query
        assert datetime.fromisoformat(params["end"]) - datetime.fromisoformat(params["start"]) == timedelta(hours=48)
        assert "SELECT *" not in query


def test_network_events_typed_columns_filter_pagination_and_nameless_match_status(network_client):
    client, calls = network_client
    response = client.get("/api/v1/network/events?protocol=TLS&page=2&page_size=5")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 3 and data["page"] == 2 and data["page_size"] == 5
    assert data["items"][0]["matched"] and data["items"][0]["catalog_match_id"] == "service"
    assert not data["items"][1]["matched"] and data["items"][1]["catalog_match_id"] is None
    assert data["items"][1]["domain"] == ""
    assert set(data["items"][0]) == set(network.NetworkEventRead.model_fields)
    assert calls[1][1]["limit"] == 5 and calls[1][1]["offset"] == 5
    for query, params, _thread in calls:
        assert "protocol = %(protocol)s" in query and params["protocol"] == "TLS"
        assert params["tenant"] == "test-org" and "LIMIT 1 BY event_id" in query


@pytest.mark.parametrize("url", [
    "/api/v1/network/overview?hours=0", "/api/v1/network/overview?hours=169", "/api/v1/network/events?hours=0",
    "/api/v1/network/events?hours=169", "/api/v1/network/events?page=0", "/api/v1/network/events?page_size=101",
    "/api/v1/network/events?protocol=tls", "/api/v1/network/events?protocol=TLS%27%20OR%201=1",
])
def test_network_read_parameters_are_bounded_and_protocol_is_an_enum(network_client, url):
    client, calls = network_client
    assert client.get(url).status_code == 422
    assert calls == []


@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
@pytest.mark.parametrize("path", ["overview", "events"])
def test_network_reads_follow_raw_evidence_roles(network_client, role, path):
    from shadai.main import app

    client, calls = network_client
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role=role)
    assert client.get("/api/v1/network/" + path).status_code == (403 if role == "viewer" else 200)
    if role == "viewer":
        assert calls == []


@pytest.mark.parametrize("path", ["overview", "events"])
def test_ingestion_key_alone_cannot_read_network_metadata(path):
    from shadai.main import app

    response = TestClient(app).get(
        "/api/v1/network/" + path, headers={"X-API-Key": get_config().security.agent_api_key}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("path", ["overview", "events"])
def test_clickhouse_failure_returns_real_503_without_secret_or_fake_empty_data(network_client, monkeypatch, path):
    def fail(*args):
        raise RuntimeError("secret-connection-credentials")

    client, _calls = network_client
    monkeypatch.setattr(network, "get_clickhouse", lambda: SimpleNamespace(execute=fail))
    response = client.get("/api/v1/network/" + path)
    assert response.status_code == 503 and "secret" not in response.text
    assert "temporarily unavailable" in response.json()["detail"]


async def test_network_queries_offload_synchronous_client(monkeypatch):
    main_thread = threading.get_ident()
    observed_threads = []

    def execute(*args):
        observed_threads.append(threading.get_ident())
        return [(0,)]

    monkeypatch.setattr(network, "get_clickhouse", lambda: SimpleNamespace(execute=execute))
    assert await network._query("SELECT count()", {}) == [(0,)]
    assert observed_threads[0] != main_thread
