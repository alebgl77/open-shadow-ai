"""Bounded relation coverage and persisted provenance stay inside network read scopes."""

import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shadai.api import network
from shadai.security.auth import get_current_user

ANCHOR = datetime(2026, 10, 15, 12, 34, 56, 654321, tzinfo=UTC)
EVENT_ID = uuid4()


@pytest.fixture
def client(monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return ANCHOR

    monkeypatch.setattr(network, "datetime", FrozenDatetime)
    app = FastAPI()
    app.include_router(network.router)
    user = SimpleNamespace(role="analyst")
    app.dependency_overrides[get_current_user] = lambda: user
    calls, result = [], {"rows": []}

    def execute(sql, params, **kwargs):
        calls.append((sql, params, kwargs, threading.get_ident()))
        if "error" in result:
            raise result["error"]
        if sql.startswith("SELECT count()"):
            return [(len(result["rows"]),)]
        return result["rows"]

    monkeypatch.setattr(network, "get_clickhouse", lambda: SimpleNamespace(execute=execute))
    return TestClient(app), calls, result, user


def relation(source="192.0.2.1", domain="service.example.test", catalog="service", protocol="TLS",
             count=3, first=None, last=None, total_obs=5, total_rel=2):
    return (source, domain, catalog, protocol, count, first or ANCHOR - timedelta(hours=1),
            last or ANCHOR, total_obs, total_rel)


def event(**overrides):
    fields = dict(zip(network.EVENT_COLUMNS, (
        EVENT_ID, ANCHOR, "TLS", "service.example.test", "service.example.test", "",
        "192.0.2.1", "192.0.2.2", 443, "sensor-1", "parser-v1", "service", "sni", 0.65,
    ), strict=True))
    fields.update(overrides)
    return tuple(fields[column] for column in network.EVENT_COLUMNS)


def assert_scope(sql, params):
    assert "tenant_id = %(tenant)s" in sql and params["tenant"] == "test-org"
    assert "source_type = 'network'" in sql and "LIMIT 1 BY event_id" in sql
    assert "ORDER BY normalized_at DESC" in sql
    assert "timestamp >= toDateTime64(%(start)s, 6, 'UTC')" in sql
    assert "timestamp <= toDateTime64(%(end)s, 6, 'UTC')" in sql
    assert datetime.fromisoformat(params["end"]) - datetime.fromisoformat(params["start"]) == timedelta(hours=24)
    assert "SELECT *" not in sql
    for forbidden in ("raw_ref", "process_path", "device_id", "user_id", "prompt", "payload", "model"):
        assert forbidden not in sql


def test_relations_full_totals_precede_limit_and_one_bounded_offloaded_snapshot(client):
    api, calls, result, _ = client
    result["rows"] = [relation(count=7, total_obs=12, total_rel=3)]
    response = api.get("/api/v1/network/relations?protocol=TLS&limit=1")
    assert response.status_code == 200
    data = response.json()
    assert (data["total_observations"], data["total_relations"]) == (12, 3)
    assert (data["represented_observations"], data["represented_relations"], data["truncated"]) == (7, 1, True)
    assert len(calls) == 1
    sql, params, kwargs, thread = calls[0]
    assert_scope(sql, params)
    assert "sum(observations) OVER ()" in sql and "count() OVER ()" in sql
    assert sql.index("sum(observations) OVER ()") < sql.index("LIMIT %(limit)s")
    assert "GROUP BY src_ip, domain, catalog_match_id, protocol" in sql
    assert "observations DESC, last_seen DESC, src_ip ASC, domain ASC, catalog_match_id ASC, protocol ASC" in sql
    assert params["limit"] == 1 and params["protocol"] == "TLS"
    assert kwargs["settings"] == network.RELATION_SETTINGS
    assert kwargs["settings"]["read_overflow_mode"] == kwargs["settings"]["timeout_overflow_mode"] == "throw"
    assert thread != threading.get_ident()
    assert data["items"][0]["last_seen"] == ANCHOR.isoformat().replace("+00:00", "Z")
    assert set(data["items"][0]) == set(network.NetworkRelation.model_fields)


def test_complete_relations_preserve_privacy_blank_nameless_unmatched_and_protocol(client):
    api, _, result, _ = client
    result["rows"] = [relation(), relation("", "", "", "QUIC", count=2)]
    response = api.get("/api/v1/network/relations")
    assert response.status_code == 200
    data = response.json()
    assert data["protocol"] is None and data["represented_observations"] == data["total_observations"] == 5
    assert data["represented_relations"] == data["total_relations"] == 2 and not data["truncated"]
    unknown = data["items"][1]
    assert unknown["source_ip"] == unknown["domain"] == "" and unknown["catalog_match_id"] is None
    assert unknown["protocol"] == "QUIC"
    assert any("privacy erasure" in item for item in data["limitations"])


def test_empty_relation_window_is_truthful_zero(client):
    api, _, _, _ = client
    data = api.get("/api/v1/network/relations").json()
    assert data["items"] == [] and not data["truncated"]
    assert all(data[key] == 0 for key in (
        "total_observations", "total_relations", "represented_observations", "represented_relations",
    ))


@pytest.mark.parametrize("query", ["limit=0", "limit=501", "hours=0", "hours=169", "protocol=TCP"])
def test_relation_parameters_reject_before_queries(client, query):
    api, calls, _, _ = client
    assert api.get("/api/v1/network/relations?" + query).status_code == 422
    assert calls == []


@pytest.mark.parametrize("query", ["source_ip=bad", "source_ip=192.0.2.1%3A443", "source_ip=fe80%3A%3A1%25eth0",
                                 "catalog_match_id=" + "x" * 129])
def test_exact_filter_parameters_reject_before_queries(client, query):
    api, calls, _, _ = client
    assert api.get("/api/v1/network/events?" + query).status_code == 422
    assert calls == []


@pytest.mark.parametrize(("source", "catalog"), [("", ""), ("192.0.2.1", "service"),
                                                 ("2001:0DB8::1", "service' OR 1=1")])
def test_exact_filters_are_parameterized_and_apply_after_uuid_dedup(client, source, catalog):
    api, calls, result, _ = client
    canonical = "2001:db8::1" if source.startswith("2001") else source
    result["rows"] = [event(src_ip=canonical, catalog_match_id=catalog)]
    response = api.get("/api/v1/network/events", params={"source_ip": source, "catalog_match_id": catalog})
    assert response.status_code == 200
    assert response.json()["items"][0]["src_ip"] == canonical
    assert calls[0][1]["start"] == calls[1][1]["start"] and calls[0][1]["end"] == calls[1][1]["end"]
    for sql, params, _, _ in calls:
        assert_scope(sql, params)
        assert params["source_ip"] == canonical and params["catalog_match_id"] == catalog
        assert "src_ip = %(source_ip)s" in sql and "catalog_match_id = %(catalog_match_id)s" in sql
        assert sql.index("LIMIT 1 BY event_id") < sql.index("src_ip = %(source_ip)s")
        assert "OR 1=1" not in sql


def test_event_detail_exposes_only_existing_persisted_metadata(client):
    api, calls, result, _ = client
    result["rows"] = [event()]
    response = api.get(f"/api/v1/network/events/{EVENT_ID}")
    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == str(EVENT_ID) and data["match_field"] == "sni" and data["match_confidence"] == 0.65
    assert data["collector_id"] == "sensor-1" and data["parser_version"] == "parser-v1"
    assert set(data) == set(network.NetworkEventRead.model_fields)
    assert len(calls) == 1
    assert_scope(*calls[0][:2])
    assert "WHERE event_id = %(event_id)s LIMIT 1" in calls[0][0] and calls[0][1]["event_id"] == EVENT_ID
    assert calls[0][2]["settings"] == network.RELATION_SETTINGS


@pytest.mark.parametrize("overrides", [{"match_field": "", "match_confidence": float("nan")},
                                     {"match_confidence": float("inf")},
                                     {"catalog_match_id": "", "match_field": "", "match_confidence": 0}])
def test_unknown_match_metadata_does_not_manufacture_confidence(client, overrides):
    api, _, result, _ = client
    result["rows"] = [event(**overrides)]
    response = api.get(f"/api/v1/network/events/{EVENT_ID}")
    assert response.status_code == 200 and response.json()["match_confidence"] is None


def test_missing_foreign_or_expired_uuid_has_same_404(client):
    api, _, _, _ = client
    response = api.get(f"/api/v1/network/events/{EVENT_ID}")
    assert response.status_code == 404 and response.json()["detail"] == "Network observation not found"


@pytest.mark.parametrize("suffix", ["bad-uuid", str(EVENT_ID) + "?hours=169", str(EVENT_ID) + "?hours=0"])
def test_event_detail_invalid_uuid_and_hours_before_queries(client, suffix):
    api, calls, _, _ = client
    assert api.get("/api/v1/network/events/" + suffix).status_code == 422 and calls == []


@pytest.mark.parametrize("path", ["relations", f"events/{EVENT_ID}"])
def test_new_routes_viewer_refused_without_store_access(client, path):
    api, calls, _, user = client
    user.role = "viewer"
    assert api.get("/api/v1/network/" + path).status_code == 403 and calls == []


@pytest.mark.parametrize("role", ["analyst", "admin"])
def test_new_routes_allow_authorized_roles(client, role):
    api, _, result, user = client
    user.role = role
    assert api.get("/api/v1/network/relations").status_code == 200
    result["rows"] = [event()]
    assert api.get(f"/api/v1/network/events/{EVENT_ID}").status_code == 200


@pytest.mark.parametrize("path", ["relations", f"events/{EVENT_ID}", "events"])
def test_store_refusal_including_resource_limits_is_sanitized_503(client, path):
    api, _, result, _ = client
    result["error"] = RuntimeError("secret-row-and-credentials")
    response = api.get("/api/v1/network/" + path)
    assert response.status_code == 503 and "secret" not in response.text


@pytest.mark.parametrize("error_type", [TimeoutError, OverflowError])
def test_detail_resource_limit_refusal_is_sanitized_and_settings_are_forwarded(client, error_type):
    api, calls, result, _ = client
    result["error"] = error_type("secret-query-and-resource-details")
    response = api.get(f"/api/v1/network/events/{EVENT_ID}?hours=168")
    assert response.status_code == 503 and "secret" not in response.text
    assert response.json()["detail"] == "Network observations are temporarily unavailable"
    assert len(calls) == 1 and calls[0][2]["settings"] == network.RELATION_SETTINGS


@pytest.mark.parametrize("row", [
    relation(count=0), relation(count=1.5), relation(source="secret-bad-ip"), relation(protocol="TCP"),
    relation(first=ANCHOR + timedelta(seconds=1)), relation(first=ANCHOR - timedelta(hours=25)),
    relation(last=ANCHOR - timedelta(hours=2)), relation(first="secret-date"),
    relation(total_obs=2), relation(total_rel=0), relation(total_obs=1, total_rel=2),
    relation(total_obs=4, total_rel=1), relation() + ("secret-extra",),
])
def test_malformed_relation_rows_fail_closed_without_row_leak(client, row):
    api, _, result, _ = client
    result["rows"] = [row]
    response = api.get("/api/v1/network/relations")
    assert response.status_code == 503 and "secret" not in response.text


def test_duplicate_inconsistent_or_wrong_protocol_aggregate_fails_closed(client):
    api, _, result, _ = client
    for rows in ([relation(), relation()], [relation(), relation(source="", total_obs=6)],
                 [relation(protocol="DNS")]):
        result["rows"] = rows
        assert api.get("/api/v1/network/relations?protocol=TLS").status_code == 503


@pytest.mark.parametrize("row", [event(event_id=uuid4()), event(timestamp="secret-date"),
                                event(timestamp=ANCHOR + timedelta(seconds=1)),
                                event(timestamp=ANCHOR - timedelta(hours=25)), event(src_ip="secret-ip"),
                                event(match_confidence=2), event() + ("secret-raw",)])
def test_malformed_or_out_of_scope_detail_fails_closed(client, row):
    api, _, result, _ = client
    result["rows"] = [row]
    response = api.get(f"/api/v1/network/events/{EVENT_ID}")
    assert response.status_code == 503 and "secret" not in response.text


def test_out_of_filter_list_fails_closed(client):
    api, _, result, _ = client
    result["rows"] = [event()]
    for query in ("source_ip=192.0.2.3", "catalog_match_id=other", "protocol=DNS", "domain=other.example.test"):
        assert api.get("/api/v1/network/events?" + query).status_code == 503


@pytest.mark.parametrize("domain", ["", "SERVICE.Example.Test.", "bücher.example.test"])
def test_domain_filter_matches_exact_stored_relation_hostname(client, domain):
    api, calls, result, _ = client
    normalized = network.network_hostname(domain)
    result["rows"] = [event(domain=normalized)]
    response = api.get("/api/v1/network/events", params={"domain": domain, "catalog_match_id": "service"})
    assert response.status_code == 200 and response.json()["items"][0]["domain"] == normalized
    for sql, params, _, _ in calls:
        assert "domain = %(domain)s" in sql and params["domain"] == normalized
        assert sql.index("LIMIT 1 BY event_id") < sql.index("domain = %(domain)s")


@pytest.mark.parametrize("domain", ["https://service.test", "192.0.2.1", "bad.test/path", "bad_name.test", "x" * 254])
def test_bad_domain_filter_rejected_before_store_access(client, domain):
    api, calls, _, _ = client
    assert api.get("/api/v1/network/events", params={"domain": domain}).status_code == 422
    assert calls == []


@pytest.mark.parametrize("rows", [None, "", {}, [event(), event()]])
def test_invalid_detail_store_result_is_503_not_not_found(client, rows):
    api, _, result, _ = client
    result["rows"] = rows
    assert api.get(f"/api/v1/network/events/{EVENT_ID}").status_code == 503


@pytest.mark.parametrize("rows", [None, "", {}])
def test_invalid_relation_store_result_is_503_not_empty_coverage(client, rows):
    api, _, result, _ = client
    result["rows"] = rows
    assert api.get("/api/v1/network/relations").status_code == 503
