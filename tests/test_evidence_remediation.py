"""Audit regressions for ambiguous evidence, confidence updates and Squid identity."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from queue_fakes import admission_fake

from shadai.api.ingestion import prepare_event
from shadai.collectors.syslog_receiver import SyslogCollector
from shadai.engine.catalog_loader import build_catalog_index, load_catalog_from_yaml
from shadai.engine.correlator import Correlator
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.parsers.proxy.squid import SquidAccessLogParser
from shadai.workers.ingest import EventProcessor


def item(item_id, **signatures):
    return CatalogItemRead(catalog_item_id=item_id, canonical_name=item_id, category="ai_platform", **signatures)


@pytest.mark.parametrize(
    ("signature", "event_fields"),
    [
        ({"domains": ["shared.test"]}, {"domain": "shared.test"}),
        ({"processes": ["shared"]}, {"process_name": "shared.exe"}),
        ({"local_ports": [11434]}, {"local_port": 11434}),
        ({"extension_ids": ["shared-id"]}, {"extension_id": "shared-id"}),
        ({"oauth_app_ids": ["shared-id"]}, {"oauth_app_id": "shared-id"}),
        ({"container_patterns": ["shared/*"]}, {"container_image": "shared/latest"}),
        (
            {"url_patterns": ["shared.test/v1/*"]},
            {"url_host": "shared.test", "url_path": "/v1/chat?secret=value"},
        ),
        ({"user_agent_patterns": ["shared/*"]}, {"user_agent": "shared/1.0"}),
    ],
)
def test_equal_evidence_is_unattributed_in_both_catalog_orders(signature, event_fields):
    items = [item("a-product", **signature), item("z-product", **signature)]
    event = CanonicalEvent(source_type="proxy", **event_fields)
    for ordered in (items, list(reversed(items))):
        matcher = CatalogMatcher(build_catalog_index(ordered))
        assert matcher.match_event(event) is None
        assert matcher.resolve_event(event).ambiguous is True


@pytest.mark.parametrize(
    ("first", "second", "event_fields", "expected_field"),
    [
        ({"processes": ["product"]}, {"processes": ["other"]}, {"process_name": "product.exe"}, "process_name"),
        (
            {"url_patterns": ["/v1/chat/*"]},
            {"url_patterns": ["/v1/*"]},
            {"url_path": "/v1/chat/private?secret=value"},
            "url_pattern",
        ),
        (
            {"user_agent_patterns": ["vendor-product/*"]},
            {"user_agent_patterns": ["vendor-*"]},
            {"user_agent": "vendor-product/private-client"},
            "user_agent",
        ),
        (
            {"url_patterns": ["/v1/*"], "user_agent_patterns": ["vendor/*"]},
            {"user_agent_patterns": ["vendor/*"]},
            {"url_path": "/v1/chat", "user_agent": "vendor/private-client"},
            "url_pattern",
        ),
    ],
)
def test_discriminating_evidence_resolves_shared_domains(first, second, event_fields, expected_field):
    items = [
        item("z-product", domains=["shared.test"], **first),
        item("a-product", domains=["shared.test"], **second),
    ]
    event = CanonicalEvent(source_type="proxy", url_host="shared.test", **event_fields)
    for ordered in (items, list(reversed(items))):
        match = CatalogMatcher(build_catalog_index(ordered)).match_event(event)
        assert match.catalog_item_id == "z-product"
        assert match.matched_field == expected_field
        assert "private" not in match.matched_value and "secret" not in match.matched_value


@pytest.mark.parametrize("transient", ["url_path", "user_agent"])
@pytest.mark.parametrize("catalog_changed", [False, True])
async def test_transient_ambiguity_survives_worker_without_weaker_attribution(transient, catalog_changed):
    signature = (
        {"url_patterns": ["shared.test/chat/*"]}
        if transient == "url_path"
        else {"user_agent_patterns": ["private-client/*"]}
    )
    fallback = item("domain-only", domains=["shared.test"])
    items = [item("a-product", **signature), item("z-product", **signature), fallback]
    matcher = CatalogMatcher(build_catalog_index(items))
    event = CanonicalEvent(
        tenant_id="test-org",
        source_type="proxy",
        url_host="shared.test",
        **{
            transient: "/chat/private-conversation?secret=value" if transient == "url_path" else "private-client/secret"
        },
    )
    prepared = prepare_event(event, matcher=matcher)
    assert prepared.catalog_match_id == "" and prepared.match_confidence == 0
    assert prepared.match_field == "ambiguous"
    assert prepared.url_path == prepared.user_agent == ""
    assert "secret" not in prepared.model_dump_json() and "private" not in prepared.model_dump_json()
    # With the discarded evidence removed, a fresh match would wrongly choose the domain owner.
    assert matcher.match_event(prepared).catalog_item_id == "domain-only"

    session = MagicMock()
    session.__aenter__.return_value = session
    session.begin.return_value = session
    session.execute = AsyncMock()
    session.get = AsyncMock(return_value=None)
    redis = admission_fake(AsyncMock())
    rows = []
    clickhouse = SimpleNamespace(execute=lambda query, values: rows.extend(values))
    worker_matcher = CatalogMatcher(build_catalog_index([fallback])) if catalog_changed else matcher
    processor = EventProcessor(redis, clickhouse, lambda: session, worker_matcher)
    await processor({"data": prepared.model_dump_json()})
    assert len(rows) == 1
    assert rows[0]["catalog_match_id"] == "" and rows[0]["match_confidence"] == 0
    assert rows[0]["match_field"] == "ambiguous"
    redis.xadd.assert_not_awaited()
    session.add.assert_called_once()


@pytest.mark.parametrize("transient", ["", "/unmatched"])
def test_untrusted_ambiguity_marker_cannot_suppress_matching(transient):
    matcher = CatalogMatcher(build_catalog_index([item("product", domains=["known.test"])]))
    event = CanonicalEvent(
        tenant_id="test-org",
        source_type="proxy",
        domain="known.test",
        url_path=transient,
        catalog_match_id="forged-product",
        match_field="ambiguous",
        match_confidence=1,
    )
    prepared = prepare_event(event, matcher=matcher)
    assert prepared.match_field != "ambiguous"
    assert matcher.match_event(prepared).catalog_item_id == "product"


def test_absent_evidence_is_distinct_from_ambiguity():
    resolution = CatalogMatcher(build_catalog_index([item("product", domains=["known.test"])])).resolve_event(
        CanonicalEvent(source_type="proxy", domain="unknown.test")
    )
    assert resolution.match is None and resolution.ambiguous is False


@pytest.mark.parametrize("reverse", [False, True])
def test_ollama_strongest_same_source_evidence_wins_in_either_arrival_order(reverse):
    items = load_catalog_from_yaml("catalog/builtin", "catalog/no-local-overrides")
    index = build_catalog_index(items)
    matcher = CatalogMatcher(index)
    correlator = Correlator(None)
    now = datetime.now(UTC)
    weak = CanonicalEvent(source_type="endpoint", local_port=11434, timestamp=now)
    strong = CanonicalEvent(
        source_type="endpoint", process_name="ollama", local_port=11434, timestamp=now - timedelta(hours=1)
    )
    assert matcher.match_event(weak).match_confidence == 0.50
    assert matcher.match_event(strong).match_confidence == 0.95
    observations = [weak, strong] if not reverse else [strong, weak]
    initial = observations.pop(0)
    match = matcher.match_event(initial)
    detection = correlator._create_detection(
        initial,
        index.items[match.catalog_item_id],
        match.matched_field,
        match.match_confidence,
        initial.timestamp,
        now,
        None,
    )
    for event in observations + [weak, strong, strong]:
        match = matcher.match_event(event)
        correlator._update_detection(
            detection, event, match.matched_field, match.match_confidence, event.timestamp, now, None
        )
        assert detection.confidence_score == 0.95
    evidence = detection.evidence_bundle["endpoint"]
    assert evidence["confidence_base"] == 0.95
    assert evidence["matched_field"] == "process_name"
    assert "process_name" in detection.reasoning_summary
    assert detection.shadow_ai_status == "high_confidence"
    assert detection.first_seen_at == strong.timestamp and detection.last_seen_at == weak.timestamp


def test_confidence_keeps_existing_corroboration_and_volume_formula():
    correlator = Correlator(None)
    now = datetime.now(UTC)
    event = CanonicalEvent(source_type="dns", domain="shared.test", timestamp=now)
    detection = correlator._create_detection(event, item("product"), "domain", 0.60, now, now, None)
    for _ in range(99):
        correlator._update_detection(detection, event, "domain", 0.60, now, now, None)
    assert detection.confidence_score == 0.60
    correlator._update_detection(detection, event, "domain", 0.60, now, now, None)
    assert detection.confidence_score == 0.65
    corroborating = CanonicalEvent(source_type="proxy", domain="shared.test", timestamp=now)
    correlator._update_detection(detection, corroborating, "domain", 0.85, now, now, None)
    assert detection.evidence_bundle["dns"]["confidence_base"] == 0.60
    assert detection.evidence_bundle["proxy"]["confidence_base"] == 0.85
    assert detection.confidence_score == 1.0


def test_legacy_source_missing_confidence_gets_current_evidence():
    correlator = Correlator(None)
    now = datetime.now(UTC)
    event = CanonicalEvent(source_type="endpoint", process_name="ollama", timestamp=now)
    detection = correlator._create_detection(event, item("product"), "local_port", 0.5, now, now, None)
    del detection.evidence_bundle["endpoint"]["confidence_base"]
    correlator._update_detection(detection, event, "process_name", 0.9, now, now, None)
    assert detection.evidence_bundle["endpoint"]["confidence_base"] == 0.9
    assert detection.evidence_bundle["endpoint"]["matched_field"] == "process_name"


def squid_line(username="alice"):
    return (
        f"{datetime.now(UTC).timestamp():.3f} 234 192.0.2.10 TCP_MISS/200 12345 "
        f"GET https://chat.example.test/conversation {username} DIRECT/192.0.2.11 application/json"
    )


@pytest.mark.parametrize(("username", "expected"), [("alice", "alice"), ("-", "")])
async def test_native_squid_username_survives_ingestion_without_inference(username, expected):
    parser = SquidAccessLogParser()
    event = parser.parse(squid_line(username))
    assert event.username == expected and event.user_id == ""
    redis = MagicMock()
    redis.pipeline.return_value.execute = AsyncMock()
    admission_fake(redis, redis.pipeline.return_value)
    collector = SyslogCollector("squid", parser, redis)
    assert await collector.push_events([event]) == 1
    payload = json.loads(redis.pipeline.return_value.xadd.call_args.args[1]["data"])
    assert payload["username"] == expected and payload["user_id"] == ""
    assert payload["url_path"] == ""


def test_native_squid_connect_preserves_supplied_identity_and_unknown_content_type():
    line = (
        squid_line("EXAMPLE/alice")
        .replace("GET https://chat.example.test/conversation", "CONNECT chat.example.test:443")
        .replace("application/json", "-")
    )
    event = SquidAccessLogParser().parse(line)
    assert event.username == "EXAMPLE/alice"
    assert event.domain == "chat.example.test" and event.dst_port == 443


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a squid record",
        "# ignored",
        "1711545825.123 234 192.0.2.10",
        "1711545825.123 234 192.0.2.10 TCP_MISS/200 12345 GET https://example.test/ DIRECT/192.0.2.11 text/html",
    ],
)
def test_malformed_squid_line_produces_no_identity(line):
    assert SquidAccessLogParser().parse(line) is None
