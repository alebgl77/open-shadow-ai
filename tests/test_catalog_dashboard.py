from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from shadai.config import CatalogSettings
from shadai.engine.catalog_loader import build_catalog_index, load_catalog_from_yaml, sync_catalog
from shadai.engine.correlator import Correlator
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent


@pytest.fixture
def item():
    return CatalogItemRead(
        catalog_item_id="test",
        canonical_name="AI",
        category="ai_platform",
        domains=["openai.com"],
        local_ports=[8080, 11434],
        processes=["ollama"],
    )


@pytest.mark.parametrize("domain", ["evilopenai.com", "openai.com.evil.test", "notopenai.com"])
def test_domain_false_positives(item, domain):
    assert CatalogMatcher(build_catalog_index([item])).match_event(CanonicalEvent(domain=domain)) is None


def test_specificity_generic_ports_disabled_and_directory(item):
    matcher = CatalogMatcher(build_catalog_index([item]))
    assert matcher.match_event(CanonicalEvent(source_type="endpoint", local_port=8080)) is None
    assert (
        matcher.match_event(CanonicalEvent(source_type="directory", evidence_type="inventory", domain="openai.com"))
        is None
    )
    match = matcher.match_event(CanonicalEvent(source_type="endpoint", process_name="ollama.exe", local_port=11434))
    assert match.match_confidence == 0.95
    item.status = "disabled"
    assert CatalogMatcher(build_catalog_index([item])).match_event(CanonicalEvent(domain="openai.com")) is None


def test_real_yaml_catalog_loads():
    items = load_catalog_from_yaml("catalog/builtin", "catalog/local")
    assert len(items) == len(list(Path("catalog/builtin").glob("*.yaml")))
    assert len({item.catalog_item_id for item in items}) == len(items)


async def test_sync_only_overwrites_managed_nonoverride_rows():
    session = AsyncMock()
    count = await sync_catalog(session, CatalogSettings(builtin_path="catalog/builtin", local_path="catalog/local"))
    assert count > 0
    statement = str(session.execute.call_args_list[0].args[0])
    assert "ON CONFLICT" in statement and "catalog.local_override IS false" in statement
    assert "catalog.source_of_truth" in statement


def test_out_of_order_observations_keep_extent_and_stable_identity(item):
    correlator = Correlator(None)
    now = datetime.now(UTC)
    event = CanonicalEvent(
        source_type="endpoint",
        user_id="user-guid",
        username="old-name",
        device_id="device-guid",
        hostname="old-host",
        timestamp=now,
    )
    detection = correlator._create_detection(event, item, "process_name", 0.9, now, now, None)
    earlier = now - timedelta(days=1)
    event.timestamp = earlier
    event.username, event.hostname = "renamed", "new-host"
    correlator._update_detection(detection, event, "process_name", 0.9, earlier, now, None)
    assert detection.last_seen_at == now and detection.first_seen_at == earlier
    assert detection.impacted_users_count == detection.impacted_devices_count == 1
    assert detection.evidence_bundle["_evidence_counts"] == {"observation": 2}


async def test_source_health_reports_inactive_sources(monkeypatch):
    from shadai.api.dashboard import get_source_health

    monkeypatch.setattr("shadai.api.dashboard.get_clickhouse", lambda: SimpleNamespace(execute=lambda *args: []))
    result = await get_source_health(None)
    assert {row["source_type"] for row in result} >= {"directory", "dns", "oauth", "instrumented"}
    assert all(row["status"] == "inactive" and row["last_event"] is None and row["events_1h"] == 0 for row in result)


async def test_confidence_filter_and_page_one():
    from shadai.api.detections import list_detections

    session = AsyncMock()
    session.scalar.return_value = 0
    session.execute.return_value = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    result = await list_detections(confidence_level="high", page=1, page_size=1, _user=None, session=session)
    assert result.page_size == 1
    sql = str(session.scalar.call_args.args[0])
    assert "confidence_score >=" in sql and "confidence_score <" in sql


async def test_readiness_fails_without_dependencies(monkeypatch):
    from shadai.main import readiness

    def fail():
        raise RuntimeError()

    monkeypatch.setattr("shadai.database.get_clickhouse", fail)
    result = await readiness()
    assert result.status_code == 503


def test_shared_signatures_resolve_independently_of_catalog_order():
    api = CatalogItemRead(
        catalog_item_id="b-api",
        canonical_name="Vendor API",
        category="api_platform",
        domains=["shared.example", "api.shared.example"],
        url_patterns=["/v1/*"],
        user_agent_patterns=["vendor-sdk/*"],
    )
    chat = CatalogItemRead(
        catalog_item_id="a-chat",
        canonical_name="Vendor Chat",
        category="chat_assistant",
        domains=["shared.example", "chat.shared.example"],
        url_patterns=["/v1/chat/completions"],
        user_agent_patterns=["vendor-sdk/*"],
    )
    forward, reverse = (CatalogMatcher(build_catalog_index(items)) for items in ([api, chat], [chat, api]))
    cases = [
        (CanonicalEvent(domain="shared.example"), "a-chat"),
        (CanonicalEvent(source_type="proxy", domain="eu.shared.example"), "a-chat"),
        (CanonicalEvent(source_type="proxy", url_host="shared.example", url_path="/v1/chat/completions"), "a-chat"),
        (CanonicalEvent(source_type="proxy", url_host="api.shared.example", url_path="/v1/models"), "b-api"),
        # Equal confidence: the item corroborated by more signal types wins over the lower ID.
        (
            CanonicalEvent(
                source_type="proxy", url_host="shared.example", user_agent="vendor-sdk/1.0", url_path="/v1/models"
            ),
            "b-api",
        ),
        (CanonicalEvent(source_type="proxy", domain="api.shared.example"), "b-api"),
        # A generic path or SDK name on another host is not evidence for these entries.
        (CanonicalEvent(source_type="proxy", url_host="llm.unrelated.example", url_path="/v1/chat/completions"), None),
        (CanonicalEvent(source_type="proxy", url_host="llm.unrelated.example", user_agent="vendor-sdk/1.0"), None),
        (CanonicalEvent(source_type="proxy", url_path="/v1/chat/completions"), None),
    ]
    for event, expected in cases:
        assert forward.match_event(event) == reverse.match_event(event)
        match = forward.match_event(event)
        assert (match.catalog_item_id if match else None) == expected


def test_real_catalog_attribution_is_stable_under_reordering():
    import random

    items = load_catalog_from_yaml(str(Path("catalog/builtin")), str(Path("catalog/local")))
    events = [CanonicalEvent(source_type="dns", domain=d) for item in items for d in item.domains]
    events += [CanonicalEvent(source_type="proxy", domain=d) for item in items for d in item.domains]
    events += [CanonicalEvent(source_type="endpoint", process_name=p) for item in items for p in item.processes]
    events += [
        CanonicalEvent(source_type="proxy", url_path=p)
        for item in items
        for p in item.url_patterns
        if not any(c in p for c in "*?[")
    ]
    events += [
        CanonicalEvent(source_type="proxy", user_agent=p.replace("*", "1.0"))
        for item in items
        for p in item.user_agent_patterns
    ]
    baseline = CatalogMatcher(build_catalog_index(items))
    expected = [baseline.match_event(event) for event in events]
    rng = random.Random(7)
    for _ in range(5):
        shuffled = items[:]
        rng.shuffle(shuffled)
        matcher = CatalogMatcher(build_catalog_index(shuffled))
        assert [matcher.match_event(event) for event in events] == expected


async def test_user_count_sort_is_accepted_and_stable():
    from shadai.api.detections import SORT_COLUMNS, list_detections

    session = AsyncMock()
    session.scalar.return_value = 0
    session.execute.return_value = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    await list_detections(
        sort_by="impacted_users_count", sort_order="desc", page=1, page_size=100, _user=None, session=session
    )
    sql = str(session.execute.call_args.args[0])
    assert "ORDER BY detections.impacted_users_count DESC, detections.detection_id" in sql
    frontend = Path("frontend/src/api/detections.ts")
    if frontend.exists():
        declared = frontend.read_text().split("DETECTION_SORT_COLUMNS = [", 1)[1].split("]", 1)[0]
        assert tuple(column.strip().strip("'") for column in declared.split(",")) == SORT_COLUMNS


async def test_export_applies_every_discovery_filter():
    from shadai.api.exports import export_detections

    session = AsyncMock()
    session.add = lambda entry: setattr(session, "audit", entry)
    session.execute.return_value = SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    user = SimpleNamespace(user_id=None, username="analyst")
    request = SimpleNamespace(client=None)
    exported = await export_detections(
        format="json",
        classification="unsanctioned",
        risk_level="high,critical",
        confidence_level="very_high",
        entity_type="saas_app",
        analyst_status="new",
        search="chat",
        sort_by="risk_score",
        sort_order="desc",
        request=request,
        current_user=user,
        session=session,
    )
    sql = str(session.execute.call_args.args[0])
    for fragment in (
        "detections.classification IN",
        "detections.risk_score BETWEEN",
        "detections.confidence_score >=",
        "detections.entity_type IN",
        "detections.analyst_status IN",
        "lower(detections.entity_name) LIKE lower",
    ):
        assert fragment in sql
    assert session.audit.details["filters"]["risk_level"] == "high,critical"
    assert exported.headers["cache-control"] == "no-store" and "attachment" in exported.headers["content-disposition"]
    with pytest.raises(HTTPException):
        await export_detections(
            format="csv", risk_level="severe", request=request, current_user=user, session=AsyncMock()
        )


def test_builtin_exact_signatures_have_a_single_owner():
    """Evidence cannot choose between two items claiming the same exact identifier."""
    from collections import defaultdict

    from shadai.engine.catalog_loader import url_pattern_scope

    owners = defaultdict(set)
    for item in load_catalog_from_yaml("catalog/builtin", "catalog/no-local-overrides"):
        for field in ("domains", "processes", "extension_ids", "oauth_app_ids", "local_ports", "container_patterns"):
            for value in getattr(item, field):
                key = str(value).lower().removesuffix(".exe").rstrip(".")
                owners[field, key].add(item.catalog_item_id)
        domains = tuple(sorted({domain.lower().rstrip(".") for domain in item.domains}))
        for pattern in item.url_patterns:
            glob, hosts = url_pattern_scope(pattern, domains)
            for host in hosts:
                owners["url_patterns", host, glob.lower()].add(item.catalog_item_id)
        for pattern in item.user_agent_patterns:
            for host in domains or ("any host",):
                owners["user_agent_patterns", host, pattern.lower()].add(item.catalog_item_id)
    assert {key: sorted(ids) for key, ids in owners.items() if len(ids) > 1} == {}
    matcher = CatalogMatcher(
        build_catalog_index(load_catalog_from_yaml("catalog/builtin", "catalog/no-local-overrides"))
    )
    for domain, expected in {
        "api.cohere.com": "cohere-api",
        "generativelanguage.googleapis.com": "google-ai-api",
        "huggingface.co": "huggingface",
        "api.together.xyz": "together-api",
        "gemini.google.com": "gemini",
    }.items():
        assert matcher.match_event(CanonicalEvent(source_type="proxy", domain=domain)).catalog_item_id == expected


def test_paths_and_user_agents_identify_products_only_on_their_hosts():
    matcher = CatalogMatcher(
        build_catalog_index(load_catalog_from_yaml("catalog/builtin", "catalog/no-local-overrides"))
    )

    def match(**fields):
        result = matcher.match_event(CanonicalEvent(source_type="proxy", **fields))
        return result and (result.catalog_item_id, result.matched_field, result.matched_value)

    # HuggingChat shares huggingface.co with the hub; only its path tells them apart.
    assert match(url_host="huggingface.co", url_path="/chat/conversation/a1b2?key=secret") == (
        "huggingchat",
        "url_pattern",
        "huggingface.co/chat/*",
    )
    assert match(url_host="huggingface.co", url_path="/chat")[0] == "huggingchat"
    assert match(url_host="huggingface.co", url_path="/models?next=/chat")[0] == "huggingface"
    assert match(url_host="example.org", url_path="/chat/support") is None
    # An OpenAI-compatible path on a private gateway is not an OpenAI or Together call.
    assert match(url_host="llm.corp.example", url_path="/v1/chat/completions") is None
    assert match(url_host="api.together.xyz", url_path="/v1/chat/completions")[0] == "together-api"
    # SDK user agents corroborate their vendor's hosts; a client-identified tool needs none.
    assert match(url_host="api.groq.com", user_agent="openai-python/1.40")[0] == "groq"
    assert match(url_host="gateway.corp.example", user_agent="claude-code/1.0.3") == (
        "claude-code",
        "user_agent",
        "claude-code/*",
    )
