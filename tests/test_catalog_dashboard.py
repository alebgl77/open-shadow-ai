from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

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
