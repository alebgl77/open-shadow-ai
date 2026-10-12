"""Inventory sources: repeated polls are not usage evidence, but they do name the entity."""

from datetime import UTC, datetime

from sqlalchemy import inspect

from shadai.engine.correlator import Correlator
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent

EXTENSION = CatalogItemRead(catalog_item_id="sider", canonical_name="Sider", category="browser_extension_ai")


def _detection(event: CanonicalEvent, item: CatalogItemRead, field: str, confidence: float):
    now = datetime.now(UTC)
    detection = Correlator(None)._create_detection(event, item, field, confidence, now, now, None)
    for name in inspect(detection).unloaded:
        setattr(detection, name, None)
    return detection


def _factors(detection) -> set[str]:
    return {factor["factor"] for factor in detection.evidence_bundle["confidence_factors"]}


def test_repeated_browser_inventory_polls_do_not_add_volume_confidence():
    now = datetime.now(UTC)
    event = CanonicalEvent(source_type="browser", evidence_type="inventory", extension_id="abc", timestamp=now)
    detection = _detection(event, EXTENSION, "extension_id", 0.95)
    for _ in range(150):
        Correlator(None)._update_detection(detection, event, "extension_id", 0.95, now, now, None)
    assert detection.total_events_count == 151
    assert detection.confidence_score == 0.95
    assert "high_volume" not in _factors(detection)


def test_endpoint_observations_still_earn_the_volume_bonus():
    now = datetime.now(UTC)
    item = CatalogItemRead(catalog_item_id="ollama", canonical_name="Ollama", category="local_runtime")
    event = CanonicalEvent(source_type="endpoint", process_name="ollama", timestamp=now)
    detection = _detection(event, item, "process_name", 0.90)
    for _ in range(150):
        Correlator(None)._update_detection(detection, event, "process_name", 0.90, now, now, None)
    assert detection.confidence_score == 0.95
    assert "high_volume" in _factors(detection)


def test_inventory_refreshes_the_entity_type_of_a_detection_first_seen_on_the_network():
    now = datetime.now(UTC)
    dns = CanonicalEvent(source_type="dns", domain="sider.ai", timestamp=now)
    detection = _detection(dns, EXTENSION, "domain", 0.60)
    assert detection.entity_type == "saas_app"
    browser = CanonicalEvent(source_type="browser", evidence_type="inventory", extension_id="abc", timestamp=now)
    Correlator(None)._update_detection(detection, browser, "extension_id", 0.95, now, now, None)
    assert detection.entity_type == "browser_extension"
    assert detection.source_types == ["dns", "browser"]


def test_network_sightings_never_downgrade_a_named_entity_type():
    now = datetime.now(UTC)
    browser = CanonicalEvent(source_type="browser", evidence_type="inventory", extension_id="abc", timestamp=now)
    detection = _detection(browser, EXTENSION, "extension_id", 0.95)
    dns = CanonicalEvent(source_type="dns", domain="sider.ai", timestamp=now)
    Correlator(None)._update_detection(detection, dns, "domain", 0.60, now, now, None)
    assert detection.entity_type == "browser_extension"
