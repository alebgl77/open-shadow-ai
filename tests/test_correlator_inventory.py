"""Inventory sources: repeated polls are not usage evidence, but they do name the entity."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect
from test_evidence_privacy import evidence_sessions as evidence_sessions
from test_evidence_privacy import installation, version_change
from test_extension_inventory import SIDER, Ingest, inventory_event

from shadai.api import detections
from shadai.database import get_postgres_session
from shadai.engine.correlator import Correlator
from shadai.models.catalog import CatalogItemRead
from shadai.models.detection import DetectionORM
from shadai.models.event import CanonicalEvent
from shadai.security.auth import get_current_user
from shadai.utils.privacy import membership_basis, sanitize_evidence

EXTENSION = CatalogItemRead(catalog_item_id="sider", canonical_name="Sider", category="browser_extension_ai")


def _json_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


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
    for index in range(150):
        # Version churn is review context: every poll reports a change, none adds confidence.
        inventory = {
            "version_changes": [{"from_version": f"1.{index}", "to_version": f"1.{index + 1}", "observed_at": now}],
            "versions": {f"1.{index + 1}": 150},
        }
        Correlator(None)._update_detection(detection, event, "extension_id", 0.95, now, now, None, inventory=inventory)
    assert detection.total_events_count == 151
    assert detection.confidence_score == 0.95
    assert "high_volume" not in _factors(detection)
    assert detection.evidence_bundle["browser"]["versions"] == {"1.150": 150}
    assert detection.evidence_bundle["browser"]["version_changes"] == [
        {"from_version": "1.149", "to_version": "1.150", "observed_at": _json_time(now)}
    ]
    # The read path recomputes the factors from the bundle: polls are not volume there either.
    read = sanitize_evidence(detection.evidence_bundle)
    assert "high_volume" not in {factor["factor"] for factor in read["confidence_factors"]}


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


async def test_browser_section_carries_identity_free_version_evidence_and_no_confidence(
    evidence_sessions, monkeypatch
):
    now = datetime.now(UTC).replace(microsecond=0)
    ingest, correlator = Ingest(evidence_sessions), Correlator(evidence_sessions)
    first = inventory_event(extension_version="1.0", timestamp=now - timedelta(hours=2))
    update = inventory_event(extension_version="1.1", timestamp=now - timedelta(hours=1))
    other = inventory_event(
        hostname="host-b", device_id="host-b", username="bob", browser_profile="Profile 1", timestamp=update.timestamp
    )
    for event in (first, update, other):
        # The ingest worker records the installation before the correlator sees the queued match.
        await ingest.deliver(event)
        identifier = await correlator.upsert_detection(event, SIDER, "extension_id", 0.95)
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
    browser = detection.evidence_bundle["browser"]
    assert browser["version_changes"] == [
        {"from_version": "1.0", "to_version": "1.1", "observed_at": _json_time(update.timestamp)}
    ]
    assert browser["versions"] == {"1.0": 1, "1.1": 1}
    assert browser["event_count"] == detection.total_events_count == 3
    assert detection.confidence_score == 0.95 and _factors(detection) == {"base_signal"}
    bundle = json.dumps(detection.evidence_bundle)
    assert not [value for value in ("host-a", "host-b", "alice", "bob", "Default", "Profile 1") if value in bundle]

    async def no_inventory(*args, **kwargs):
        raise AssertionError("Only browser events read the inventory")

    monkeypatch.setattr("shadai.engine.correlator._inventory_context", no_inventory)
    dns = CanonicalEvent(tenant_id="test-org", source_type="dns", domain="sider.ai", timestamp=now)
    await correlator.upsert_detection(dns, SIDER, "domain", 0.6)
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
    assert detection.evidence_bundle["browser"]["version_changes"] == browser["version_changes"]
    assert "versions" not in detection.evidence_bundle["dns"]


async def seed_version_history(sessions, now):
    """Visible and invisible installations of the Sider catalog item, with a version history."""
    current = {"now": now, "identity_basis": membership_basis()}
    rows = {
        "a": installation(key="a" * 64, device_digest="1" * 64, version="1.1.11", **current),
        "b": installation(key="b" * 64, device_digest="2" * 64, version="1.2.0", **current),
        "c": installation(key="c" * 64, device_digest="2" * 64, profile="Default", version=None, **current),
        "expired": installation(
            key="d" * 64, device_digest="3" * 64, version="2-expired", **{**current, "now": now - timedelta(days=31)}
        ),
        "stale": installation(
            key="e" * 64, device_digest="4" * 64, version="2-stale", **{**current, "identity_basis": "s" * 64}
        ),
        "other": installation(
            key="f" * 64, device_digest="5" * 64, version="2-other", catalog_item_id="other", **current
        ),
    }
    history = [
        version_change(
            rows["a"], from_version=f"1.1.{index}", to_version=f"1.1.{index + 1}",
            observed_at=now - timedelta(hours=12 - index),
        )
        for index in range(11)
    ]
    history.append(
        version_change(rows["b"], from_version=None, to_version="1.2.0", observed_at=now - timedelta(minutes=30))
    )
    async with sessions.begin() as session:
        session.add_all(rows.values())
        await session.flush()
        session.add_all(
            [
                *history,
                # Older than the identity window, from a previous key, and of another catalog item.
                version_change(
                    rows["a"], from_version="1-expired", to_version="1.1.0", observed_at=now - timedelta(days=31)
                ),
                version_change(rows["stale"], from_version="1-stale", to_version="2-stale", observed_at=now),
                version_change(rows["other"], from_version="1-other", to_version="2-other", observed_at=now),
            ]
        )
    # The newest ten changes the detection may show, oldest first.
    return [(change.from_version, change.to_version, change.observed_at) for change in history[-10:]]


async def test_version_evidence_is_bounded_by_the_window_the_key_and_the_catalog_item(evidence_sessions):
    now = datetime.now(UTC).replace(microsecond=0)
    expected = await seed_version_history(evidence_sessions, now)
    event = CanonicalEvent(
        tenant_id="test-org", source_type="browser", evidence_type="inventory", extension_id="abc", timestamp=now
    )
    identifier = await Correlator(evidence_sessions).upsert_detection(event, EXTENSION, "extension_id", 0.95)
    async with evidence_sessions() as session:
        browser = (await session.get(DetectionORM, identifier)).evidence_bundle["browser"]
    assert browser["version_changes"] == [
        {"from_version": old, "to_version": new, "observed_at": _json_time(observed)} for old, new, observed in expected
    ]
    # Distinct hosts per last reported version; "" is an installation that reported none.
    assert browser["versions"] == {"1.1.11": 1, "1.2.0": 1, "": 1}


async def test_timeline_lists_identity_free_version_changes_for_every_role(evidence_sessions):
    now = datetime.now(UTC).replace(microsecond=0)
    expected = await seed_version_history(evidence_sessions, now)
    event = CanonicalEvent(
        tenant_id="test-org", source_type="browser", evidence_type="inventory", extension_id="abc", timestamp=now
    )
    identifier = await Correlator(evidence_sessions).upsert_detection(event, EXTENSION, "extension_id", 0.95)

    async def session_dependency():
        async with evidence_sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(detections.router)
    app.dependency_overrides[get_postgres_session] = session_dependency
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(role="viewer")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as client:
        timeline = await client.get(f"/api/v1/detections/{identifier}/timeline")
        detail = await client.get(f"/api/v1/detections/{identifier}")
    assert timeline.status_code == detail.status_code == 200, timeline.text
    changes = [entry for entry in timeline.json() if entry["type"] == "extension_version_change"]
    assert changes == [
        {
            "type": "extension_version_change",
            "timestamp": observed.isoformat(),
            "description": f"chrome extension updated {old or 'not reported'} -> {new}",
            "browser": "chrome",
            "from_version": old,
            "to_version": new,
        }
        for old, new, observed in expected
    ]
    assert [entry["timestamp"] for entry in timeline.json()] == sorted(entry["timestamp"] for entry in timeline.json())
    # Labels, profiles and versions of rows outside the window, the key or the catalog item never appear.
    for text in (timeline.text, json.dumps(detail.json()["evidence_bundle"])):
        assert not [value for value in ("p1_", "Profile 1", "Default", "-expired", "-stale", "-other") if value in text]
    browser = detail.json()["evidence_bundle"]["browser"]
    assert [change["to_version"] for change in browser["version_changes"]] == [new for _, new, _ in expected]
    assert browser["versions"] == {"1.1.11": 1, "1.2.0": 1, "": 1}
