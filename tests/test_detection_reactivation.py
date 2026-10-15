"""Only current incoming evidence may reopen an aged automatic detection status."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_evidence_privacy import evidence_sessions as evidence_sessions

from shadai.config import get_config
from shadai.engine.correlator import Correlator
from shadai.models.catalog import CatalogItemRead
from shadai.models.detection import DetectionORM
from shadai.models.event import CanonicalEvent
from shadai.workers.purge import purge_once

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
ITEM = CatalogItemRead(catalog_item_id="reactivation-test", canonical_name="Service", category="ai_platform")


def observation(source, timestamp):
    fields = {}
    if source == "network":
        fields = {"protocol": "TLS", "sni": "service.example.test"}
    elif source == "instrumented":
        fields = {"evidence_type": "usage", "measurement_provenance": "instrumented"}
    elif source == "browser":
        fields = {"evidence_type": "inventory"}
    return CanonicalEvent(
        tenant_id="test-org", collector_id="test-sensor", source_type=source,
        domain="service.example.test", timestamp=timestamp, **fields,
    )


def retained_detection(status, *, source="dns", confidence=0.60, timestamp=None):
    event = observation(source, timestamp or NOW - timedelta(days=100))
    detection = Correlator(None)._create_detection(event, ITEM, "domain", confidence, event.timestamp, NOW, None)
    detection.detection_id = uuid4()
    detection.shadow_ai_status = status
    detection.analyst_status = "investigating"
    detection.analyst_id = uuid4()
    detection.analyst_notes = "Keep this manual note"
    detection.reviewed_at = NOW - timedelta(days=1)
    detection.recommended_action = "review"
    return detection


def analyst_fields(detection):
    return (
        detection.analyst_status, detection.analyst_id, detection.analyst_notes,
        detection.reviewed_at, detection.recommended_action,
    )


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
@pytest.mark.parametrize("source,confidence", [
    ("dns", 0.60), ("network", 0.65), ("proxy", 0.85), ("instrumented", 0.99),
])
@pytest.mark.parametrize("historical_strong", [False, True])
def test_historical_backfill_of_any_strength_does_not_reactivate(
    retained_status, source, confidence, historical_strong,
):
    detection = retained_detection(
        retained_status, source="instrumented" if historical_strong else source,
        confidence=0.99 if historical_strong else confidence,
    )
    identifier, analyst = detection.detection_id, analyst_fields(detection)
    event = observation(source, NOW - timedelta(days=59))

    Correlator(None)._update_detection(detection, event, "domain", confidence, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == retained_status
    assert detection.first_seen_at == NOW - timedelta(days=100)
    assert detection.last_seen_at == event.timestamp < NOW - timedelta(days=30)
    assert detection.detection_id == identifier and detection.total_events_count == 2
    assert analyst_fields(detection) == analyst
    # Catalog association and materialized risk retain their separate existing semantics.
    assert detection.evidence_bundle[source]["confidence_base"] >= confidence
    if historical_strong:
        assert detection.confidence_score >= 0.99
        assert detection.evidence_bundle["instrumented"]["confidence_base"] == 0.99
    assert detection.risk_calculated_at == NOW and not detection.risk_score_stale


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
@pytest.mark.parametrize("source,confidence", [("dns", 0.60), ("network", 0.65)])
def test_fresh_weak_evidence_reactivates_as_suspected_despite_historical_strength(retained_status, source, confidence):
    detection = retained_detection(retained_status, source="instrumented", confidence=0.99)
    analyst = analyst_fields(detection)
    event = observation(source, NOW - timedelta(hours=1))

    Correlator(None)._update_detection(detection, event, "domain", confidence, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == "suspected"
    assert detection.confidence_score >= 0.99
    assert detection.evidence_bundle["instrumented"]["confidence_base"] == 0.99
    assert detection.evidence_bundle["_evidence_counts"] == {"usage": 1, "observation": 1}
    assert detection.last_seen_at == event.timestamp and analyst_fields(detection) == analyst


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
@pytest.mark.parametrize("source,confidence,expected", [
    ("dns", 0.60, "suspected"),
    ("network", 0.65, "suspected"),
    ("proxy", 0.69, "suspected"),
    ("proxy", 0.70, "probable"),
    ("proxy", 0.89, "probable"),
    ("proxy", 0.90, "high_confidence"),
    ("browser", 0.95, "high_confidence"),
    ("instrumented", 0.99, "high_confidence"),
])
def test_fresh_reactivation_matches_creation_rules(retained_status, source, confidence, expected):
    correlator = Correlator(None)
    event = observation(source, NOW - timedelta(seconds=1))
    detection = retained_detection(retained_status)
    created = correlator._create_detection(event, ITEM, "domain", confidence, event.timestamp, NOW, None)

    correlator._update_detection(detection, event, "domain", confidence, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == created.shadow_ai_status == expected
    assert detection.last_seen_at == event.timestamp < NOW


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
def test_historical_input_cannot_reactivate_even_when_stored_last_seen_is_current(retained_status):
    previous_seen = NOW - timedelta(days=1)
    detection = retained_detection(retained_status, source="instrumented", confidence=0.99, timestamp=previous_seen)
    event = observation("proxy", NOW - timedelta(days=59))

    Correlator(None)._update_detection(detection, event, "domain", 0.90, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == retained_status
    assert detection.first_seen_at == event.timestamp
    assert detection.last_seen_at == previous_seen


@pytest.mark.parametrize("age_days", [0, 59])
@pytest.mark.parametrize("status,confidence,expected", [
    ("suspected", 0.65, "suspected"),
    ("suspected", 0.70, "probable"),
    ("suspected", 0.90, "high_confidence"),
    ("probable", 0.65, "probable"),
    ("high_confidence", 0.65, "high_confidence"),
    ("confirmed", 0.99, "confirmed"),
    ("false_positive", 0.99, "false_positive"),
])
def test_ordinary_status_updates_keep_existing_upgrade_rules(age_days, status, confidence, expected):
    detection = retained_detection(status, source="proxy")
    analyst = analyst_fields(detection)
    event = observation("proxy", NOW - timedelta(days=age_days))

    Correlator(None)._update_detection(detection, event, "domain", confidence, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == expected
    assert analyst_fields(detection) == analyst


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
@pytest.mark.parametrize("analyst_status", ["classified", "false_positive", "escalated"])
@pytest.mark.parametrize("age_days", [0, 59])
def test_analyst_choices_survive_both_reactivation_and_backfill(retained_status, analyst_status, age_days):
    detection = retained_detection(retained_status)
    detection.analyst_status = analyst_status
    analyst = analyst_fields(detection)
    event = observation("dns", NOW - timedelta(days=age_days))

    Correlator(None)._update_detection(detection, event, "domain", 0.60, event.timestamp, NOW, None)

    assert detection.shadow_ai_status == ("suspected" if age_days == 0 else retained_status)
    assert analyst_fields(detection) == analyst


@pytest.mark.parametrize("retained_status", ["stale", "archived"])
@pytest.mark.parametrize("offset_us", [-1, 0, 1])
async def test_reactivation_cutoff_matches_purge_and_freezes_one_clock(
    evidence_sessions, monkeypatch, retained_status, offset_us,
):
    clock_calls = []

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            clock_calls.append(tz)
            return NOW

    monkeypatch.setattr("shadai.engine.correlator.datetime", Clock)
    detection = retained_detection(retained_status, source="instrumented", confidence=0.99)
    identifier, analyst = detection.detection_id, analyst_fields(detection)
    event = observation("dns", NOW - timedelta(days=30) + timedelta(microseconds=offset_us))
    control = Correlator(None)._create_detection(
        event, ITEM.model_copy(update={"catalog_item_id": "purge-control"}),
        "domain", 0.60, event.timestamp, NOW, None,
    )
    control.detection_id = uuid4()
    async with evidence_sessions.begin() as session:
        session.add_all([detection, control])
    correlator = Correlator(evidence_sessions)

    assert await correlator.upsert_detection(event, ITEM, "domain", 0.60) == identifier
    assert clock_calls == [UTC]
    expected = retained_status if offset_us < 0 else "suspected"
    async with evidence_sessions() as session:
        updated = await session.get(DetectionORM, identifier)
        assert updated.shadow_ai_status == expected
        assert updated.last_seen_at.replace(tzinfo=UTC) == event.timestamp
        assert updated.first_seen_at.replace(tzinfo=UTC) == NOW - timedelta(days=100)
        assert updated.total_events_count == 2
        assert updated.risk_calculated_at == NOW
        assert analyst_fields(updated)[:3] == analyst[:3]
        retained_bundle = updated.evidence_bundle

    # Receipt replay must neither renew timestamps nor add another update or clock read.
    assert await correlator.upsert_detection(event, ITEM, "domain", 0.60) == identifier
    assert clock_calls == [UTC]
    async with evidence_sessions() as session:
        replayed = await session.get(DetectionORM, identifier)
        assert replayed.shadow_ai_status == expected and replayed.total_events_count == 2
        assert replayed.last_seen_at.replace(tzinfo=UTC) == event.timestamp
        assert replayed.evidence_bundle == retained_bundle

    # Actual maintenance agrees on the inclusive edge, without any live store.
    monkeypatch.setattr("shadai.workers.purge.datetime", Clock)
    await purge_once(get_config(), evidence_sessions, SimpleNamespace(execute=lambda *args: None))
    assert clock_calls == [UTC, UTC]
    async with evidence_sessions() as session:
        maintained = await session.get(DetectionORM, identifier)
        assert maintained.shadow_ai_status == expected
        assert maintained.last_seen_at.replace(tzinfo=UTC) == event.timestamp
        maintenance_control = await session.get(DetectionORM, control.detection_id)
        assert maintenance_control.shadow_ai_status == ("stale" if offset_us < 0 else "suspected")
