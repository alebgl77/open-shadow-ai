"""Network samples retain newest observed evidence without manufacturing duplicate activity."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from test_evidence_privacy import evidence_sessions as evidence_sessions

from shadai.config import get_config
from shadai.engine.correlator import Correlator, NetworkObservation, _network_context
from shadai.models.catalog import CatalogItemRead
from shadai.models.detection import DetectionORM
from shadai.models.event import NETWORK_PROTOCOLS, CanonicalEvent
from shadai.utils.privacy import sanitize_evidence

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
FIELDS = {"timestamp", "protocol", "domain", "src_ip", "dst_ip", "dst_port", "collector_id", "event_id"}


def sample(identifier, observed_at, **changes):
    value = NetworkObservation(
        event_id=UUID(int=identifier), timestamp=observed_at, protocol="TLS", domain="service.example.test",
        src_ip="192.0.2.1", dst_ip="192.0.2.2", dst_port=443, collector_id="test-sensor",
    ).model_dump(mode="json")
    return value | changes


def event(identifier, timestamp, **changes):
    return CanonicalEvent(**({
        "tenant_id": "test-org", "source_type": "network", "protocol": "TLS", "sni": "service.example.test",
        "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "dst_port": 443, "collector_id": "test-sensor",
        "event_id": UUID(int=identifier), "timestamp": timestamp,
    } | changes))


def retained(values, *, config=None):
    return sanitize_evidence({"network": {"network_observations": values}}, now=NOW, config=config)["network"][
        "network_observations"
    ]


def identifiers(values):
    return [UUID(value["event_id"]).int for value in values]


@pytest.mark.parametrize("seconds_ago,expected", [
    (100, list(range(1, 11))),
    (15.5, [2, 3, 4, 5, 11, 6, 7, 8, 9, 10]),
    (0, [*range(2, 11), 11]),
])
def test_merge_selects_newest_ten_for_older_middle_and_newer_arrivals(seconds_ago, expected):
    previous = {
        "protocol_counts": {"DNS": 2, "TLS": 10},
        "network_observations": [sample(index, NOW - timedelta(seconds=21 - index)) for index in range(1, 11)],
    }
    original = deepcopy(previous)

    result = _network_context(event(11, NOW - timedelta(seconds=seconds_ago)), previous, now=NOW)

    assert identifiers(result["network_observations"]) == expected
    assert result["protocol_counts"] == {"DNS": 2, "TLS": 11, "HTTP": 0, "QUIC": 0}
    assert previous == original
    assert set(result) == {"protocol_counts", "network_observations"}
    assert all(set(value) == FIELDS for value in result["network_observations"])


def test_all_prior_candidates_merge_before_cap_or_duplicate_selection():
    previous = [sample(index, NOW - timedelta(seconds=21 - index)) for index in range(1, 13)]
    # The incoming UUID already has a newer retained claim. Its earlier observation must
    # win dedup before top-ten selection, leaving UUID 2 available for the final sample.
    result = _network_context(event(12, NOW - timedelta(seconds=100)), {"network_observations": previous}, now=NOW)

    assert identifiers(result["network_observations"]) == list(range(2, 12))
    assert result["protocol_counts"]["TLS"] == 1


def test_utc_datetime_order_handles_zero_and_fractional_seconds_and_offset_spellings():
    values = [
        sample(4, NOW, timestamp="2026-10-15T14:00:01+02:00"),
        sample(2, NOW, timestamp="2026-10-15T12:00:00.000001Z"),
        sample(1, NOW, timestamp="2026-10-15T12:00:00Z"),
        sample(3, NOW, timestamp="2026-10-15T08:00:00.999999-04:00"),
    ]

    assert identifiers(retained(values)) == [1, 2, 3, 4]
    result = _network_context(event(5, NOW + timedelta(microseconds=500000)), {"network_observations": values}, now=NOW)
    assert identifiers(result["network_observations"]) == [1, 2, 5, 3, 4]


@pytest.mark.parametrize("order", [list(range(1, 13)), list(range(12, 0, -1)),
                                   [*range(2, 13, 2), *range(1, 13, 2)],
                                   [*range(7, 13), *range(1, 7)]])
def test_equal_time_selection_and_output_use_deterministic_uuid_order(order):
    values = [sample(index, NOW) for index in order]

    assert identifiers(retained(values)) == list(range(3, 13))
    result = _network_context(event(13, NOW), {"network_observations": values}, now=NOW)
    assert identifiers(result["network_observations"]) == list(range(4, 14))


@pytest.mark.parametrize("incoming_earlier", [False, True])
def test_duplicate_uuid_keeps_earliest_whole_record_without_renewing_activity(incoming_earlier):
    previous = sample(1, NOW - timedelta(minutes=10))
    incoming_time = NOW - timedelta(minutes=20) if incoming_earlier else NOW
    incoming = event(
        1, incoming_time, collector_id="other-sensor", src_ip="192.0.2.10", dst_ip="192.0.2.20", dst_port=8443,
    )
    result = _network_context(incoming, {"protocol_counts": {"TLS": 1}, "network_observations": [previous]}, now=NOW)
    expected = sample(
        1, incoming_time, collector_id="other-sensor", src_ip="192.0.2.10", dst_ip="192.0.2.20", dst_port=8443,
    ) if incoming_earlier else previous

    assert result["network_observations"] == [expected]
    # This helper records one admitted event; SQL receipts provide actual replay idempotence.
    assert result["protocol_counts"]["TLS"] == 2


@pytest.mark.parametrize("field,smaller,larger", [
    ("protocol", "DNS", "TLS"),
    ("domain", "a.example.test", "z.example.test"),
    ("src_ip", "192.0.2.1", "192.0.2.3"),
    ("dst_ip", "192.0.2.2", "192.0.2.4"),
    ("dst_port", 80, 443),
    ("collector_id", "a-sensor", "z-sensor"),
])
def test_same_uuid_same_time_conflicts_choose_canonical_fields_independently_of_input_order(field, smaller, larger):
    first = sample(1, NOW, **{field: smaller})
    second = sample(1, NOW, **{field: larger})

    assert retained([first, second]) == retained([second, first]) == [first]


def test_equivalent_uuid_and_utc_spellings_deduplicate_to_one_canonical_observation():
    identifier = UUID("abcdef01-2345-6789-abcd-ef0123456789")
    canonical = sample(identifier.int, NOW)
    equivalent = canonical | {"event_id": str(identifier).upper(), "timestamp": "2026-10-15T14:00:00+02:00"}

    assert retained([equivalent, canonical, equivalent]) == [canonical]


@pytest.mark.parametrize("surface", ["read", "update"])
def test_retention_edges_remain_inclusive_and_use_configured_identity_window(surface):
    config = get_config()
    config.retention.identity_days = 1
    cutoff, future = NOW - timedelta(days=1), NOW + timedelta(minutes=5)
    values = [
        sample(1, cutoff - timedelta(microseconds=1)), sample(2, cutoff),
        sample(3, future), sample(4, future + timedelta(microseconds=1)),
    ]

    if surface == "read":
        result = retained(values, config=config)
    else:
        result = _network_context(event(5, NOW), {"network_observations": values}, now=NOW)["network_observations"]
    assert identifiers(result) == ([2, 3] if surface == "read" else [2, 5, 3])


@pytest.mark.parametrize("excluded_time", [NOW - timedelta(days=31), NOW + timedelta(minutes=5, microseconds=1)])
@pytest.mark.parametrize("surface", ["read", "update"])
def test_out_of_window_duplicate_is_not_a_tombstone_for_current_evidence(excluded_time, surface):
    current = sample(1, NOW)
    excluded = sample(1, excluded_time, collector_id="expired-or-future-sensor")

    if surface == "read":
        assert retained([current, excluded]) == retained([excluded, current]) == [current]
    else:
        result = _network_context(event(1, NOW), {"network_observations": [excluded]}, now=NOW)
        assert result["network_observations"] == [current]


@pytest.mark.parametrize("bad", [
    None, [], {}, "not-an-observation",
    {"packet_body": "private-content"},
    {"event_id": "invalid"},
    {"timestamp": "2026-10-15T12:00:00"},
    {"timestamp": "9999-12-31T23:59:59-01:00"},
    {"timestamp": "0001-01-01T00:00:00+01:00"},
    {"protocol": "TCP"}, {"domain": "192.0.2.1"},
    {"src_ip": "fe80::1%zone"}, {"dst_ip": "not-an-address"},
    {"dst_port": -1}, {"dst_port": 65536},
    {"collector_id": ""}, {"collector_id": "s" * 256},
])
def test_malformed_candidates_fail_closed_without_losing_valid_neighbors(bad):
    good = sample(1, NOW)
    malformed = sample(2, NOW) | bad if isinstance(bad, dict) and bad else bad

    assert retained([good, malformed]) == [good]
    result = _network_context(
        event(3, NOW + timedelta(seconds=1)), {"network_observations": [malformed, good]}, now=NOW,
    )
    assert identifiers(result["network_observations"]) == [1, 3]
    assert all(set(value) == FIELDS for value in result["network_observations"])


@pytest.mark.parametrize("values", [None, {}, "legacy-value", 7])
def test_malformed_sample_containers_do_not_prevent_a_valid_new_observation(values):
    assert retained(values) == []
    result = _network_context(event(1, NOW), {"network_observations": values}, now=NOW)
    assert result["network_observations"] == [sample(1, NOW)]


def seeded_detection_with_uncapped_candidates():
    correlator = Correlator(None)
    item = CatalogItemRead(catalog_item_id="seeded-network-ordering", canonical_name="Service", category="ai_platform")
    first = event(1, NOW - timedelta(seconds=20))
    detection = correlator._create_detection(first, item, "sni", 0.65, first.timestamp, NOW, None)
    detection.detection_id = uuid4()
    detection.last_seen_at = NOW - timedelta(seconds=9)
    detection.total_events_count = 12
    detection.analyst_status = "investigating"
    detection.analyst_notes = "Keep this manual note"
    bundle = deepcopy(detection.evidence_bundle)
    bundle["_evidence_counts"] = {"observation": 12}
    bundle["network"].update(
        event_count=12, protocol_counts={"TLS": 12},
        last_seen=detection.last_seen_at.isoformat(),
        network_observations=[sample(index, NOW - timedelta(seconds=21 - index)) for index in range(1, 13)] + [
            sample(2, NOW, packet_body="private-network-canary"),
            sample(13, NOW - timedelta(days=31)),
            sample(14, NOW + timedelta(minutes=5, microseconds=1)),
        ],
        packet_body="private-network-canary",
    )
    detection.evidence_bundle = bundle
    return detection, item


def assert_seeded_update(detection):
    observations = detection.evidence_bundle["network"]["network_observations"]
    assert identifiers(observations) == list(range(2, 12))
    assert all(set(value) == FIELDS for value in observations)
    assert "private-network-canary" not in repr(detection.evidence_bundle)
    assert detection.evidence_bundle["network"]["protocol_counts"]["TLS"] == 13
    assert detection.total_events_count == detection.evidence_bundle["network"]["event_count"] == 13
    assert detection.evidence_bundle["_evidence_counts"] == {"observation": 13}
    assert detection.source_types == ["network"] and detection.confidence_score == 0.65
    assert detection.shadow_ai_status == "suspected"
    assert detection.impacted_users_count == detection.impacted_devices_count == 0
    assert detection.first_seen_at.replace(tzinfo=UTC) == NOW - timedelta(seconds=100)
    assert detection.last_seen_at.replace(tzinfo=UTC) == NOW - timedelta(seconds=9)
    assert detection.analyst_status == "investigating" and detection.analyst_notes == "Keep this manual note"


def test_direct_update_preserves_original_candidates_before_premerge_sanitation():
    detection, _ = seeded_detection_with_uncapped_candidates()
    incoming = event(12, NOW - timedelta(seconds=100))

    Correlator(None)._update_detection(detection, incoming, "sni", 0.65, incoming.timestamp, NOW, None)

    assert_seeded_update(detection)


async def test_upsert_preserves_original_candidates_across_identity_premerge_sanitation(evidence_sessions, monkeypatch):
    from shadai.engine import correlator as correlator_module

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(correlator_module, "datetime", Clock)
    detection, item = seeded_detection_with_uncapped_candidates()
    identifier = detection.detection_id
    async with evidence_sessions.begin() as session:
        session.add(detection)
    sync = correlator_module.sync_identity_members
    after_identity_sync = []

    async def traced_sync(session, current, incoming, now):
        assert len(current.evidence_bundle["network"]["network_observations"]) > 10
        await sync(session, current, incoming, now)
        after_identity_sync.append(identifiers(current.evidence_bundle["network"]["network_observations"]))

    monkeypatch.setattr(correlator_module, "sync_identity_members", traced_sync)
    incoming = event(12, NOW - timedelta(seconds=100))
    correlator = Correlator(evidence_sessions)

    assert await correlator.upsert_detection(incoming, item, "sni", 0.65) == identifier
    assert after_identity_sync == [list(range(3, 13))]
    async with evidence_sessions() as session:
        updated = await session.get(DetectionORM, identifier)
        assert_seeded_update(updated)
        retained_bundle = deepcopy(updated.evidence_bundle)

    # A receipt replay bypasses identity synchronization and cannot restore rejected candidates.
    assert await correlator.upsert_detection(incoming, item, "sni", 0.65) == identifier
    assert after_identity_sync == [list(range(3, 13))]
    async with evidence_sessions() as session:
        replayed = await session.get(DetectionORM, identifier)
        assert replayed.evidence_bundle == retained_bundle and replayed.total_events_count == 13


@pytest.mark.parametrize("source", ["dns", "proxy", "browser"])
def test_other_source_updates_do_not_carry_uncapped_network_candidates(source):
    detection, _ = seeded_detection_with_uncapped_candidates()
    incoming = CanonicalEvent(tenant_id="test-org", source_type=source, timestamp=NOW, domain="service.example.test")

    Correlator(None)._update_detection(detection, incoming, "domain", 0.60, incoming.timestamp, NOW, None)

    assert identifiers(detection.evidence_bundle["network"]["network_observations"]) == list(range(3, 13))
    assert "private-network-canary" not in repr(detection.evidence_bundle)
    assert "network_observations" not in detection.evidence_bundle[source]


async def test_correlation_receipts_freeze_samples_counters_provenance_and_observation_clock(
    evidence_sessions, monkeypatch,
):
    clock_calls = []

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            clock_calls.append(tz)
            return NOW

    monkeypatch.setattr("shadai.engine.correlator.datetime", Clock)
    correlator = Correlator(evidence_sessions)
    item = CatalogItemRead(catalog_item_id="network-ordering", canonical_name="Service", category="ai_platform")
    events = [event(index, NOW - timedelta(seconds=21 - index)) for index in range(1, 11)]
    events += [event(11, NOW - timedelta(seconds=100)), event(12, NOW)]
    identifiers_seen = [await correlator.upsert_detection(value, item, "sni", 0.65) for value in events]
    identifier = identifiers_seen[0]
    assert len(set(identifiers_seen)) == 1 and clock_calls == [UTC] * 12
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
        bundle = deepcopy(detection.evidence_bundle)
        assert identifiers(bundle["network"]["network_observations"]) == [*range(2, 11), 12]
        assert bundle["network"]["protocol_counts"] == {
            protocol: 12 if protocol == "TLS" else 0 for protocol in NETWORK_PROTOCOLS
        }
        assert detection.total_events_count == 12 and bundle["network"]["event_count"] == 12
        assert detection.source_types == ["network"] and bundle["_evidence_counts"] == {"observation": 12}
        assert detection.confidence_score == 0.65 and detection.shadow_ai_status == "suspected"
        assert detection.first_seen_at.replace(tzinfo=UTC) == NOW - timedelta(seconds=100)
        assert detection.last_seen_at.replace(tzinfo=UTC) == NOW

    # Even conflicting replay bytes cannot renew an already received UUID.
    replay = events[4].model_copy(update={"timestamp": NOW + timedelta(minutes=1), "collector_id": "other-sensor"})
    assert await correlator.upsert_detection(replay, item, "sni", 0.65) == identifier
    assert clock_calls == [UTC] * 12
    async with evidence_sessions() as session:
        replayed = await session.get(DetectionORM, identifier)
        assert replayed.evidence_bundle == bundle and replayed.total_events_count == 12
        assert replayed.last_seen_at.replace(tzinfo=UTC) == NOW
