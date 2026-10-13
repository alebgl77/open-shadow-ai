"""Personal evidence ages independently of service activity and delivery retries."""

import importlib.util
import json
import os
import re
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from cryptography.fernet import Fernet
from sqlalchemy import JSON, delete, func, inspect, select
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import defer
from starlette.requests import Request

from shadai.api.ingestion import prepare_event
from shadai.config import get_config
from shadai.engine.correlator import Correlator
from shadai.models.base import Base
from shadai.models.catalog import CatalogItemRead
from shadai.models.detection import DetectionORM, DetectionRead, DetectionUpdate
from shadai.models.event import CanonicalEvent
from shadai.models.evidence_identity import EvidenceIdentityORM
from shadai.models.extension_inventory import (
    INVENTORY_INSTALL_SOURCES,
    ExtensionInventoryListResponse,
    ExtensionInventoryORM,
    ExtensionInventoryRead,
    ExtensionVersionChangeORM,
    ExtensionVersionChangeRead,
)
from shadai.models.governance import GovernanceORM
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM
from shadai.models.user import UserORM
from shadai.utils.privacy import IDENTITY_FIELDS, keyed_identity, refresh_identity_counts, sanitize_evidence
from shadai.workers.purge import PERSONAL_EVENT_COLUMNS, maintain_personal_evidence, scrub_personal_history


def observation(**kwargs):
    return CanonicalEvent(tenant_id="test-org", collector_id="sensor", source_type="endpoint", **kwargs)


def item(name="privacy-test"):
    return CatalogItemRead(catalog_item_id=name, canonical_name="Service", category="ai_platform")


@pytest.fixture
async def evidence_sessions(identity_sessions, monkeypatch):
    sessions = identity_sessions
    column = DetectionORM.__table__.c.source_types
    monkeypatch.setattr(column, "type", column.type.with_variant(JSON(), "sqlite"))

    def sqlite_advisory(connection, record):
        connection.create_function("hashtextextended", 2, lambda value, seed: 1)
        connection.create_function("pg_advisory_xact_lock", 1, lambda value: None)
        # PostgreSQL enforces ON DELETE CASCADE; SQLite only does so with the pragma.
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    engine = sessions.kw["bind"]
    sqlalchemy_event.listen(engine.sync_engine, "connect", sqlite_advisory)
    # Dispose the original schema connection so SQLite gets the above functions.
    await engine.dispose()
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda conn: Base.metadata.create_all(
                conn,
                tables=[
                    DetectionORM.__table__,
                    EvidenceIdentityORM.__table__,
                    GovernanceORM.__table__,
                    CorrelationReceiptORM.__table__,
                    IngestReceiptORM.__table__,
                    ExtensionInventoryORM.__table__,
                    ExtensionVersionChangeORM.__table__,
                ],
            )
        )
    yield sessions


def test_pseudonyms_are_domain_separated_and_internal_replay_is_idempotent():
    config = get_config()
    config.security.pseudonymize_identities = True
    raw = observation(
        user_id="Alice",
        username="Alice",
        hostname="Alice",
        device_id="Alice",
        identity_object_id="CN=Alice,OU=People,DC=corp",
        identity_sid="S-1-5-21-100",
        src_ip="192.0.2.10",
        dst_ip="192.0.2.20",
        domain="service.example",
        provider="openai",
        site_id="site-1",
        identity_provider="active_directory",
    )
    prepared = prepare_event(raw.model_copy(deep=True))
    assert len({prepared.user_id, prepared.username, prepared.hostname, prepared.device_id}) == 4
    assert prepared.src_ip == "" and prepared.dst_ip == raw.dst_ip
    assert prepared.domain == raw.domain and prepared.provider == raw.provider and prepared.site_id == raw.site_id
    assert prepared.identity_provider == "active_directory"
    output = prepared.model_dump_json()
    for value in ("Alice", "CN=Alice", "S-1-5-21-100", "192.0.2.10"):
        assert value not in output
    assert "privacy_stamp" not in prepared.to_clickhouse_dict()
    for _ in range(3):
        prepared = prepare_event(prepared, trusted_collector=True)
    assert prepared.model_dump_json() == output
    changed = prepared.model_copy(deep=True)
    changed.username = "Injected user"
    assert prepare_event(changed, trusted_collector=True).username != "Injected user"
    config.security.encryption_key = Fernet.generate_key().decode()
    different = prepare_event(raw.model_copy(deep=True))
    assert different.user_id != prepared.user_id


def test_external_marker_or_alias_never_skips_transformation_and_raw_mode_is_compatible():
    config = get_config()
    raw = observation(user_id="raw-name", src_ip="192.0.2.10", identity_provider="provider:raw-name@example.test")
    assert prepare_event(raw.model_copy(deep=True)).user_id == "raw-name"
    config.security.pseudonymize_identities = True
    prepared = prepare_event(raw.model_copy(deep=True))
    assert prepared.identity_provider == ""
    external = prepare_event(prepared.model_copy(deep=True))
    assert external.user_id != prepared.user_id
    forged = raw.model_copy(update={"privacy_stamp": "a" * 64, "user_id": "p1_" + "0" * 64})
    forged_id = forged.user_id
    transformed = prepare_event(forged, trusted_collector=True)
    assert transformed.user_id != forged_id
    assert keyed_identity("user", "Alice") != keyed_identity("device", "Alice")


async def test_active_service_new_identity_does_not_renew_old_and_replay_cannot_resurrect(
    evidence_sessions, monkeypatch
):
    config = get_config()
    config.retention.identity_days = 1
    clock = datetime(2026, 10, 6, 12, tzinfo=UTC)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock

    monkeypatch.setattr("shadai.engine.correlator.datetime", Clock)
    correlator = Correlator(evidence_sessions)
    alice = observation(user_id="Alice", device_id="Device-A", username="Alice", timestamp=clock)
    identifier = await correlator.upsert_detection(alice, item(), "username", 0.9)
    clock += timedelta(days=2)
    bob = observation(user_id="Bob", device_id="Device-B", username="Bob", timestamp=clock)
    await correlator.upsert_detection(bob, item(), "username", 0.9)
    for timestamp in (clock, clock - timedelta(hours=1)):
        await correlator.upsert_detection(
            observation(user_id="Bob", username="Bob", device_id="Device-B", timestamp=timestamp),
            item(),
            "username",
            0.9,
        )
    await correlator.upsert_detection(alice.model_copy(update={"event_id": uuid4()}), item(), "username", 0.9)
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
        assert detection.last_seen_at.replace(tzinfo=UTC) == clock
        assert detection.impacted_users_count == detection.impacted_devices_count == 1
        assert "Alice" not in json.dumps(detection.evidence_bundle)
        assert detection.evidence_bundle["endpoint"]["sample_values"] == ["Bob"]
        members = list((await session.execute(select(EvidenceIdentityORM))).scalars())
        assert len(members) == 2 and all(member.last_seen_at.replace(tzinfo=UTC) == clock for member in members)
        assert await session.scalar(select(func.count()).select_from(CorrelationReceiptORM)) == 5


async def test_exact_utc_cutoff_uncapped_membership_and_bounded_samples(evidence_sessions, monkeypatch):
    now = datetime(2026, 10, 6, 12, tzinfo=UTC)
    config = get_config()
    config.retention.identity_days = 1

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("shadai.engine.correlator.datetime", Clock)
    correlator = Correlator(evidence_sessions)
    cutoff = now - timedelta(days=1)
    identifier = await correlator.upsert_detection(
        observation(user_id="Edge", username="Edge", timestamp=cutoff), item(), "username", 0.9
    )
    await correlator.upsert_detection(
        observation(user_id="Outside", username="Outside", timestamp=cutoff - timedelta(microseconds=1)),
        item(),
        "username",
        0.9,
    )
    for index in range(25):
        await correlator.upsert_detection(
            observation(user_id=f"User-{index}", username=f"User-{index}", timestamp=now), item(), "username", 0.9
        )
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
        assert detection.impacted_users_count == 26
        assert len(detection.evidence_bundle["endpoint"]["sample_values"]) == 10
        assert "_users" not in detection.evidence_bundle and "_devices" not in detection.evidence_bundle
        assert await session.scalar(select(func.count()).select_from(EvidenceIdentityORM)) == 26


async def test_mode_toggle_keeps_members_and_key_change_rebuild_is_explicit(evidence_sessions):
    config, correlator, now = get_config(), Correlator(evidence_sessions), datetime.now(UTC)
    for name in ("Alice", "Bob"):
        identifier = await correlator.upsert_detection(
            prepare_event(observation(user_id=name, timestamp=now)), item(), "process_name", 0.9
        )
    config.security.pseudonymize_identities = True
    pseudonymous = prepare_event(observation(user_id="Alice", timestamp=now))
    await correlator.upsert_detection(pseudonymous, item(), "process_name", 0.9)
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
        assert detection.impacted_users_count == 2
        assert detection.evidence_bundle["_identity_window"]["basis_reset_reason"] == "initialized"
    config.security.pseudonymize_identities = False
    replayed = prepare_event(pseudonymous.model_copy(update={"event_id": uuid4()}), trusted_collector=True)
    assert replayed.user_id == pseudonymous.user_id and replayed.privacy_stamp == pseudonymous.privacy_stamp
    await correlator.upsert_detection(replayed, item(), "process_name", 0.9)
    async with evidence_sessions() as session:
        assert (await session.get(DetectionORM, identifier)).impacted_users_count == 2
    config.security.encryption_key = Fernet.generate_key().decode()
    await correlator.upsert_detection(
        prepare_event(observation(user_id="Alice", timestamp=now)), item(), "process_name", 0.9
    )
    async with evidence_sessions() as session:
        detection = await session.get(DetectionORM, identifier)
        assert detection.impacted_users_count == 1
        assert detection.evidence_bundle["_identity_window"]["basis_reset_reason"] == "key_changed"


async def test_historical_scrub_arbitrary_cursor_cannot_skip_unclean_rows(evidence_sessions):
    now = datetime.now(UTC)
    async with evidence_sessions.begin() as session:
        detection = Correlator(None)._create_detection(
            observation(username="Alice", timestamp=now), item(), "username", 0.9, now, now, None
        )
        session.add(detection)
    result = await scrub_personal_history(
        get_config(), evidence_sessions, HistoricalClickHouse(0), after_detection_id=UUID(int=2**128 - 1)
    )
    assert result["complete"] is False and result["sql_complete"] is False


def test_legacy_shapes_and_sample_variants_fail_closed_at_exact_utc_edge():
    config = get_config()
    config.retention.identity_days = 1
    now = datetime(2026, 10, 6, 12, tzinfo=UTC)
    edge = now - timedelta(days=1)
    bundle = {
        "_users": ["Alice"],
        "_devices": {"A": now.isoformat()},
        "users": ["Alice"],
        "endpoint": {
            "sample_values": ["Alice"],
            "users": ["Alice"],
            "matched_field": ["Alice"],
            "sample_observations": [
                {"field": "username", "value": "Edge", "observed_at": edge.astimezone().isoformat()},
                {
                    "field": "username",
                    "value": "Expired",
                    "observed_at": (edge - timedelta(microseconds=1)).isoformat(),
                },
                {"field": "username", "value": "Unaged", "observed_at": edge.replace(tzinfo=None).isoformat()},
                {"field": "username", "value": "Extra", "observed_at": now.isoformat(), "raw": "Alice"},
                {"field": [], "value": "Bad field", "observed_at": now.isoformat()},
            ],
        },
        "browser": ["Alice"],
        "network": {"network_observations": [{"raw": "Alice"}]},
        "confidence_factors": [{"description": "Alice"}],
        "risk_factors": [{"factor": "many_users", "value": 10, "description": "Alice"}],
    }
    clean = sanitize_evidence(bundle, now=now)
    assert "Alice" not in json.dumps(clean)
    assert clean["endpoint"]["sample_values"] == ["Edge"]
    assert clean["network"]["network_observations"] == []
    assert "browser" not in clean and "users" not in clean and "_users" not in clean


def test_browser_version_evidence_survives_only_well_formed_aged_and_identity_free():
    config = get_config()
    config.retention.identity_days = 1
    now = datetime(2026, 10, 6, 12, tzinfo=UTC)
    edge = now - timedelta(days=1)

    def change(observed_at, **state):
        return {"from_version": "1.0", "to_version": "1.1", "observed_at": observed_at, **state}

    recent = [change((now - timedelta(minutes=index)).isoformat(), to_version=f"2.{index}") for index in range(12)]
    browser = {
        "first_seen": edge.isoformat(),
        "last_seen": now.isoformat(),
        "event_count": 150,
        "confidence_base": 0.95,
        "matched_field": "extension_id",
        "version_changes": [
            change(edge.astimezone(timezone(timedelta(hours=2))).isoformat(), to_version="edge"),
            change((edge - timedelta(microseconds=1)).isoformat(), to_version="expired"),
            change(edge.replace(tzinfo=None).isoformat(), to_version="unaged"),
            change((now + timedelta(minutes=5, microseconds=1)).isoformat(), to_version="future"),
            change(now.isoformat(), host_label="WS-ALICE-01"),
            change(now.isoformat(), user_label="alice", profile="Profile 1"),
            change(now.isoformat(), from_version="x" * 101),
            change(now.isoformat(), from_version=1),
            {"from_version": "1.0", "observed_at": now.isoformat()},
            "WS-ALICE-01",
            change(now.isoformat(), from_version=None, to_version=None),
        ],
        "versions": {
            "1.1": 3,
            "": 1,
            "boolean": True,
            "negative": -1,
            "zero": 0,
            "fraction": 1.5,
            "x" * 101: 1,
            "nested": {"host_label": "WS-ALICE-01"},
        },
    }
    clean = sanitize_evidence({"browser": browser}, now=now)
    section = clean["browser"]
    assert "WS-ALICE-01" not in json.dumps(clean) and "alice" not in json.dumps(clean)
    assert section["version_changes"] == [
        {"from_version": "1.0", "to_version": "edge", "observed_at": edge.isoformat().replace("+00:00", "Z")},
        {"from_version": None, "to_version": None, "observed_at": now.isoformat().replace("+00:00", "Z")},
    ]
    assert section["versions"] == {"1.1": 3, "": 1}
    # Polls are not independent evidence on the read path either.
    assert "high_volume" not in {factor["factor"] for factor in clean["confidence_factors"]}
    assert sanitize_evidence(clean, now=now) == clean

    # The newest ten changes and the ten most reported versions are kept, in a stable order.
    many = {f"1.{index}": index + 1 for index in range(12)}
    bounded = {**browser, "version_changes": recent, "versions": many}
    bounded = sanitize_evidence({"browser": bounded}, now=now)["browser"]
    assert [value["to_version"] for value in bounded["version_changes"]] == [f"2.{index}" for index in range(9, -1, -1)]
    assert bounded["versions"] == {f"1.{index}": index + 1 for index in range(11, 1, -1)}

    # A distribution is as old as its section: unknown, expired or malformed ages keep nothing.
    unaged = {key: value for key, value in browser.items() if key != "last_seen"}
    for last_seen in ((edge - timedelta(microseconds=1)).isoformat(), edge.replace(tzinfo=None).isoformat(), 1):
        assert sanitize_evidence({"browser": {**browser, "last_seen": last_seen}}, now=now)["browser"]["versions"] == {}
    assert sanitize_evidence({"browser": unaged}, now=now)["browser"]["versions"] == {}
    malformed = {**browser, "version_changes": {"a": 1}, "versions": [["1.1", 3]]}
    malformed = sanitize_evidence({"browser": malformed}, now=now)["browser"]
    assert (malformed["version_changes"], malformed["versions"]) == ([], {})

    # Only the browser section may carry inventory evidence.
    endpoint = sanitize_evidence({"endpoint": {**browser, "matched_field": "process_name"}}, now=now)["endpoint"]
    assert "version_changes" not in endpoint and "versions" not in endpoint


async def test_reads_project_current_counts_and_risk_without_orm_writes(evidence_sessions):
    now = datetime.now(UTC)
    old = now - timedelta(days=31)
    correlator = Correlator(evidence_sessions)
    detection = correlator._create_detection(
        observation(user_id="Bob", timestamp=now), item(), "process_name", 0.9, now, now, None
    )
    detection.impacted_users_count = 20
    detection.evidence_bundle["endpoint"]["sample_observations"] = [
        {"field": "username", "value": "Alice", "observed_at": old.isoformat()}
    ]
    async with evidence_sessions.begin() as session:
        session.add(detection)
        await session.flush()
        session.add(
            EvidenceIdentityORM(
                detection_id=detection.detection_id,
                kind="user",
                identity_digest=keyed_identity("user", "Alice"),
                last_seen_at=old,
            )
        )
    async with evidence_sessions() as session:
        original = await session.get(DetectionORM, detection.detection_id)
        bundle = json.dumps(original.evidence_bundle)
        projected = (await refresh_identity_counts(session, [original], now=now))[0]
        assert projected.impacted_users_count == 0 and "Alice" not in projected.model_dump_json()
        assert not any(factor["factor"] == "many_users" for factor in projected.evidence_bundle["risk_factors"])
        assert original.impacted_users_count == 20 and json.dumps(original.evidence_bundle) == bundle
        assert not session.dirty
    await maintain_personal_evidence(get_config(), evidence_sessions, now=now, batch_size=1)
    async with evidence_sessions() as session:
        updated = await session.get(DetectionORM, detection.detection_id)
        assert updated.impacted_users_count == 0 and "Alice" not in json.dumps(updated.evidence_bundle)
        assert updated.last_seen_at.replace(tzinfo=UTC) == now


async def test_projection_loads_only_missing_scalars_without_sync_sql_or_flushing_notes(evidence_sessions, monkeypatch):
    now = datetime.now(UTC)
    async with evidence_sessions.begin() as session:
        detection = Correlator(None)._create_detection(
            observation(timestamp=now), item(), "process_name", 0.9, now, now, None
        )
        session.add(detection)
    identifier = detection.detection_id
    async with evidence_sessions() as session:
        original = (
            await session.execute(select(DetectionORM).options(defer(DetectionORM.recommended_action)))
        ).scalar_one()
        original.analyst_notes = "Pending manual note"
        session.expire(original, ["detection_id", "created_at", "updated_at", "entity_category"])
        validation_active, flushes = False, []
        model_validate = DetectionRead.model_validate

        def validate(value, *args, **kwargs):
            nonlocal validation_active
            validation_active = True
            try:
                return model_validate(value, *args, **kwargs)
            finally:
                validation_active = False

        def before_sql(*args):
            assert not validation_active, "Synchronous DTO attribute reads attempted SQL"

        def before_flush(*args):
            flushes.append(True)

        engine = evidence_sessions.kw["bind"]
        sqlalchemy_event.listen(engine.sync_engine, "before_cursor_execute", before_sql)
        sqlalchemy_event.listen(session.sync_session, "before_flush", before_flush)
        monkeypatch.setattr(DetectionRead, "model_validate", validate)
        try:
            projected = (await refresh_identity_counts(session, [original], now=now))[0]
            assert projected.detection_id == identifier
            assert projected.created_at and projected.updated_at and projected.entity_category == "ai_platform"
            assert projected.recommended_action is None
            assert projected.analyst_notes == original.analyst_notes == "Pending manual note"
            assert session.is_modified(original) and not flushes
            assert session.sync_session.is_modified(original, include_collections=False)
        finally:
            sqlalchemy_event.remove(engine.sync_engine, "before_cursor_execute", before_sql)
            sqlalchemy_event.remove(session.sync_session, "before_flush", before_flush)
            await session.rollback()
    async with evidence_sessions() as session:
        assert (await session.get(DetectionORM, identifier)).analyst_notes is None


async def test_stored_high_risk_remains_filtered_high_until_retention_maintenance(evidence_sessions, monkeypatch):
    from shadai.api.detections import list_detections
    from shadai.engine.scorer import compute_risk

    now, config = datetime.now(UTC), get_config()
    config.retention.identity_days = 1
    calculated = now - timedelta(hours=1)
    detection = Correlator(None)._create_detection(
        observation(timestamp=now, bytes_out=10_000_001), item(), "process_name", 0.9, now, now, None
    )
    detection.classification, detection.total_events_count, detection.impacted_users_count = "unsanctioned", 4, 11
    score, factors = compute_risk(
        entity_type=detection.entity_type,
        impacted_users_count=11,
        total_events_count=4,
        total_bytes_out=10_000_001,
        classification="unsanctioned",
    )
    assert score == 75
    detection.risk_score = score
    detection.evidence_bundle = {
        **detection.evidence_bundle,
        "risk_factors": factors,
        "_risk_calculated_at": calculated.isoformat(),
    }
    async with evidence_sessions.begin() as session:
        session.add(detection)
        await session.flush()
        for index in range(11):
            session.add(
                EvidenceIdentityORM(
                    detection_id=detection.detection_id,
                    kind="user",
                    identity_digest=keyed_identity("user", str(index)),
                    last_seen_at=now if index < 10 else now - timedelta(days=1, microseconds=1),
                )
            )

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("shadai.api.detections.datetime", Clock)
    async with evidence_sessions() as session:
        page = await list_detections(
            risk_level="high", page=1, page_size=10, _user=SimpleNamespace(role="analyst"), session=session
        )
        assert page.total == 1
        projected = page.items[0]
        assert projected.risk_score == 75 and projected.risk_level == "high" and projected.risk_score_stale
        assert projected.impacted_users_count == 10 and projected.risk_calculated_at == calculated
        assert not session.dirty
    await maintain_personal_evidence(config, evidence_sessions, now=now)
    async with evidence_sessions() as session:
        original = await session.get(DetectionORM, detection.detection_id)
        assert original.risk_score == 65 and original.impacted_users_count == 10
        projected = (await refresh_identity_counts(session, [original], now=now))[0]
        assert projected.risk_score == 65 and projected.risk_level == "medium" and not projected.risk_score_stale
        assert projected.risk_calculated_at == now


@pytest.mark.parametrize("legacy_stamp", [None, "invalid", "2026-10-06T12:00:00"])
async def test_legacy_risk_timestamp_is_unknown_and_note_edit_cannot_fabricate_it(
    evidence_sessions, monkeypatch, legacy_stamp
):
    from shadai.api.detections import update_detection

    now = datetime.now(UTC)
    detection = Correlator(None)._create_detection(
        observation(timestamp=now), item(), "process_name", 0.9, now, now, None
    )
    detection.evidence_bundle = {**detection.evidence_bundle, "_risk_calculated_at": legacy_stamp}
    async with evidence_sessions.begin() as session:
        session.add(detection)
    monkeypatch.setattr("shadai.api.detections.log_audit", AsyncMock())
    actor = SimpleNamespace(user_id=uuid4(), username="analyst", role="analyst")
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    async with evidence_sessions.begin() as session:
        projected = await update_detection(
            detection.detection_id, DetectionUpdate(analyst_notes="Manual note"), request, actor, session
        )
        assert projected.risk_calculated_at is None and projected.risk_score_stale
        assert projected.evidence_bundle["_risk_calculated_at"] == legacy_stamp
        assert "Manual note" in projected.analyst_notes


@pytest.mark.parametrize("kind,sort_by", [("user", "impacted_users_count"), ("device", "impacted_devices_count")])
@pytest.mark.parametrize("order", ["asc", "desc"])
async def test_retained_member_sorting_pages_cutoff_and_uuid_ties(evidence_sessions, monkeypatch, kind, sort_by, order):
    from shadai.api.detections import list_detections

    now, config = datetime.now(UTC), get_config()
    config.retention.identity_days = 1
    cutoff = now - timedelta(days=1)
    async with evidence_sessions.begin() as session:
        for index, retained in enumerate((2, 1, 2, 0), start=1):
            detection = Correlator(None)._create_detection(
                observation(timestamp=now), item(str(index)), "process_name", 0.9, now, now, None
            )
            detection.detection_id = UUID(int=index)
            detection.impacted_users_count = detection.impacted_devices_count = 100 - index
            session.add(detection)
            await session.flush()
            for member in range(retained + 1):
                session.add(
                    EvidenceIdentityORM(
                        detection_id=detection.detection_id,
                        kind=kind,
                        identity_digest=keyed_identity(kind, str(member)),
                        last_seen_at=cutoff if member < retained else cutoff - timedelta(microseconds=1),
                    )
                )

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("shadai.api.detections.datetime", Clock)
    returned = []
    async with evidence_sessions() as session:
        for page in (1, 2):
            response = await list_detections(
                sort_by=sort_by,
                sort_order=order,
                page=page,
                page_size=2,
                _user=SimpleNamespace(role="analyst"),
                session=session,
            )
            assert response.total == 4
            returned.extend(response.items)
        assert not session.dirty
    assert [row.detection_id.int for row in returned] == ([4, 2, 1, 3] if order == "asc" else [1, 3, 2, 4])
    assert [getattr(row, sort_by) for row in returned] == ([0, 1, 2, 2] if order == "asc" else [2, 2, 1, 0])


class HistoricalClickHouse:
    """Answers the scrub's statements and pins that each one names exactly the personal columns."""

    def __init__(self, count=1, *, complete=True, failure=False):
        self.ids = [str(uuid4()) for _ in range(count)]
        self.complete, self.failure, self.calls = complete, failure, []

    def execute(self, query, params, **kwargs):
        self.calls.append((query, params, kwargs))
        if query.startswith("ALTER"):
            if self.failure:
                raise RuntimeError("mutation failure")
            assert kwargs["settings"] == {"mutations_sync": 2}
            assignments = query.split(" UPDATE ", 1)[1].split(" WHERE ", 1)[0].split(", ")
            assert assignments == [f"{name} = ''" for name in PERSONAL_EVENT_COLUMNS]
            if self.complete:
                self.ids = [identifier for identifier in self.ids if identifier not in params["ids"]]
            return []
        # Selection and verification use one predicate over the same columns the mutation blanks.
        predicate = re.search(r"AND \((.*?)\)", query).group(1).split(" OR ")
        assert predicate == [f"{name} != ''" for name in PERSONAL_EVENT_COLUMNS]
        if query.startswith("SELECT DISTINCT"):
            return [(identifier,) for identifier in self.ids[: params["limit"]]]
        selected = [identifier for identifier in self.ids if "ids" not in params or identifier in params["ids"]]
        return [(len(selected),)]


async def test_historical_cleanup_is_bounded_resumable_idempotent_and_preserves_console_receipts(evidence_sessions):
    sessions, now = evidence_sessions, datetime.now(UTC)
    ids = []
    async with sessions.begin() as session:
        user = UserORM(username="Console Alice", password_hash="!", role="admin")
        session.add(user)
        for index in range(2):
            detection = Correlator(None)._create_detection(
                observation(user_id="Alice", username="Alice", timestamp=now),
                item(str(index)),
                "username",
                0.9,
                now,
                now,
                None,
            )
            session.add(detection)
            await session.flush()
            ids.append(detection.detection_id)
            session.add(
                EvidenceIdentityORM(
                    detection_id=detection.detection_id,
                    kind="user",
                    identity_digest=keyed_identity("user", "Alice"),
                    last_seen_at=now,
                )
            )
        session.add_all(
            [IngestReceiptORM(event_id=uuid4()), CorrelationReceiptORM(event_id=uuid4(), catalog_item_id="old")]
        )
        # Installation rows name the host, the user (or none for a wire v1 row) and the profile.
        alice = installation(key="a" * 64, user_label="Alice")
        host = installation(key="h" * 64, user_label=None, user_digest=None, wire_version=1, install_source="")
        session.add_all([alice, host])
        await session.flush()
        session.add(version_change(alice))
    ch = HistoricalClickHouse(2)
    first = await scrub_personal_history(get_config(), sessions, ch, batch_size=1, max_batches=1)
    assert first["complete"] is False and first["clickhouse_complete"] is False and first["next_detection_id"]
    assert first["inventory_rows_scrubbed"] == 2
    second = await scrub_personal_history(
        get_config(), sessions, ch, batch_size=1, max_batches=1, after_detection_id=UUID(first["next_detection_id"])
    )
    assert second["complete"] is True and second["inventory_rows_scrubbed"] == 0
    repeated = await scrub_personal_history(get_config(), sessions, ch, batch_size=2, max_batches=2)
    assert repeated["complete"] is True
    # The ClickHouse scrub blanks the profile directory name along with the identifiers.
    assert "browser_profile != ''" in ch.calls[0][0]
    assert "browser_profile = ''" in next(query for query, _, _ in ch.calls if query.startswith("ALTER"))
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(EvidenceIdentityORM)) == 0
        for table in (ExtensionInventoryORM, ExtensionVersionChangeORM):
            assert await session.scalar(select(func.count()).select_from(table)) == 0
        assert await session.scalar(select(func.count()).select_from(IngestReceiptORM)) == 1
        assert await session.scalar(select(func.count()).select_from(CorrelationReceiptORM)) == 1
        assert (await session.get(UserORM, user.user_id)).username == "Console Alice"
        for identifier in ids:
            detection = await session.get(DetectionORM, identifier)
            assert "Alice" not in json.dumps(detection.evidence_bundle) and detection.primary_evidence is None


def test_personal_event_columns_cover_identity_fields_and_the_browser_profile():
    assert set(PERSONAL_EVENT_COLUMNS) == {*IDENTITY_FIELDS, "src_ip", "browser_profile"}
    event = CanonicalEvent(
        tenant_id="test-org", source_type="browser", username="Alice", browser_profile="Profile 1", src_ip="192.0.2.10"
    )
    columns = event.to_clickhouse_dict()
    # Every scrubbed column is a text column of the events table, so blanking it to '' is valid.
    assert all(isinstance(columns[name], str) for name in PERSONAL_EVENT_COLUMNS)
    assert "browser_profile" in Path("migrations/clickhouse/003_extension_inventory.sql").read_text()


class ResumedInventoryWriter:
    """A writer that was not quiesced: it stores an installation once the scrub has emptied the tables."""

    def __init__(self, sessions):
        self.sessions, self.written = sessions, False

    def __call__(self):
        return self.sessions()

    @asynccontextmanager
    async def begin(self):
        async with self.sessions.begin() as session:
            yield session
        if not self.written:
            self.written = True
            async with self.sessions.begin() as session:
                session.add(installation())


async def test_an_installation_stored_after_the_inventory_scrub_denies_completion(evidence_sessions):
    result = await scrub_personal_history(
        get_config(), ResumedInventoryWriter(evidence_sessions), HistoricalClickHouse(0)
    )
    assert result["clickhouse_complete"] is True and result["inventory_rows_scrubbed"] == 0
    assert result["sql_complete"] is False and result["complete"] is False and result["next_detection_id"] is None
    async with evidence_sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ExtensionInventoryORM)) == 1
    again = await scrub_personal_history(get_config(), evidence_sessions, HistoricalClickHouse(0))
    assert again["complete"] is True and again["inventory_rows_scrubbed"] == 1


@pytest.mark.parametrize("failure", [False, True])
async def test_incomplete_or_failed_ch_mutation_never_claims_cleanup(evidence_sessions, failure):
    with pytest.raises(RuntimeError):
        await scrub_personal_history(
            get_config(), evidence_sessions, HistoricalClickHouse(complete=False, failure=failure)
        )


async def test_actual_identity_migration_clears_unaged_legacy_without_invented_dates(evidence_sessions):
    now = datetime.now(UTC)
    async with evidence_sessions.begin() as session:
        detection = Correlator(None)._create_detection(
            observation(timestamp=now), item(), "process_name", 0.9, now, now, None
        )
        detection.evidence_bundle = {"_users": ["Alice"], "endpoint": {"sample_values": ["Alice"]}}
        detection.impacted_users_count = 10
        session.add(detection)
    spec = importlib.util.spec_from_file_location(
        "identity_migration", Path("migrations/versions/005_evidence_identity_retention.py")
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    async with evidence_sessions.kw["bind"].begin() as connection:

        def upgrade(conn):
            EvidenceIdentityORM.__table__.drop(conn)
            with Operations.context(MigrationContext.configure(conn)):
                migration.upgrade()

        await connection.run_sync(upgrade)
    async with evidence_sessions() as session:
        result = await session.get(DetectionORM, detection.detection_id)
        assert result.impacted_users_count == 0 and "Alice" not in json.dumps(result.evidence_bundle)
        assert await session.scalar(select(func.count()).select_from(EvidenceIdentityORM)) == 0


def installation(key="a" * 64, now=datetime(2026, 10, 6, 12, tzinfo=UTC), **state):
    values = {
        "inventory_key": key,
        "device_digest": "d" * 64,
        "user_digest": "u" * 64,
        "host_label": "p1_" + "h" * 61,
        "user_label": "p1_" + "u" * 61,
        "browser": "chrome",
        "profile": "Profile 1",
        "extension_id": "abcdefghijklmnopabcdefghijklmnop",
        "extension_name": "Sider",
        "version": "1.0.0",
        "enabled": True,
        "install_source": "store",
        "installed_at": now - timedelta(days=3),
        "first_seen_at": now - timedelta(days=1),
        "last_seen_at": now,
        "catalog_item_id": "sider",
        "collector_id": "sensor",
        "identity_basis": "b" * 64,
        "last_event_id": uuid4(),
        "wire_version": 2,
    }
    values.update(state)
    return ExtensionInventoryORM(**values)


def version_change(row, event_id=None, **state):
    values = {
        "inventory_key": row.inventory_key,
        "event_id": event_id or uuid4(),
        "extension_id": row.extension_id,
        "extension_name": row.extension_name,
        "browser": row.browser,
        "host_label": row.host_label,
        "user_label": row.user_label,
        "profile": row.profile,
        "from_version": "0.9.0",
        "to_version": row.version,
        "previous_observed_at": row.first_seen_at,
        "observed_at": row.last_seen_at,
        "catalog_item_id": row.catalog_item_id,
    }
    values.update(state)
    return ExtensionVersionChangeORM(**values)


def inventory_schema(conn):
    inspector = inspect(conn)
    return {
        name: {
            "columns": {column["name"]: column["nullable"] for column in inspector.get_columns(name)},
            "indexes": {index["name"]: list(index["column_names"]) for index in inspector.get_indexes(name)},
            "foreign_keys": inspector.get_foreign_keys(name),
            "checks": {check["name"]: check["sqltext"] for check in inspector.get_check_constraints(name)},
            "unique": {unique["name"]: unique["column_names"] for unique in inspector.get_unique_constraints(name)},
        }
        for name in inspector.get_table_names()
        if name.startswith("extension_")
    }


async def test_extension_inventory_migration_matches_the_orm_and_drops_cleanly(evidence_sessions):
    spec = importlib.util.spec_from_file_location(
        "inventory_migration", Path("migrations/versions/006_extension_inventory.py")
    )
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert (migration.revision, migration.down_revision) == ("006_extension_inventory", "005_evidence_identity")
    assert ScriptDirectory.from_config(Config("alembic.ini")).get_current_head() == "006_extension_inventory"
    assert tuple(migration.INSTALL_SOURCES) == INVENTORY_INSTALL_SOURCES
    assert set(INVENTORY_INSTALL_SOURCES) == {
        "", "store", "user", "unpacked", "external", "policy", "component", "orphan", "unknown"
    }
    engine = evidence_sessions.kw["bind"]

    def run(conn, operation):
        with Operations.context(MigrationContext.configure(conn)):
            operation()

    def upgrade(conn):
        ExtensionVersionChangeORM.__table__.drop(conn)
        ExtensionInventoryORM.__table__.drop(conn)
        run(conn, migration.upgrade)

    async with engine.begin() as connection:
        await connection.run_sync(upgrade)
        schema = await connection.run_sync(inventory_schema)
    assert set(schema) == {"extension_inventory", "extension_version_changes"}
    for orm in (ExtensionInventoryORM, ExtensionVersionChangeORM):
        table = orm.__table__
        migrated = schema[table.name]
        assert migrated["columns"] == {column.name: column.nullable for column in table.columns}
        assert migrated["indexes"] == {index.name: [column.name for column in index.columns] for index in table.indexes}
    inventory, changes = schema["extension_inventory"], schema["extension_version_changes"]
    assert inventory["checks"] == {"valid_extension_install_source": migration.INSTALL_SOURCE_CHECK}
    assert inventory["indexes"]["idx_extension_inventory_last_seen"] == ["last_seen_at"]
    assert changes["unique"] == {"uq_extension_version_change_event": ["event_id"]}
    assert changes["indexes"]["idx_extension_version_changes_installation"] == ["inventory_key", "observed_at"]
    [foreign_key] = changes["foreign_keys"]
    assert foreign_key["referred_table"] == "extension_inventory"
    assert foreign_key["constrained_columns"] == ["inventory_key"]
    assert foreign_key["options"].get("ondelete", "").upper() == "CASCADE"
    # The ORM round-trips through the migrated schema, so every mapped column exists with a compatible type.
    row, event_id = installation(), uuid4()
    async with evidence_sessions.begin() as session:
        session.add(row)
        await session.flush()
        session.add(version_change(row, event_id))
    async with evidence_sessions() as session:
        stored = await session.get(ExtensionInventoryORM, row.inventory_key)
        state = (stored.version, stored.enabled, stored.install_source, stored.wire_version)
        assert state == ("1.0.0", True, "store", 2)
        assert stored.last_event_id == row.last_event_id and stored.user_digest == "u" * 64
        read = ExtensionInventoryRead.model_validate(stored)
        assert read.present_in_latest_snapshot is True and read.detection_id is None
        [change] = (await session.scalars(select(ExtensionVersionChangeORM))).all()
        assert ExtensionVersionChangeRead.model_validate(change).event_id == event_id
        assert (change.from_version, change.to_version) == ("0.9.0", "1.0.0")
        # Agent retries carry the same event id: a change is recorded once.
        session.add(version_change(row, event_id))
        with pytest.raises(IntegrityError):
            await session.flush()
    async with evidence_sessions() as session:
        session.add(installation(key="m" * 64, install_source="magic"))
        with pytest.raises(IntegrityError):
            await session.flush()
    async with evidence_sessions.begin() as session:
        await session.execute(delete(ExtensionInventoryORM).where(ExtensionInventoryORM.inventory_key == "a" * 64))
    async with evidence_sessions() as session:
        assert await session.scalar(select(func.count()).select_from(ExtensionVersionChangeORM)) == 0
    async with engine.begin() as connection:
        await connection.run_sync(run, migration.downgrade)
        assert await connection.run_sync(inventory_schema) == {}


def test_extension_inventory_read_models_expose_labels_and_the_identity_window_only():
    row = installation(user_label=None, user_digest=None, wire_version=1, install_source="")
    read = ExtensionInventoryRead.model_validate(row)
    assert read.user_label is None and read.install_source == "" and read.wire_version == 1
    assert read.host_label == row.host_label and read.last_event_id == row.last_event_id
    # Keyed digests and the membership basis stay inside PostgreSQL.
    exposed = set(ExtensionInventoryRead.model_fields) | set(ExtensionVersionChangeRead.model_fields)
    assert exposed.isdisjoint({"device_digest", "user_digest", "identity_basis"})
    with pytest.raises(ValueError):
        ExtensionInventoryRead.model_validate(installation(install_source="magic"))
    response = ExtensionInventoryListResponse(
        items=[read],
        total=1,
        page=1,
        page_size=25,
        identity_window={"days": 30, "as_of": datetime(2026, 10, 6, 12, tzinfo=UTC)},
        identity_mode="pseudonymized",
    )
    assert response.identity_window.days == 30
    with pytest.raises(ValueError):
        ExtensionInventoryListResponse.model_validate({**response.model_dump(), "identity_window": None})
    with pytest.raises(ValueError):
        ExtensionInventoryListResponse.model_validate({**response.model_dump(), "identity_mode": "plain"})


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("SHADAI_INTEGRATION") != "1", reason="Disposable PostgreSQL services not requested")
async def test_live_identity_membership_migration_and_concurrent_retention():
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True, text=True)
    config, name = get_config(), "identity-live-" + uuid4().hex
    engine = create_async_engine(config.database.postgres_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    correlator, now = Correlator(sessions), datetime.now(UTC)
    events = [
        CanonicalEvent(
            tenant_id=config.tenant_id,
            user_id=f"User-{index}",
            collector_id=name,
            timestamp=now,
            domain="service.example",
        )
        for index in range(12)
    ]
    try:
        await asyncio.gather(*(correlator.upsert_detection(event, item(name), "domain", 0.9) for event in events))
        await maintain_personal_evidence(
            config, sessions, now=now + timedelta(days=config.retention.identity_days, microseconds=1), batch_size=1
        )
        async with sessions() as session:
            detection = (
                await session.execute(select(DetectionORM).where(DetectionORM.catalog_item_id == name))
            ).scalar_one()
            assert detection.impacted_users_count == 0
            assert (
                await session.scalar(
                    select(func.count())
                    .select_from(EvidenceIdentityORM)
                    .where(EvidenceIdentityORM.detection_id == detection.detection_id)
                )
                == 0
            )
            assert detection.total_events_count == 12
    finally:
        async with sessions.begin() as session:
            await session.execute(delete(DetectionORM).where(DetectionORM.catalog_item_id == name))
            await session.execute(delete(CorrelationReceiptORM).where(CorrelationReceiptORM.catalog_item_id == name))
        await engine.dispose()
