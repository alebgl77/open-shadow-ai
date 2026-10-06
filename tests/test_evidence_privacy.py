"""Personal evidence ages independently of service activity and delivery retries."""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from cryptography.fernet import Fernet
from sqlalchemy import JSON, delete, func, select
from sqlalchemy import event as sqlalchemy_event
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
from shadai.models.governance import GovernanceORM
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM
from shadai.models.user import UserORM
from shadai.utils.privacy import keyed_identity, refresh_identity_counts, sanitize_evidence
from shadai.workers.purge import maintain_personal_evidence, scrub_personal_history


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
    def __init__(self, count=1, *, complete=True, failure=False):
        self.ids = [str(uuid4()) for _ in range(count)]
        self.complete, self.failure, self.calls = complete, failure, []

    def execute(self, query, params, **kwargs):
        self.calls.append((query, params, kwargs))
        if query.startswith("ALTER"):
            if self.failure:
                raise RuntimeError("mutation failure")
            assert kwargs["settings"] == {"mutations_sync": 2}
            if self.complete:
                self.ids = [identifier for identifier in self.ids if identifier not in params["ids"]]
            return []
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
    ch = HistoricalClickHouse(2)
    first = await scrub_personal_history(get_config(), sessions, ch, batch_size=1, max_batches=1)
    assert first["complete"] is False and first["clickhouse_complete"] is False and first["next_detection_id"]
    second = await scrub_personal_history(
        get_config(), sessions, ch, batch_size=1, max_batches=1, after_detection_id=UUID(first["next_detection_id"])
    )
    assert second["complete"] is True
    repeated = await scrub_personal_history(get_config(), sessions, ch, batch_size=2, max_batches=2)
    assert repeated["complete"] is True
    async with sessions() as session:
        assert await session.scalar(select(func.count()).select_from(EvidenceIdentityORM)) == 0
        assert await session.scalar(select(func.count()).select_from(IngestReceiptORM)) == 1
        assert await session.scalar(select(func.count()).select_from(CorrelationReceiptORM)) == 1
        assert (await session.get(UserORM, user.user_id)).username == "Console Alice"
        for identifier in ids:
            detection = await session.get(DetectionORM, identifier)
            assert "Alice" not in json.dumps(detection.evidence_bundle) and detection.primary_evidence is None


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
