"""Transactional collector identity, scoped ingress, rotation and truthful liveness."""

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from queue_fakes import admission_fake
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from shadai.api import collectors
from shadai.api.ingestion import prepare_event
from shadai.config import RetentionSettings, get_config, validate_security
from shadai.database import get_postgres_session
from shadai.models.audit import AuditLogORM
from shadai.models.base import Base
from shadai.models.collector import CollectorCredentialORM, CollectorORM
from shadai.models.event import CanonicalEvent
from shadai.security.auth import get_current_user


@pytest.fixture
async def collector_console(tmp_path, monkeypatch, identity_sessions):
    # identity_sessions installs SQLite JSONB/UUID compilers; use its real transactions.
    sessions = identity_sessions
    async with sessions().bind.begin() as connection:
        await connection.run_sync(
            lambda conn: Base.metadata.create_all(
                conn, tables=[CollectorORM.__table__, CollectorCredentialORM.__table__]
            )
        )
    from shadai.main import app

    async def session_dependency():
        async with sessions() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    actor = SimpleNamespace(user_id=uuid4(), username="admin", role="admin")

    async def current_actor():
        return actor

    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_postgres_session] = session_dependency
    app.dependency_overrides[get_current_user] = current_actor
    monkeypatch.setattr(collectors, "postgres_session_factory", lambda: sessions)
    pipe = SimpleNamespace(xadd=Mock(), execute=AsyncMock())
    redis = admission_fake(SimpleNamespace(pipeline=Mock(return_value=pipe)), pipe)
    monkeypatch.setattr("shadai.api.ingestion.get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.api.agent.get_redis", AsyncMock(return_value=redis))
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="https://testserver"
    ) as client:
        yield SimpleNamespace(client=client, sessions=sessions, actor=actor, pipe=pipe)
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)


async def enroll(console, collector_id="sensor-1", sources=None):
    response = await console.client.post(
        "/api/v1/collectors",
        json={
            "collector_id": collector_id,
            "display_name": "Test sensor",
            "allowed_source_types": sources or ["dns"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def event(collector_id="sensor-1", source_type="dns", timestamp=None):
    return CanonicalEvent(
        collector_id=collector_id,
        source_type=source_type,
        tenant_id="test-org",
        domain="example.test",
        timestamp=timestamp or datetime.now(UTC),
    ).model_dump(mode="json")


async def config_response(console, token):
    return await console.client.get("/api/v1/agent/config", headers={"X-API-Key": token})


async def test_enrollment_hash_only_secret_once_inventory_and_transactional_audit(collector_console):
    console = collector_console
    body = await enroll(console)
    token = body["api_key"]
    public_id, secret = token.removeprefix("sc_").split(".")
    assert len(secret) == 43
    async with console.sessions() as session:
        credential = await session.get(CollectorCredentialORM, UUID(hex=public_id))
        assert credential.secret_digest == sha256(secret.encode()).hexdigest()
        assert secret not in str(credential.__dict__)
        audit = (await session.execute(select(AuditLogORM))).scalar_one()
        assert audit.action == "enroll_collector" and audit.resource_id == "sensor-1"
        assert secret not in str(audit.details)
    inventory = await console.client.get("/api/v1/collectors")
    assert inventory.status_code == 200 and inventory.json()["total"] == 1
    assert inventory.json()["items"][0]["status"] == "unknown"
    assert token not in inventory.text and secret not in inventory.text and "digest" not in inventory.text
    duplicate = await console.client.post(
        "/api/v1/collectors",
        json={
            "collector_id": "sensor-1",
            "display_name": "Again",
            "allowed_source_types": ["endpoint"],
        },
    )
    assert duplicate.status_code == 409


@pytest.mark.parametrize("role", ["viewer", "analyst"])
async def test_lifecycle_requires_admin(collector_console, role):
    console = collector_console
    await enroll(console)
    console.actor.role = role
    for method, path, kwargs in (
        ("GET", "/api/v1/collectors", {}),
        (
            "POST",
            "/api/v1/collectors",
            {"json": {"collector_id": "new", "display_name": "x", "allowed_source_types": ["dns"]}},
        ),
        ("POST", "/api/v1/collectors/sensor-1/rotate", {"json": {}}),
        ("POST", "/api/v1/collectors/sensor-1/revoke", {}),
    ):
        assert (await console.client.request(method, path, **kwargs)).status_code == 403


@pytest.mark.parametrize("failure", ["audit", "commit"])
async def test_no_credential_or_secret_response_on_failed_transaction(collector_console, monkeypatch, failure):
    console = collector_console
    if failure == "audit":

        async def fail(*args, **kwargs):
            raise RuntimeError("audit unavailable")

        monkeypatch.setattr(collectors, "lifecycle_audit", fail)
    else:

        async def fail(self):
            raise RuntimeError("commit unavailable")

        monkeypatch.setattr(AsyncSession, "commit", fail)
    response = await console.client.post(
        "/api/v1/collectors",
        json={
            "collector_id": "never-committed",
            "display_name": "x",
            "allowed_source_types": ["dns"],
        },
    )
    assert response.status_code == 500 and "api_key" not in response.text
    async with console.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(CollectorORM)) == 0
        assert await session.scalar(select(func.count()).select_from(CollectorCredentialORM)) == 0
        assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 0


@pytest.mark.parametrize("state", ["inactive", "revoked", "expired", "credential_revoked", "foreign_tenant"])
async def test_scoped_auth_rechecks_current_state_on_every_request(collector_console, state):
    console = collector_console
    body = await enroll(console)
    assert (await config_response(console, body["api_key"])).status_code == 200
    async with console.sessions.begin() as session:
        collector = await session.get(CollectorORM, "sensor-1")
        credential = await session.get(CollectorCredentialORM, UUID(body["credential_id"]))
        if state == "inactive":
            collector.is_active = False
        elif state == "revoked":
            collector.revoked_at = datetime.now(UTC)
        elif state == "expired":
            credential.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        elif state == "credential_revoked":
            credential.revoked_at = datetime.now(UTC)
        else:
            collector.tenant_id = "another-org"
    assert (await config_response(console, body["api_key"])).status_code == 401


async def test_missing_wrong_malformed_and_bounded_tokens(collector_console):
    console = collector_console
    body = await enroll(console)
    token = body["api_key"]
    assert (await console.client.get("/api/v1/agent/config")).status_code == 401
    for invalid in (
        "",
        "wrong",
        "sc_bad",
        "x" * 4097,
        token[:-1] + ("A" if token[-1] != "A" else "B"),
        "sc_" + "0" * 32 + "." + "x" * 43,
    ):
        assert (await config_response(console, invalid)).status_code == 401


async def test_source_and_identity_scope_batch_atomicity(collector_console):
    console = collector_console
    body = await enroll(console)
    headers = {"X-API-Key": body["api_key"]}
    valid = event()
    for invalid in (event("sensor-2"), event(source_type="endpoint")):
        response = await console.client.post(
            "/api/v1/ingest/events", json={"events": [valid, invalid]}, headers=headers
        )
        assert response.status_code == 403
        console.pipe.xadd.assert_not_called()
    response = await console.client.post("/api/v1/ingest/events", json={"events": [valid]}, headers=headers)
    assert response.status_code == 202
    fields = console.pipe.xadd.call_args.args[1]
    assert json.loads(fields["data"])["collector_id"] == "sensor-1"
    assert "accepted_at" in fields and "accepted_at" not in json.loads(fields["data"])
    console.pipe.xadd.reset_mock()
    foreign = event() | {"tenant_id": "elsewhere"}
    assert (
        await console.client.post("/api/v1/ingest/events", json={"events": [foreign]}, headers=headers)
    ).status_code == 422
    console.pipe.xadd.assert_not_called()


async def test_rotation_overlap_deadline_never_extends_and_individual_revocation(collector_console):
    console = collector_console
    first = await enroll(console)
    other = await enroll(console, "sensor-2")
    response = await console.client.post("/api/v1/collectors/sensor-1/rotate", json={"overlap_seconds": 60})
    assert response.status_code == 200
    second = response.json()
    assert (await config_response(console, first["api_key"])).status_code == 200
    assert (await config_response(console, second["api_key"])).status_code == 200
    async with console.sessions.begin() as session:
        old = await session.get(CollectorCredentialORM, UUID(first["credential_id"]))
        old_deadline = old.expires_at
    third = (await console.client.post("/api/v1/collectors/sensor-1/rotate", json={"overlap_seconds": 86400})).json()
    async with console.sessions.begin() as session:
        old = await session.get(CollectorCredentialORM, UUID(first["credential_id"]))
        assert old.expires_at == old_deadline
        old.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert (await config_response(console, first["api_key"])).status_code == 401
    assert (await config_response(console, third["api_key"])).status_code == 200
    assert (await console.client.post("/api/v1/collectors/sensor-1/revoke")).status_code == 200
    for token in (second["api_key"], third["api_key"]):
        assert (await config_response(console, token)).status_code == 401
    assert (await config_response(console, other["api_key"])).status_code == 200
    assert (await console.client.post("/api/v1/collectors/sensor-1/rotate", json={})).status_code == 409


async def test_immediate_rotation_and_invalid_scope_limits(collector_console):
    console = collector_console
    first = await enroll(console)
    rotated = await console.client.post("/api/v1/collectors/sensor-1/rotate", json={"overlap_seconds": 0})
    assert rotated.status_code == 200
    assert (await config_response(console, first["api_key"])).status_code == 401
    assert (await config_response(console, rotated.json()["api_key"])).status_code == 200
    for overlap in (-1, 86401, True, "60"):
        assert (
            await console.client.post("/api/v1/collectors/sensor-1/rotate", json={"overlap_seconds": overlap})
        ).status_code == 422
    for sources in ([], ["DNS"], ["dns", "dns"], ["admin"]):
        response = await console.client.post(
            "/api/v1/collectors",
            json={
                "collector_id": "new",
                "display_name": "x",
                "allowed_source_types": sources,
            },
        )
        assert response.status_code == 422
    for query in ("limit=501", "limit=0", "offset=-1", "offset=1000001"):
        assert (await console.client.get("/api/v1/collectors?" + query)).status_code == 422


async def test_legacy_is_unattributed_cannot_spoof_heartbeat_and_can_be_disabled(collector_console):
    console = collector_console
    await enroll(console)
    config = get_config()
    headers = {"X-API-Key": config.security.agent_api_key}
    response = await console.client.post("/api/v1/ingest/events", json={"events": [event()]}, headers=headers)
    assert response.status_code == 202
    assert json.loads(console.pipe.xadd.call_args.args[1]["data"])["collector_id"] == "legacy:unattributed"
    heartbeat = {"collector_id": "sensor-1", "client_version": "1.0"}
    assert (await console.client.post("/api/v1/agent/heartbeat", json=heartbeat, headers=headers)).status_code == 403
    config.security.agent_api_key = "sc_legacy-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert (await config_response(console, config.security.agent_api_key)).status_code == 200
    config.security.allow_legacy_agent_key = False
    assert (await config_response(console, config.security.agent_api_key)).status_code == 401
    config.security.agent_api_key = ""
    validate_security(config)
    assert (await config_response(console, (await enroll(console, "sensor-2"))["api_key"])).status_code == 200


async def test_browser_only_telemetry_enforces_its_actual_canonical_source(collector_console):
    console = collector_console
    browser = await enroll(console, "browser-only", ["browser"])
    headers = {"X-API-Key": browser["api_key"]}
    snapshot = {
        "hostname": "ws-001",
        "timestamp": datetime.now(UTC).isoformat(),
        "extensions": [{"id": "extension", "name": "AI helper", "browser": "chrome"}],
    }
    assert (await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers=headers)).status_code == 200
    assert console.pipe.xadd.call_args.args[0] == "events:browser"
    console.pipe.xadd.reset_mock()
    snapshot["processes"] = [{"name": "ollama"}]
    assert (await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers=headers)).status_code == 403
    console.pipe.xadd.assert_not_called()


async def test_scoped_client_uuids_are_isolated_and_stable_through_rotation(collector_console):
    console = collector_console
    first, second = await enroll(console), await enroll(console, "sensor-2")
    source = event()
    identifiers = []
    for collector_id, credential in (("sensor-1", first), ("sensor-2", second)):
        response = await console.client.post(
            "/api/v1/ingest/events",
            json={"events": [source | {"collector_id": collector_id}]},
            headers={"X-API-Key": credential["api_key"]},
        )
        assert response.status_code == 202
        identifiers.append(json.loads(console.pipe.xadd.call_args.args[1]["data"])["event_id"])
    assert identifiers[0] != identifiers[1] and source["event_id"] not in identifiers
    rotated = (await console.client.post("/api/v1/collectors/sensor-1/rotate", json={"overlap_seconds": 0})).json()
    response = await console.client.post(
        "/api/v1/ingest/events",
        json={"events": [source]},
        headers={"X-API-Key": rotated["api_key"]},
    )
    assert response.status_code == 202
    assert json.loads(console.pipe.xadd.call_args.args[1]["data"])["event_id"] == identifiers[0]
    legacy = await console.client.post(
        "/api/v1/ingest/events",
        json={"events": [source]},
        headers={"X-API-Key": get_config().security.agent_api_key},
    )
    assert legacy.status_code == 202
    assert json.loads(console.pipe.xadd.call_args.args[1]["data"])["event_id"] == source["event_id"]


async def test_endpoint_uuid_stays_stable_across_privacy_and_key_changes(collector_console):
    from cryptography.fernet import Fernet

    console = collector_console
    credential = await enroll(console, sources=["endpoint"])
    config = await config_response(console, credential["api_key"])
    assert config.json()["collector_id"] == "sensor-1" and config.json()["legacy"] is False
    assert config.json()["allowed_source_types"] == ["endpoint"]
    assert config.json()["ingestion_max_age_days"] == get_config().retention.ingestion_max_age_days
    assert credential["api_key"] not in config.text
    snapshot = {
        "hostname": "Alice-device",
        "timestamp": datetime.now(UTC).isoformat(),
        "processes": [{"name": "ollama", "username": "Alice"}],
    }
    identifiers = []
    for mode, key in ((False, None), (True, None), (True, Fernet.generate_key().decode())):
        get_config().security.pseudonymize_identities = mode
        if key is not None:
            get_config().security.encryption_key = key
        response = await console.client.post(
            "/api/v1/agent/telemetry",
            json=snapshot,
            headers={"X-API-Key": credential["api_key"]},
        )
        assert response.status_code == 200
        payload = json.loads(console.pipe.xadd.call_args.args[1]["data"])
        identifiers.append(payload["event_id"])
        if mode:
            assert "Alice" not in json.dumps(payload)
    assert len(set(identifiers)) == 1


async def test_heartbeat_uses_server_clock_and_separates_stale_observation(collector_console):
    console = collector_console
    body = await enroll(console)
    headers = {"X-API-Key": body["api_key"]}
    past = datetime.now(UTC) - timedelta(days=1)
    assert (
        await console.client.post("/api/v1/ingest/events", json={"events": [event(timestamp=past)]}, headers=headers)
    ).status_code == 202
    heartbeat = {
        "collector_id": "sensor-1",
        "client_version": "1.0",
        "queue_events": 12,
        "queued_bytes": 300,
        "last_success_at": past.isoformat(),
    }
    before = datetime.now(UTC)
    response = await console.client.post("/api/v1/agent/heartbeat", json=heartbeat, headers=headers)
    assert response.status_code == 200
    received = datetime.fromisoformat(response.json()["received_at"])
    assert before <= received <= datetime.now(UTC)
    row = (await console.client.get("/api/v1/collectors")).json()["items"][0]
    assert row["status"] == "replay_or_quiet"
    assert datetime.fromisoformat(row["last_observed_at"]).replace(tzinfo=UTC) == past
    assert row["client_counters"]["queue_events"] == 12
    for invalid in (
        {"collector_id": "sensor-2"},
        {"queue_events": -1},
        {"queue_events": True},
        {"queued_bytes": 10**15 + 1},
        {"last_success_at": (datetime.now(UTC) + timedelta(days=2)).isoformat()},
        {"last_success_at": "2026-10-01T12:00:00"},
        {"api_key": "never-store"},
    ):
        rejected = await console.client.post("/api/v1/agent/heartbeat", json=heartbeat | invalid, headers=headers)
        assert rejected.status_code in {403, 422}
    row_after = (await console.client.get("/api/v1/collectors")).json()["items"][0]
    assert row_after["last_heartbeat_at"] == row["last_heartbeat_at"]


async def test_endpoint_empty_snapshot_contact_scope_stable_retry_uuid_and_failed_enqueue(collector_console):
    console = collector_console
    body = await enroll(console, sources=["endpoint", "browser"])
    headers = {"X-API-Key": body["api_key"]}
    snapshot = {"hostname": "ws-001", "timestamp": datetime.now(UTC).isoformat()}
    response = await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers=headers)
    assert response.status_code == 200 and response.json()["received"] == 0
    row = (await console.client.get("/api/v1/collectors")).json()["items"][0]
    assert row["last_contact_at"] is not None and row["last_observed_at"] is None and row["status"] == "quiet"
    snapshot["processes"] = [{"name": "ollama", "path": "private-path"}]
    payloads = []
    for _ in range(2):
        assert (await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers=headers)).status_code == 200
        payloads.append(console.pipe.xadd.call_args.args[1])
    assert payloads[0]["data"] == payloads[1]["data"]
    assert payloads[0]["accepted_at"] != payloads[1]["accepted_at"]
    assert json.loads(payloads[0]["data"])["collector_id"] == "sensor-1"
    previous = (await console.client.get("/api/v1/collectors")).json()["items"][0]["last_contact_at"]
    console.pipe.execute.side_effect = RuntimeError("redis unavailable")
    response = await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers=headers)
    assert response.status_code == 503 and response.headers["Retry-After"] == "5"
    assert (await console.client.get("/api/v1/collectors")).json()["items"][0]["last_contact_at"] == previous
    dns = await enroll(console, "dns-only")
    assert (
        await console.client.post("/api/v1/agent/telemetry", json=snapshot, headers={"X-API-Key": dns["api_key"]})
    ).status_code == 403


def test_internal_acceptance_replay_keeps_boundary_age_checks():
    accepted = datetime.now(UTC) - timedelta(days=10)
    old = accepted - timedelta(days=get_config().retention.ingestion_max_age_days - 1)
    with pytest.raises(ValueError):
        prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=old))
    assert prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=old), accepted_at=accepted).timestamp == old
    for invalid in (accepted.replace(tzinfo=None), datetime.now(UTC) + timedelta(minutes=6)):
        with pytest.raises(ValueError):
            prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=old), accepted_at=invalid)
    for timestamp in (accepted - timedelta(days=91), accepted + timedelta(minutes=6)):
        with pytest.raises(ValueError):
            prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=timestamp), accepted_at=accepted)


def test_identity_retention_compatible_bounds_and_config_legacy_off(monkeypatch):
    assert RetentionSettings(events_days=7).identity_days == 7
    assert RetentionSettings().identity_days == 30
    with pytest.raises(ValueError):
        RetentionSettings(events_days=7, identity_days=8)
    monkeypatch.setenv("ALLOW_LEGACY_AGENT_KEY", "false")
    monkeypatch.setenv("AGENT_API_KEY", "")
    get_config.cache_clear()
    config = get_config()
    assert config.security.allow_legacy_agent_key is False
    validate_security(config)


@pytest.mark.integration
@pytest.mark.skipif(os.environ.get("SHADAI_INTEGRATION") != "1", reason="Disposable PostgreSQL services not requested")
async def test_live_collector_migration_rotation_revocation_locks_and_legacy_path(monkeypatch):
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True, text=True)
    config = get_config()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    collector_id = "integration-" + uuid4().hex
    actor = SimpleNamespace(user_id=uuid4(), username="collector-integration", role="admin")
    request = SimpleNamespace(client=None)
    monkeypatch.setattr(collectors, "postgres_session_factory", lambda: sessions)
    try:
        async with sessions() as session:
            enrollment = await collectors.enroll_collector(
                collectors.CollectorCreate(
                    collector_id=collector_id, display_name="Integration", allowed_source_types=["dns"]
                ),
                request,
                actor,
                session,
            )
        # A request holds the collector lock until accepted contact is committed.
        authenticated = collectors.authenticate_collector(enrollment["api_key"])
        principal = await anext(authenticated)
        rotated = asyncio.Event()

        async def rotate():
            async with sessions() as session:
                result = await collectors.rotate_collector(
                    collector_id, collectors.CollectorRotate(overlap_seconds=0), request, actor, session
                )
                rotated.set()
                return result

        rotation = asyncio.create_task(rotate())
        await asyncio.sleep(0.1)
        assert not rotated.is_set()
        principal.contact()
        await authenticated.aclose()  # Cancelled requests roll back their unfinished contact.
        next_credential = await asyncio.wait_for(rotation, 10)
        old = collectors.authenticate_collector(enrollment["api_key"])
        with pytest.raises(HTTPException):
            await anext(old)
        fresh = collectors.authenticate_collector(next_credential["api_key"])
        await anext(fresh)
        revoke = asyncio.create_task(_live_revoke(sessions, collector_id, request, actor))
        await asyncio.sleep(0.1)
        assert not revoke.done()
        await fresh.aclose()
        await asyncio.wait_for(revoke, 10)
        final = collectors.authenticate_collector(next_credential["api_key"])
        with pytest.raises(HTTPException):
            await anext(final)
        if config.security.allow_legacy_agent_key:
            legacy = collectors.authenticate_collector(config.security.agent_api_key)
            assert (await anext(legacy)).legacy
            await legacy.aclose()
        async with sessions() as session:
            audits = (
                (await session.execute(select(AuditLogORM).where(AuditLogORM.resource_id == collector_id)))
                .scalars()
                .all()
            )
            assert [audit.action for audit in audits] == ["enroll_collector", "rotate_collector", "revoke_collector"]
    finally:
        async with sessions.begin() as session:
            await session.execute(
                delete(CollectorCredentialORM).where(CollectorCredentialORM.collector_id == collector_id)
            )
            await session.execute(delete(CollectorORM).where(CollectorORM.collector_id == collector_id))
            await session.execute(delete(AuditLogORM).where(AuditLogORM.resource_id == collector_id))
        await engine.dispose()


async def _live_revoke(sessions, collector_id, request, actor):
    async with sessions() as session:
        return await collectors.revoke_collector(collector_id, request, actor, session)
