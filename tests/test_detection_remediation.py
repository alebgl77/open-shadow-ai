import asyncio
from datetime import UTC, datetime
from threading import Event
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from clickhouse_driver import Client as ClickHouseClient
from fastapi import FastAPI, HTTPException
from sqlalchemy import JSON, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai import database
from shadai.api import detections
from shadai.database import SerializedClickHouseClient
from shadai.models.audit import AuditLogORM
from shadai.models.detection import DetectionORM
from shadai.models.user import UserORM
from shadai.security.auth import get_current_user


@pytest.fixture
async def note_console(identity_sessions, monkeypatch):
    # SQLite exercises real commit/rollback; PostgreSQL arrays are not needed by note writes.
    column = DetectionORM.__table__.c.source_types
    monkeypatch.setattr(column, "type", column.type.with_variant(JSON(), "sqlite"))
    async with identity_sessions.kw["bind"].begin() as connection:
        await connection.run_sync(DetectionORM.__table__.create)
    async with identity_sessions.begin() as session:
        analyst = UserORM(username="analyst", password_hash="!", role="analyst")
        detection = DetectionORM(
            entity_type="saas_app",
            entity_name="Example tool",
            catalog_item_id="example-tool",
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
            analyst_notes="Existing note",
        )
        session.add_all([analyst, detection])
    monkeypatch.setattr(database, "_async_session_factory", identity_sessions)
    app = FastAPI()
    app.include_router(detections.router)
    app.dependency_overrides[get_current_user] = lambda: analyst
    transport = httpx.ASGITransport(app, raise_app_exceptions=False, client=("192.0.2.10", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="https://example.test") as client:
        yield SimpleNamespace(client=client, sessions=identity_sessions, analyst=analyst, detection=detection)


async def test_note_and_safe_audit_commit_together(note_console):
    console = note_console
    response = await console.client.post(
        f"/api/v1/detections/{console.detection.detection_id}/notes", params={"note": "Sensitive review detail"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Note added"}
    async with console.sessions() as session:
        detection = await session.get(DetectionORM, console.detection.detection_id)
        assert detection.analyst_notes.startswith("Existing note\n[")
        assert detection.analyst_notes.endswith("analyst: Sensitive review detail")
        assert detection.analyst_id == console.analyst.user_id
        assert detection.reviewed_at is not None
        audit = (await session.scalars(select(AuditLogORM))).one()
        assert audit.user_id == console.analyst.user_id
        assert audit.username == "analyst" and audit.actor_kind == "user"
        assert audit.action == "update_detection"
        assert audit.resource_type == "detection"
        assert audit.resource_id == str(detection.detection_id)
        assert audit.ip_address == "192.0.2.10"
        assert audit.details == {"note_added": True}


@pytest.mark.parametrize("failure", ["audit", "commit"])
async def test_failed_note_or_audit_transaction_rolls_back_both(note_console, monkeypatch, failure):
    console = note_console
    if failure == "audit":
        original = detections.log_audit

        async def fail_audit(session, *args, **kwargs):
            await original(session, *args, **kwargs)
            await session.flush()
            raise RuntimeError("audit failure")

        monkeypatch.setattr(detections, "log_audit", fail_audit)
    else:

        async def fail_commit(session):
            await session.flush()
            raise RuntimeError("commit failure")

        monkeypatch.setattr(AsyncSession, "commit", fail_commit)
    response = await console.client.post(
        f"/api/v1/detections/{console.detection.detection_id}/notes", params={"note": "Must roll back"}
    )
    assert response.status_code == 500
    async with console.sessions() as session:
        detection = await session.get(DetectionORM, console.detection.detection_id)
        assert detection.analyst_notes == "Existing note"
        assert detection.analyst_id is None and detection.reviewed_at is None
        assert list(await session.scalars(select(AuditLogORM))) == []


async def test_missing_detection_does_not_create_note_audit(note_console):
    response = await note_console.client.post(f"/api/v1/detections/{uuid4()}/notes", params={"note": "Missing"})
    assert response.status_code == 404 and response.json() == {"detail": "Detection not found"}
    async with note_console.sessions() as session:
        assert list(await session.scalars(select(AuditLogORM))) == []


async def test_note_append_locks_the_detection_before_reading_existing_notes(monkeypatch):
    detection = SimpleNamespace(analyst_notes="Existing note")
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: detection)
    monkeypatch.setattr(detections, "log_audit", AsyncMock())
    await detections.add_note(uuid4(), "New note", None, SimpleNamespace(user_id=uuid4(), username="analyst"), session)
    sql = str(session.execute.call_args.args[0])
    assert "WHERE detections.detection_id =" in sql and sql.endswith("FOR UPDATE")
    assert detection.analyst_notes.endswith("analyst: New note")


async def test_event_response_keeps_native_value_serialization(note_console, monkeypatch):
    event_id = uuid4()
    timestamp = datetime(2026, 10, 5, 12, 30, tzinfo=UTC)
    execute = Mock(side_effect=[[(event_id, timestamp, "example-tool")], [(1,)]])
    monkeypatch.setattr(detections, "get_clickhouse", lambda: SimpleNamespace(execute=execute))
    response = await note_console.client.get(f"/api/v1/detections/{note_console.detection.detection_id}/events")
    assert response.status_code == 200
    assert response.json() == {
        "items": [[str(event_id), timestamp.isoformat(), "example-tool"]],
        "total": 1,
        "page": 1,
        "page_size": 20,
    }


@pytest.mark.parametrize("blocked_query", ["items", "count"])
async def test_event_queries_leave_loop_responsive_and_keep_shared_client_serialized(monkeypatch, blocked_query):
    started = asyncio.Event()
    release = Event()
    loop = asyncio.get_running_loop()
    calls = []
    activity = {"active": 0, "maximum": 0, "blocked": False}
    events = [(uuid4(), datetime.now(UTC), "example-tool")]

    def execute(_client, sql, params):
        activity["active"] += 1
        activity["maximum"] = max(activity["maximum"], activity["active"])
        try:
            kind = "count" if "uniqExact" in sql else "items"
            calls.append((kind, sql, params))
            if kind == blocked_query and not activity["blocked"]:
                activity["blocked"] = True
                loop.call_soon_threadsafe(started.set)
                assert release.wait(2), "event loop did not release the blocked query"
            return [(7,)] if kind == "count" else events
        finally:
            activity["active"] -= 1

    monkeypatch.setattr(ClickHouseClient, "execute", execute)
    client = SerializedClickHouseClient("unused.test")
    monkeypatch.setattr(detections, "get_clickhouse", lambda: client)
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(one_or_none=lambda: ("example-tool",))
    tasks = [
        asyncio.create_task(detections.get_detection_events(uuid4(), 3, 2, SimpleNamespace(), session))
        for _ in range(2)
    ]
    try:
        await asyncio.wait_for(started.wait(), 1)
        # Another coroutine must progress while a native ClickHouse operation is still blocked.
        await asyncio.sleep(0.01)
        assert not release.is_set()
        assert any(not task.done() for task in tasks)
        release.set()
        results = await asyncio.gather(*tasks)
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert results == [{"items": events, "total": 7, "page": 3, "page_size": 2}] * 2
    assert activity["maximum"] == 1
    assert len(calls) == 4
    for kind, sql, params in calls:
        assert "catalog_match_id = %(cid)s" in sql and "tenant_id = %(tenant)s" in sql
        expected = {"cid": "example-tool", "tenant": "test-org"}
        if kind == "items":
            expected.update(limit=2, offset=4)
            assert "LIMIT 1 BY event_id" in sql and "ORDER BY timestamp DESC" in sql
        assert params == expected


@pytest.mark.parametrize("failed_query", ["items", "count"])
async def test_event_query_errors_propagate_without_partial_success(monkeypatch, failed_query):
    failure = RuntimeError("ClickHouse unavailable")
    execute = Mock(side_effect=failure if failed_query == "items" else [[("event",)], failure])
    monkeypatch.setattr(detections, "get_clickhouse", lambda: SimpleNamespace(execute=execute))
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(one_or_none=lambda: ("example-tool",))
    with pytest.raises(RuntimeError) as error:
        await detections.get_detection_events(uuid4(), 1, 20, SimpleNamespace(), session)
    assert error.value is failure
    assert execute.call_count == (1 if failed_query == "items" else 2)


async def test_missing_detection_does_not_query_clickhouse(monkeypatch):
    clickhouse = Mock()
    monkeypatch.setattr(detections, "get_clickhouse", clickhouse)
    session = AsyncMock()
    session.execute.return_value = SimpleNamespace(one_or_none=lambda: None)
    with pytest.raises(HTTPException) as error:
        await detections.get_detection_events(uuid4(), 1, 20, SimpleNamespace(), session)
    assert error.value.status_code == 404 and error.value.detail == "Detection not found"
    clickhouse.assert_not_called()
