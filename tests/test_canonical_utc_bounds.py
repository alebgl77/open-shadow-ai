"""UTC conversion bounds remain validation failures at every ingestion boundary."""

import json
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from shadai.api import ingestion
from shadai.models.event import CanonicalEvent
from shadai.utils import queue_admission
from shadai.utils.queueing import PermanentMessageError, prepare_queued_event
from shadai.workers.streams import permanent_error

FIELDS = ("timestamp", "normalized_at", "extension_installed_at")
INVALID_UTC = ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00")


def record(**fields):
    return {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
        "collector_id": "utc-bounds-sensor",
        "tenant_id": "test-org",
        **fields,
    }


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("stamp", INVALID_UTC)
def test_utc_conversion_bounds_are_pydantic_validation_errors(field, stamp):
    with pytest.raises(ValidationError) as caught:
        CanonicalEvent.model_validate(record(**{field: stamp}))
    assert caught.value.errors()[0]["loc"] == (field,)
    assert "supported UTC range" in caught.value.errors()[0]["msg"]


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("0001-01-01T00:00:00Z", datetime.min.replace(tzinfo=UTC)),
        ("9999-12-31T23:59:59.999999Z", datetime.max.replace(tzinfo=UTC)),
        ("0001-01-01T01:00:00+01:00", datetime.min.replace(tzinfo=UTC)),
        ("9999-12-31T22:59:59.999999-01:00", datetime.max.replace(tzinfo=UTC)),
        ("2026-10-15T14:00:00+02:00", datetime(2026, 10, 15, 12, tzinfo=UTC)),
    ],
)
def test_representable_aware_datetimes_keep_utc_semantics(field, stamp, expected):
    event = CanonicalEvent.model_validate(record(**{field: stamp}))
    assert getattr(event, field) == expected
    assert getattr(event, field).tzinfo is UTC


@pytest.mark.parametrize("field", FIELDS)
def test_naive_datetimes_still_require_timezone(field):
    with pytest.raises(ValidationError, match="require a timezone"):
        CanonicalEvent.model_validate(record(**{field: "2026-10-15T12:00:00"}))


def test_optional_extension_install_time_stays_optional():
    assert CanonicalEvent.model_validate(record(extension_installed_at=None)).extension_installed_at is None


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("stamp", INVALID_UTC)
def test_invalid_internal_event_is_explicitly_permanent(field, stamp):
    payload = {"data": json.dumps(record(**{field: stamp}))}
    with pytest.raises(PermanentMessageError, match="^Invalid internal event envelope$") as caught:
        prepare_queued_event(payload)
    assert permanent_error(caught.value)


@pytest.fixture
async def isolated_ingestion(monkeypatch):
    application = FastAPI()
    application.include_router(ingestion.router)
    principal = SimpleNamespace(
        legacy=True,
        require_sources=lambda sources: None,
        bind=lambda collector: collector,
        contact=MagicMock(),
    )
    application.dependency_overrides[ingestion.authenticate_collector] = lambda: principal
    redis = AsyncMock(return_value=object())
    admit = AsyncMock()
    monkeypatch.setattr(ingestion, "get_redis", redis)
    monkeypatch.setattr(queue_admission, "admit_records", admit)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(application, raise_app_exceptions=False), base_url="https://testserver"
    ) as client:
        yield SimpleNamespace(client=client, redis=redis, admit=admit, principal=principal)


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("stamp", INVALID_UTC)
async def test_http_rejects_entire_batch_before_admission(isolated_ingestion, field, stamp):
    boundary = isolated_ingestion
    response = await boundary.client.post(
        "/api/v1/ingest/events", json={"events": [record(), record(**{field: stamp})]}
    )
    assert response.status_code == 422
    boundary.redis.assert_not_awaited()
    boundary.admit.assert_not_awaited()
    boundary.principal.contact.assert_not_called()


@pytest.mark.parametrize("field", FIELDS)
async def test_http_accepts_valid_offset_without_changing_instant(isolated_ingestion, field):
    boundary = isolated_ingestion
    now = datetime.now(UTC)
    stamp = now.astimezone(timezone(timedelta(hours=2)))
    response = await boundary.client.post(
        "/api/v1/ingest/events", json={"events": [record(**{field: stamp.isoformat()})]}
    )
    assert response.status_code == 202
    boundary.redis.assert_awaited_once()
    boundary.admit.assert_awaited_once()
    queued = json.loads(boundary.admit.await_args.args[1][0]["fields"]["data"])
    assert datetime.fromisoformat(queued[field]) == now
    boundary.principal.contact.assert_called_once()
