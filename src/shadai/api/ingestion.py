"""Validated canonical ingestion for custom collectors, directory inventories and instrumentation."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from shadai.api.agent import _validate_api_key
from shadai.config import get_config
from shadai.database import get_redis
from shadai.models.event import CanonicalEvent

SOURCE_TYPES = ("dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb")
router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


class InputEvent(CanonicalEvent):
    event_id: UUID
    timestamp: datetime
    collector_id: str = Field(min_length=1, max_length=255)
    tenant_id: str = ""


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[InputEvent] = Field(min_length=1, max_length=500)


def prepare_event(event: CanonicalEvent, *, trusted_collector: bool = False) -> CanonicalEvent:
    config = get_config()
    if event.tenant_id and event.tenant_id != config.tenant_id:
        if not (trusted_collector and event.tenant_id == "default"):
            raise ValueError("Event belongs to another organization")
    event.tenant_id = config.tenant_id
    if event.timestamp > datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5):
        raise ValueError("Event timestamp is too far in the future")
    if event.timestamp < datetime.now(UTC) - timedelta(days=config.retention.ingestion_max_age_days):
        raise ValueError("Event timestamp is outside the accepted retention window")
    # Paths are deliberately discarded at the common ingestion boundary; free-form URL
    # components and process paths may contain credentials or prompt text.
    event.url_path = ""
    event.process_path = ""
    event.raw_ref = ""
    event.user_agent = ""
    for field in ("domain", "url_host", "sni"):
        host = getattr(event, field)
        if host and (any(c in host for c in "/?#@\\ \r\n") or len(host) > 253):
            raise ValueError("Domain fields must contain only a hostname")
    if not trusted_collector:
        event.catalog_match_id = ""
        event.match_field = ""
        event.match_confidence = 0
    return CanonicalEvent.model_validate(event.model_dump())


@router.post("/events", status_code=202)
async def ingest_events(batch: EventBatch, _key: str = Depends(_validate_api_key)):
    try:
        events = [prepare_event(event) for event in batch.events]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    redis = await get_redis()
    pipe = redis.pipeline(transaction=True)
    for event in events:
        pipe.xadd(f"events:{event.source_type}", {"data": event.model_dump_json()})
    await pipe.execute()
    return {"received": len(events), "tenant_id": get_config().tenant_id}
