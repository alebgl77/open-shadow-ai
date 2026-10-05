"""Validated canonical ingestion for custom collectors, directory inventories and instrumentation."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from shadai.api.agent import _validate_api_key
from shadai.config import get_config
from shadai.database import get_redis, postgres_session_factory
from shadai.engine.catalog_cache import CatalogCache
from shadai.engine.catalog_loader import load_database_catalog
from shadai.engine.matcher import AMBIGUOUS_MATCH_FIELD, CatalogMatcher
from shadai.models.event import CanonicalEvent

SOURCE_TYPES = ("dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb", "network")
router = APIRouter(prefix="/api/v1/ingest", tags=["ingestion"])


class InputEvent(CanonicalEvent):
    event_id: UUID
    timestamp: datetime
    collector_id: str = Field(min_length=1, max_length=255)
    tenant_id: str = ""


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[InputEvent] = Field(min_length=1, max_length=500)


def has_transient_signals(event: CanonicalEvent) -> bool:
    return bool(event.url_path or event.user_agent) and get_config().privacy.match_transient_signals


def prepare_event(
    event: CanonicalEvent, *, trusted_collector: bool = False, matcher: CatalogMatcher | None = None
) -> CanonicalEvent:
    config = get_config()
    if event.tenant_id and event.tenant_id != config.tenant_id:
        if not (trusted_collector and event.tenant_id == "default"):
            raise ValueError("Event belongs to another organization")
    event.tenant_id = config.tenant_id
    if event.timestamp > datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5):
        raise ValueError("Event timestamp is too far in the future")
    if event.timestamp < datetime.now(UTC) - timedelta(days=config.retention.ingestion_max_age_days):
        raise ValueError("Event timestamp is outside the accepted retention window")
    for field in ("domain", "url_host", "sni"):
        host = getattr(event, field)
        if host and (any(c in host for c in "/?#@\\ \r\n") or len(host) > 253):
            raise ValueError("Domain fields must contain only a hostname")
    if not trusted_collector:
        event.catalog_match_id = ""
        event.match_field = ""
        event.match_confidence = 0
    if matcher is not None and has_transient_signals(event):
        # Evaluated in memory only: the catalog match is kept, the path and user agent are not.
        resolution = matcher.resolve_event(event)
        match = resolution.match
        if match is not None:
            event.catalog_match_id = match.catalog_item_id
            event.match_field = match.matched_field
            event.match_confidence = match.match_confidence
        elif resolution.ambiguous:
            # The worker cannot safely re-evaluate weaker evidence after these signals disappear.
            event.catalog_match_id = ""
            event.match_field = AMBIGUOUS_MATCH_FIELD
            event.match_confidence = 0
    # Paths are deliberately discarded at the common ingestion boundary; free-form URL
    # components and process paths may contain credentials or prompt text.
    event.url_path = ""
    event.process_path = ""
    event.raw_ref = ""
    event.user_agent = ""
    return CanonicalEvent.model_validate(event.model_dump())


boundary_catalog = CatalogCache()


async def load_boundary_catalog():
    async with postgres_session_factory()() as session:
        return await load_database_catalog(session)


@router.post("/events", status_code=202)
async def ingest_events(batch: EventBatch, _key: str = Depends(_validate_api_key)):
    matcher = None
    if any(has_transient_signals(event) for event in batch.events):
        matcher = await boundary_catalog.get(load_boundary_catalog)
    try:
        events = [prepare_event(event, matcher=matcher) for event in batch.events]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    redis = await get_redis()
    pipe = redis.pipeline(transaction=True)
    for event in events:
        pipe.xadd(f"events:{event.source_type}", {"data": event.model_dump_json()})
    await pipe.execute()
    return {"received": len(events), "tenant_id": get_config().tenant_id}
