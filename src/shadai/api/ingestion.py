"""Validated canonical ingestion for custom collectors, directory inventories and instrumentation."""

import json
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from shadai.api.collectors import SOURCE_TYPES as SOURCE_TYPES
from shadai.api.collectors import CollectorPrincipal, authenticate_collector
from shadai.config import get_config
from shadai.database import get_redis, postgres_session_factory
from shadai.engine.catalog_cache import CatalogCache
from shadai.engine.catalog_loader import load_database_catalog
from shadai.engine.matcher import AMBIGUOUS_MATCH_FIELD, CatalogMatcher
from shadai.models.event import CanonicalEvent

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
    event: CanonicalEvent, *, trusted_collector: bool = False, matcher: CatalogMatcher | None = None,
    accepted_at: datetime | None = None,
) -> CanonicalEvent:
    config = get_config()
    if event.tenant_id and event.tenant_id != config.tenant_id:
        if not (trusted_collector and event.tenant_id == "default"):
            raise ValueError("Event belongs to another organization")
    event.tenant_id = config.tenant_id
    now = datetime.now(UTC)
    if accepted_at is not None and (
        accepted_at.tzinfo is None or accepted_at > now + timedelta(minutes=5)
    ):
        raise ValueError("Invalid internal acceptance timestamp")
    acceptance = accepted_at.astimezone(UTC) if accepted_at is not None else now
    if event.timestamp > acceptance.replace(microsecond=0) + timedelta(minutes=5):
        raise ValueError("Event timestamp is too far in the future")
    if event.timestamp < acceptance - timedelta(days=config.retention.ingestion_max_age_days):
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
    from shadai.utils.privacy import prepare_identity

    event = prepare_identity(event, trusted_internal=trusted_collector)
    return CanonicalEvent.model_validate(event.model_dump())


boundary_catalog = CatalogCache()


async def load_boundary_catalog():
    async with postgres_session_factory()() as session:
        return await load_database_catalog(session)


@router.post("/events", status_code=202)
async def ingest_events(
    batch: EventBatch, principal: CollectorPrincipal = Depends(authenticate_collector, scope="function"),
):
    received_at = datetime.now(UTC)
    principal.require_sources(event.source_type for event in batch.events)
    for event in batch.events:
        event.collector_id = principal.bind(event.collector_id)
        if not principal.legacy:
            # A client UUID is scoped to its immutable enrolled collector, so it
            # cannot preempt another collector's global ingestion receipts.
            identity = json.dumps(
                [get_config().tenant_id, principal.collector_id, str(event.event_id)], separators=(",", ":")
            )
            event.event_id = uuid5(NAMESPACE_URL, identity)
    matcher = None
    if any(has_transient_signals(event) for event in batch.events):
        matcher = await boundary_catalog.get(load_boundary_catalog)
    try:
        events = [prepare_event(event, matcher=matcher) for event in batch.events]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    from shadai.utils.queue_admission import admit_records
    from shadai.utils.queueing import queue_fields

    try:
        redis = await get_redis()
        await admit_records(redis, [{"stream": f"events:{event.source_type}",
                                     "fields": queue_fields(event.model_dump_json(), accepted_at=received_at)}
                                    for event in events])
    except Exception:
        raise HTTPException(status_code=503, detail="Queue temporarily unavailable",
                            headers={"Retry-After": "5"}) from None
    principal.contact(max(event.timestamp for event in events))
    return {"received": len(events), "tenant_id": get_config().tenant_id}
