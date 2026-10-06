"""Read-only operational DTOs deliberately exclude credential metadata."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ClientReported(BaseModel):
    provenance: Literal['client_reported'] = 'client_reported'
    as_of: datetime | None
    fresh: bool
    queue_events: int | None
    queued_bytes: int | None
    dropped_events: int | None
    expired_events: int | None
    rejected_events: int | None
    last_success_at: datetime | None


class CollectorHealth(BaseModel):
    collector_id: str
    display_name: str
    allowed_source_types: list[str]
    status: Literal['revoked', 'unknown', 'stale', 'quiet', 'active']
    last_server_contact_at: datetime | None
    last_heartbeat_at: datetime | None
    last_observed_at: datetime | None
    server_contact_fresh: bool
    client_reported: ClientReported
    capture_loss: None = None


class CollectorHealthPage(BaseModel):
    items: list[CollectorHealth]
    total: int
    offset: int
    limit: int
    as_of: datetime


class StreamHealth(BaseModel):
    stream: str
    status: str
    group_present: bool
    retained_entries: int | None
    pending: int | None
    undelivered: int | None
    oldest_pending_age_seconds: float | None
    worker_state_fresh: bool
    last_worker_seen_at: datetime | None
    last_poll_at: datetime | None
    last_progress_at: datetime | None
    last_failure_at: datetime | None
    counters_since: datetime | None
    counters: dict[str, int | None]


class StageHealth(BaseModel):
    stage: str
    group: str
    status: str
    deadletter_retained: int
    streams: list[StreamHealth]


class PipelineHealth(BaseModel):
    scope: Literal['deployment']
    as_of: datetime
    backend_available: bool
    stages: list[StageHealth]
    capture_loss: None = None
