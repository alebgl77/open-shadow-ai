"""Agent telemetry API routes."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from shadai.api.collectors import CollectorPrincipal, authenticate_collector, validate_legacy_key
from shadai.config import get_config
from shadai.database import get_redis
from shadai.models.event import CanonicalEvent

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str = Field(min_length=1, max_length=255)
    agent_version: str = "0.1.0"
    timestamp: datetime
    processes: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    containers: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    local_ai_hits: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    extensions: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    model_files: list[dict[str, Any]] = Field(default_factory=list, max_length=500)

    @field_validator("timestamp")
    @classmethod
    def aware_timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timestamp requires timezone")
        return value.astimezone(UTC)

    @field_validator("processes", "containers", "local_ai_hits", "extensions", "model_files")
    @classmethod
    def validate_records(cls, records):
        text_fields = {"name", "path", "parent", "username", "image", "process_name", "tool_name", "id", "browser"}
        for record in records:
            for field in text_fields & record.keys():
                if not isinstance(record[field], str) or len(record[field]) > 2048:
                    raise ValueError("Invalid telemetry text field")
            for field in {"port", "listening_port"} & record.keys():
                if (
                    not isinstance(record[field], int)
                    or isinstance(record[field], bool)
                    or not 0 <= record[field] <= 65535
                ):
                    raise ValueError("Invalid telemetry port")
        return records


def _validate_api_key(x_api_key: str | None = Header(None)) -> str:
    """Compatibility helper for callers explicitly checking the shared legacy key."""
    return validate_legacy_key(x_api_key)


@router.post("/telemetry")
async def receive_telemetry(
    batch: TelemetryBatch,
    principal: CollectorPrincipal = Depends(authenticate_collector, scope="function"),
):
    """Receive endpoint agent telemetry and push to pipeline."""
    endpoint_records = any((batch.processes, batch.containers, batch.local_ai_hits, batch.model_files))
    sources = {"endpoint"} if endpoint_records else set()
    if batch.extensions:
        sources.add("browser")
    principal.require_sources(sources or {"endpoint"})
    received_at = datetime.now(UTC)
    events: list[CanonicalEvent] = []
    from shadai.api.ingestion import prepare_event

    # Parse processes
    for proc in batch.processes:
        event = CanonicalEvent(
            source_type="endpoint",
            hostname=batch.hostname,
            device_id=batch.hostname,
            process_name=proc.get("name", ""),
            process_path="",
            parent_process=proc.get("parent", ""),
            username=proc.get("username", ""),
            local_port=proc.get("listening_port", 0),
        )
        events.append(event)

    # Parse containers
    for container in batch.containers:
        event = CanonicalEvent(
            source_type="endpoint",
            hostname=batch.hostname,
            device_id=batch.hostname,
            container_name=container.get("name", ""),
            container_image=container.get("image", ""),
            local_port=container.get("port", 0),
        )
        events.append(event)

    # Parse local AI hits
    for hit in batch.local_ai_hits:
        event = CanonicalEvent(
            source_type="endpoint",
            hostname=batch.hostname,
            device_id=batch.hostname,
            process_name=hit.get("process_name", ""),
            local_port=hit.get("port", 0),
            software_name=hit.get("tool_name", ""),
        )
        events.append(event)

    # Parse browser extensions
    for ext in batch.extensions:
        event = CanonicalEvent(
            source_type="browser",
            hostname=batch.hostname,
            device_id=batch.hostname,
            extension_id=ext.get("id", ""),
            extension_name=ext.get("name", ""),
            browser_name=ext.get("browser", ""),
        )
        events.append(event)

    # Snapshot identity is stable for client retries of the same batch.
    for index, event in enumerate(events):
        event.timestamp = batch.timestamp
        event.normalized_at = batch.timestamp
        event.tenant_id = get_config().tenant_id
        event.collector_id = principal.collector_id
        event.evidence_type = "inventory" if event.source_type == "browser" else "observation"
        # Observation identity is derived before mode/key-specific privacy aliases.
        # A mode change during an uncertain-delivery retry must not duplicate work.
        content = json.dumps(event.model_dump(mode="json", exclude={"event_id", "privacy_stamp"}), sort_keys=True)
        event.event_id = uuid.uuid5(uuid.NAMESPACE_URL, sha256(content.encode()).hexdigest())
        try:
            event = prepare_event(event, trusted_collector=True)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid telemetry event") from None
        events[index] = event

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
    principal.contact(batch.timestamp if events else None)

    return {"received": len(events), "hostname": batch.hostname}


@router.get("/config")
async def get_agent_config(principal: CollectorPrincipal = Depends(authenticate_collector, scope="function")):
    """Return agent configuration."""
    return {
        "collector_id": None if principal.legacy else principal.collector_id,
        "legacy": principal.legacy,
        "allowed_source_types": sorted(principal.allowed_source_types),
        "ingestion_max_age_days": get_config().retention.ingestion_max_age_days,
        "poll_interval_seconds": 300,
        "collect_processes": True,
        "collect_containers": True,
        "collect_extensions": True,
        "collect_local_ai": True,
    }


class CollectorHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector_id: str = Field(min_length=1, max_length=255)
    client_version: str = Field(min_length=1, max_length=100)
    queue_events: int = Field(default=0, ge=0, le=10**12, strict=True)
    queued_bytes: int = Field(default=0, ge=0, le=10**15, strict=True)
    dropped_events: int = Field(default=0, ge=0, le=10**15, strict=True)
    expired_events: int = Field(default=0, ge=0, le=10**15, strict=True)
    rejected_events: int = Field(default=0, ge=0, le=10**15, strict=True)
    last_success_at: datetime | None = None

    @field_validator("last_success_at")
    @classmethod
    def aware_success(cls, value):
        if value is not None:
            if value.tzinfo is None:
                raise ValueError("Timestamp requires timezone")
            if value > datetime.now(UTC):
                raise ValueError("Client success cannot be in the future")
            return value.astimezone(UTC)
        return value


@router.post("/heartbeat")
async def collector_heartbeat(
    body: CollectorHeartbeat,
    principal: CollectorPrincipal = Depends(authenticate_collector, scope="function"),
):
    """Server-received liveness; client timestamps and counters remain advisory."""
    if principal.legacy:
        raise HTTPException(status_code=403, detail="Enrolled collector credential required")
    principal.bind(body.collector_id)
    principal.contact(heartbeat=True)
    principal.collector.client_version = body.client_version
    principal.collector.client_last_success_at = body.last_success_at
    principal.collector.client_counters = body.model_dump(exclude={"collector_id", "client_version", "last_success_at"})
    return {"collector_id": principal.collector_id, "received_at": principal.collector.last_heartbeat_at}
