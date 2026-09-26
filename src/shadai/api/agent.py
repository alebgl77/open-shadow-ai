"""Agent telemetry API routes."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

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


def _validate_api_key(x_api_key: str = Header(...)) -> str:
    """Validate agent API key from header using constant-time comparison."""
    import hmac

    expected = get_config().security.agent_api_key
    if len(expected.encode()) < 32 or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@router.post("/telemetry")
async def receive_telemetry(
    batch: TelemetryBatch,
    _key: str = Depends(_validate_api_key),
):
    """Receive endpoint agent telemetry and push to pipeline."""
    redis = await get_redis()
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
        event.collector_id = "agent:" + batch.hostname
        event.evidence_type = "inventory" if event.source_type == "browser" else "observation"
        try:
            event = prepare_event(event, trusted_collector=True)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid telemetry event") from None
        content = json.dumps(event.model_dump(mode="json", exclude={"event_id"}), sort_keys=True)
        event.event_id = uuid.uuid5(uuid.NAMESPACE_URL, sha256(content.encode()).hexdigest())
        events[index] = event

    # Push to Redis
    pipe = redis.pipeline()
    for event in events:
        stream_key = f"events:{event.source_type}"
        pipe.xadd(stream_key, {"data": event.model_dump_json()})
    await pipe.execute()

    return {"received": len(events), "hostname": batch.hostname}


@router.get("/config")
async def get_agent_config(_key: str = Depends(_validate_api_key)):
    """Return agent configuration."""
    return {
        "poll_interval_seconds": 300,
        "collect_processes": True,
        "collect_containers": True,
        "collect_extensions": True,
        "collect_local_ai": True,
    }
