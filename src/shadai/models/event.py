"""Canonical event model (Pydantic only — stored in ClickHouse, not Postgres)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CanonicalEvent(BaseModel):
    """Unified event schema for all source types. Maps to ClickHouse `events` table."""

    model_config = ConfigDict(extra="forbid", str_max_length=2048, allow_inf_nan=False)

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_type: Literal["dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb"] = (
        "dns"  # dns, proxy, endpoint, browser, oauth, casb
    )
    collector_id: str = ""
    tenant_id: str = "default"
    site_id: str = "default"

    # Device context
    device_id: str = ""
    hostname: str = ""

    # User context
    user_id: str = ""
    username: str = ""

    # Network context
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: str = ""
    domain: str = ""
    sni: str = ""
    url_host: str = ""
    url_path: str = ""
    http_method: str = ""
    user_agent: str = ""
    bytes_in: int = Field(default=0, ge=0, le=2**63 - 1)
    bytes_out: int = Field(default=0, ge=0, le=2**63 - 1)

    # Endpoint context
    process_name: str = ""
    process_path: str = ""
    parent_process: str = ""

    # Browser context
    browser_name: str = ""
    extension_id: str = ""
    extension_name: str = ""

    # Software/service context
    software_name: str = ""
    service_name: str = ""
    container_name: str = ""
    container_image: str = ""
    local_port: int = Field(default=0, ge=0, le=65535)

    # OAuth context
    oauth_app_id: str = ""
    oauth_app_name: str = ""
    oauth_scopes: list[str] = Field(default_factory=list, max_length=256)

    # Evidence is a claim from a collector; inventory is never measured usage.
    evidence_type: Literal["inventory", "observation", "usage"] = "observation"
    provider: str = ""
    model: str = ""
    model_provenance: Literal["unknown", "reported", "instrumented"] = "unknown"
    measurement_provenance: Literal["unknown", "reported", "instrumented"] = "unknown"
    input_tokens: int | None = Field(default=None, ge=0, le=2**63 - 1)
    output_tokens: int | None = Field(default=None, ge=0, le=2**63 - 1)
    cost_usd: float | None = Field(default=None, ge=0, le=1e9)
    identity_provider: str = ""
    identity_object_id: str = ""
    identity_sid: str = ""

    @field_validator("timestamp", "normalized_at")
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamps require a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def truthful_measurements(self):
        if self.source_type == "directory" and self.evidence_type != "inventory":
            raise ValueError("Directory events are inventory only")
        if self.source_type == "dns" and (
            self.model or self.model_provenance != "unknown" or self.evidence_type == "usage"
        ):
            raise ValueError("DNS cannot identify a model or prove usage")
        if self.model and self.model_provenance == "unknown":
            raise ValueError("Model identity requires reported or instrumented provenance")
        measurements = (self.input_tokens, self.output_tokens, self.cost_usd)
        if any(value is not None for value in measurements):
            if self.measurement_provenance == "unknown" or self.evidence_type != "usage" or self.source_type == "dns":
                raise ValueError("Measurements require usage evidence and explicit provenance")
        return self

    # Meta
    raw_ref: str = ""
    parser_version: str = ""
    normalized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Matching result (populated by matcher worker)
    catalog_match_id: str = ""
    match_field: str = ""
    match_confidence: float = Field(default=0.0, ge=0, le=1)

    def to_clickhouse_dict(self) -> dict:
        """Serialize to dict for clickhouse-driver batch insert."""
        d = self.model_dump()
        d["event_id"] = str(d["event_id"])
        d["timestamp"] = d["timestamp"]
        d["normalized_at"] = d["normalized_at"]
        return d
