"""Canonical event model (Pydantic only — stored in ClickHouse, not Postgres)."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NetworkProtocol = Literal["DNS", "TLS", "QUIC", "HTTP"]
NETWORK_PROTOCOLS = ("DNS", "TLS", "QUIC", "HTTP")


def network_hostname(value: str) -> str:
    """Normalize a DNS name, never treating an address or URL as a service name."""
    if not value:
        return ""
    host = value.lower()
    try:
        host = host.encode("idna").decode("ascii").removesuffix(".")
        # Validate pre-encoded punycode too, rather than accepting an invalid A-label.
        host.encode("ascii").decode("idna")
    except UnicodeError:
        raise ValueError("Network host fields require a valid DNS name") from None
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Network host fields require a DNS name, not an IP address")
    if len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
    ):
        raise ValueError("Network host fields require a valid DNS name")
    return host


class CanonicalEvent(BaseModel):
    """Unified event schema for all source types. Maps to ClickHouse `events` table."""

    model_config = ConfigDict(extra="forbid", str_max_length=2048, allow_inf_nan=False)

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_type: Literal[
        "dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb", "network"
    ] = "dns"
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
        if self.source_type == "network":
            if self.evidence_type != "observation" or (
                self.model
                or self.provider
                or self.model_provenance != "unknown"
                or self.measurement_provenance != "unknown"
                or any(value is not None for value in (self.input_tokens, self.output_tokens, self.cost_usd))
            ):
                raise ValueError("Network observations cannot claim models, usage or measurements")
            if any(
                getattr(self, field)
                for field in (
                    "user_id", "username", "device_id", "hostname", "identity_provider", "identity_object_id",
                    "identity_sid", "process_name", "process_path", "parent_process", "browser_name", "extension_id",
                    "extension_name", "software_name", "service_name", "container_name", "container_image",
                    "local_port",
                    "oauth_app_id", "oauth_app_name", "oauth_scopes", "url_path", "user_agent", "raw_ref",
                )
            ):
                raise ValueError("Network observations contain only network metadata, without identity or content")
            if self.protocol not in NETWORK_PROTOCOLS:
                raise ValueError("Network protocol must be DNS, TLS, QUIC or HTTP")
            if not self.collector_id or len(self.collector_id) > 255 or len(self.parser_version) > 255:
                raise ValueError("Network collector and parser identifiers must be bounded")
            for field in ("src_ip", "dst_ip"):
                value = getattr(self, field)
                if value:
                    try:
                        if "%" in value:
                            raise ValueError()
                        setattr(self, field, str(ip_address(value)))
                    except ValueError:
                        raise ValueError("Network address fields require a valid IP address") from None
            for field in ("domain", "sni", "url_host"):
                setattr(self, field, network_hostname(getattr(self, field)))
            if self.protocol == "DNS":
                if self.sni or self.url_host:
                    raise ValueError("DNS observations contain only domain")
            elif self.protocol in ("TLS", "QUIC"):
                if self.url_host or (self.domain and self.domain != self.sni):
                    raise ValueError("TLS and QUIC observations require domain to equal SNI")
                self.domain = self.sni
            else:
                if self.sni or (self.domain and self.domain != self.url_host):
                    raise ValueError("HTTP observations require domain to equal the Host header")
                self.domain = self.url_host
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
    # Queue-only server proof. External ingestion never trusts a submitted proof.
    privacy_stamp: str = Field(default="", max_length=64, pattern=r"^(?:[a-f0-9]{64})?$")

    def to_clickhouse_dict(self) -> dict:
        """Serialize to dict for clickhouse-driver batch insert."""
        d = self.model_dump(exclude={"privacy_stamp"})
        d["event_id"] = str(d["event_id"])
        d["timestamp"] = d["timestamp"]
        d["normalized_at"] = d["normalized_at"]
        return d
