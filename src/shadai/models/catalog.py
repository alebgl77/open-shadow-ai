"""Catalog item ORM model and Pydantic schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base, TimestampMixin


# ── SQLAlchemy ORM ───────────────────────────────────────────────
class CatalogItemORM(Base, TimestampMixin):
    __tablename__ = "catalog"

    catalog_item_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)

    # Signatures multi-signaux
    domains: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    url_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    processes: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    extension_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    oauth_app_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    local_ports: Mapped[list[int]] = mapped_column(ARRAY(Text), default=list)  # stored as text[], cast on read
    local_paths: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    container_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    user_agent_patterns: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)

    # Governance defaults
    rule_tags: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    default_trust_level: Mapped[str] = mapped_column(String(50), default="unknown")

    # Meta
    status: Mapped[str] = mapped_column(String(50), default="active")
    source_of_truth: Mapped[str] = mapped_column(String(50), default="builtin")
    last_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    local_override: Mapped[bool] = mapped_column(Boolean, default=False)


# ── Pydantic Schemas ─────────────────────────────────────────────
class CatalogSignatures(BaseModel):
    domains: list[str] = Field(default_factory=list)
    url_patterns: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    extension_ids: list[str] = Field(default_factory=list)
    oauth_app_ids: list[str] = Field(default_factory=list)
    local_ports: list[int] = Field(default_factory=list)
    local_paths: list[str] = Field(default_factory=list)
    container_patterns: list[str] = Field(default_factory=list)
    user_agent_patterns: list[str] = Field(default_factory=list)


class CatalogYAMLEntry(BaseModel):
    """Schema for YAML catalog file format."""

    id: str
    canonical_name: str
    aliases: list[str] = Field(default_factory=list)
    category: str
    vendor: str | None = None
    description: str | None = None
    signatures: CatalogSignatures = CatalogSignatures()
    default_trust_level: str = "unknown"
    rule_tags: list[str] = Field(default_factory=list)


class CatalogItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    catalog_item_id: str
    canonical_name: str
    aliases: list[str] = Field(default_factory=list)
    category: str
    vendor: str | None = None
    description: str | None = None
    domains: list[str] = Field(default_factory=list)
    url_patterns: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    extension_ids: list[str] = Field(default_factory=list)
    oauth_app_ids: list[str] = Field(default_factory=list)
    local_ports: list[int] = Field(default_factory=list)
    local_paths: list[str] = Field(default_factory=list)
    container_patterns: list[str] = Field(default_factory=list)
    user_agent_patterns: list[str] = Field(default_factory=list)
    rule_tags: list[str] = Field(default_factory=list)
    default_trust_level: str = "unknown"
    status: str = "active"
    source_of_truth: str = "builtin"
    last_reviewed_at: datetime | None = None
    local_override: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


class CatalogItemCreate(BaseModel):
    catalog_item_id: str
    canonical_name: str
    aliases: list[str] = Field(default_factory=list)
    category: str
    vendor: str | None = None
    description: str | None = None
    domains: list[str] = Field(default_factory=list)
    url_patterns: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    extension_ids: list[str] = Field(default_factory=list)
    oauth_app_ids: list[str] = Field(default_factory=list)
    local_ports: list[int] = Field(default_factory=list)
    local_paths: list[str] = Field(default_factory=list)
    container_patterns: list[str] = Field(default_factory=list)
    user_agent_patterns: list[str] = Field(default_factory=list)
    rule_tags: list[str] = Field(default_factory=list)
    default_trust_level: str = "unknown"


class CatalogItemUpdate(BaseModel):
    canonical_name: str | None = None
    aliases: list[str] | None = None
    category: str | None = None
    vendor: str | None = None
    description: str | None = None
    domains: list[str] | None = None
    url_patterns: list[str] | None = None
    processes: list[str] | None = None
    extension_ids: list[str] | None = None
    oauth_app_ids: list[str] | None = None
    local_ports: list[int] | None = None
    local_paths: list[str] | None = None
    container_patterns: list[str] | None = None
    user_agent_patterns: list[str] | None = None
    rule_tags: list[str] | None = None
    default_trust_level: str | None = None
    status: str | None = None
