"""Enrolled collectors, hashed credentials, and server-received health metadata."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base, TimestampMixin


class CollectorORM(Base, TimestampMixin):
    __tablename__ = "collectors"

    collector_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    allowed_source_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    credential_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_contact_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    client_version: Mapped[str | None] = mapped_column(String(100))
    client_last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    client_counters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")


class CollectorCredentialORM(Base):
    __tablename__ = "collector_credentials"
    __table_args__ = (Index("idx_collector_credentials_collector", "collector_id"),)

    credential_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    collector_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("collectors.collector_id", ondelete="CASCADE"), nullable=False
    )
    secret_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
