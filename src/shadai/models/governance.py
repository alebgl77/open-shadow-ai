"""Governance policy ORM model and Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base, TimestampMixin


class GovernanceORM(Base, TimestampMixin):
    __tablename__ = "governance"
    __table_args__ = (Index("idx_governance_target", "target_type", "target_id"),)

    governance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    org_classification: Mapped[str] = mapped_column(String(50), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(255))
    exception_policy: Mapped[str | None] = mapped_column(Text)
    enforcement_mode: Mapped[str] = mapped_column(String(50), default="monitor")
    justification: Mapped[str | None] = mapped_column(Text)
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    @property
    def approval_status(self) -> str:
        expiry = self.approved_until
        if expiry is not None:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry <= datetime.now(UTC):
                return "expired"
        return "active"


# ── Pydantic Schemas ─────────────────────────────────────────────
class GovernanceDates(BaseModel):
    @field_validator("approved_at", "approved_until", check_fields=False)
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.tzinfo is None:
            raise ValueError("Approval dates require an explicit timezone")
        return value


class GovernanceCreate(GovernanceDates):
    target_type: str
    target_id: str
    org_classification: str
    owner: str | None = None
    exception_policy: str | None = None
    enforcement_mode: str = "monitor"
    justification: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    approved_until: datetime | None = None


class GovernanceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_status: str = "active"
    governance_id: uuid.UUID
    target_type: str
    target_id: str
    org_classification: str
    owner: str | None = None
    exception_policy: str | None = None
    enforcement_mode: str
    justification: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    approved_until: datetime | None = None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class GovernanceUpdate(GovernanceDates):
    org_classification: str | None = None
    owner: str | None = None
    exception_policy: str | None = None
    enforcement_mode: str | None = None
    justification: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    approved_until: datetime | None = None
