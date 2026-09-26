"""Detection object ORM model and Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base, TimestampMixin


# ── SQLAlchemy ORM ───────────────────────────────────────────────
class DetectionORM(Base, TimestampMixin):
    __tablename__ = "detections"
    __table_args__ = (
        UniqueConstraint("catalog_item_id", name="uq_detection_catalog"),
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="valid_confidence"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="valid_risk"),
        Index("idx_detections_risk", "risk_score", "analyst_status"),
        Index("idx_detections_classification", "classification"),
        Index("idx_detections_entity", "entity_type", "entity_name"),
        Index("idx_detections_last_seen", "last_seen_at"),
        Index("idx_detections_catalog", "catalog_item_id"),
    )

    detection_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Entity identification
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_name: Mapped[str] = mapped_column(String(255), nullable=False)
    entity_category: Mapped[str | None] = mapped_column(String(100))
    catalog_item_id: Mapped[str | None] = mapped_column(String(100))

    # Classification
    classification: Mapped[str] = mapped_column(String(50), default="unknown")
    shadow_ai_status: Mapped[str] = mapped_column(String(50), default="suspected")

    # Scoring
    confidence_score: Mapped[float] = mapped_column(default=0.0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Evidence
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    impacted_users_count: Mapped[int] = mapped_column(Integer, default=0)
    impacted_devices_count: Mapped[int] = mapped_column(Integer, default=0)
    total_events_count: Mapped[int] = mapped_column(BigInteger, default=0)
    source_types: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    primary_evidence: Mapped[str | None] = mapped_column(Text)
    evidence_bundle: Mapped[dict] = mapped_column(JSONB, default=dict)
    reasoning_summary: Mapped[str | None] = mapped_column(Text)

    # Analyst workflow
    analyst_status: Mapped[str] = mapped_column(String(50), default="new")
    analyst_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Governance
    recommended_action: Mapped[str | None] = mapped_column(String(100))
    governance_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    @property
    def governance_status(self) -> str:
        policy = (self.evidence_bundle or {}).get("_governance")
        if not policy:
            return "none"
        expiry = policy.get("approved_until")
        if expiry and datetime.fromisoformat(expiry) <= datetime.now(UTC):
            return "expired"
        return "active"

    @property
    def risk_score_stale(self) -> bool:
        bundle = self.evidence_bundle or {}
        policy = bundle.get("_governance") or {}
        return bool(
            bundle.get("_risk_score_stale", False)
            or (self.governance_id is not None and not policy)
            or (policy and policy.get("applied_status") != self.governance_status)
        )

    @property
    def confidence_level(self) -> str:
        if self.confidence_score >= 0.90:
            return "very_high"
        if self.confidence_score >= 0.70:
            return "high"
        if self.confidence_score >= 0.40:
            return "medium"
        return "low"

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 86:
            return "critical"
        if self.risk_score >= 71:
            return "high"
        if self.risk_score >= 51:
            return "medium"
        if self.risk_score >= 26:
            return "low"
        return "info"


# ── Pydantic Schemas ─────────────────────────────────────────────
class DetectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    detection_id: uuid.UUID
    entity_type: str
    entity_name: str
    entity_category: str | None = None
    catalog_item_id: str | None = None
    classification: str = "unknown"
    shadow_ai_status: str = "suspected"
    confidence_score: float
    confidence_level: str
    risk_score: int
    risk_level: str
    risk_score_stale: bool = False
    governance_status: str = "none"
    first_seen_at: datetime
    last_seen_at: datetime
    impacted_users_count: int = 0
    impacted_devices_count: int = 0
    total_events_count: int = 0
    source_types: list[str] = Field(default_factory=list)
    primary_evidence: str | None = None
    evidence_bundle: dict = Field(default_factory=dict)
    reasoning_summary: str | None = None
    analyst_status: str = "new"
    analyst_id: uuid.UUID | None = None
    analyst_notes: str | None = None
    reviewed_at: datetime | None = None
    recommended_action: str | None = None
    governance_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime


class DetectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    classification: Literal["sanctioned", "tolerated", "unsanctioned", "unknown"] | None = None
    analyst_status: Literal["new", "investigating", "classified", "false_positive", "escalated"] | None = None
    analyst_notes: str | None = Field(default=None, max_length=2000)
    recommended_action: str | None = Field(default=None, max_length=100)


class DetectionListResponse(BaseModel):
    items: list[DetectionRead]
    total: int
    page: int
    page_size: int


class DetectionFilter(BaseModel):
    classification: list[str] | None = None
    risk_level: list[str] | None = None
    confidence_level: list[str] | None = None
    entity_type: list[str] | None = None
    analyst_status: list[str] | None = None
    source_type: list[str] | None = None
    search: str | None = None
    first_seen_after: datetime | None = None
    last_seen_before: datetime | None = None
    page: int = 1
    page_size: int = 25
    sort_by: str = "last_seen_at"
    sort_order: str = "desc"
