"""Observed identity membership, independent of aggregate service activity."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base


class EvidenceIdentityORM(Base):
    __tablename__ = "detection_identity_members"
    __table_args__ = (
        CheckConstraint("kind IN ('user', 'device')", name="valid_evidence_identity_kind"),
        Index("idx_evidence_identity_last_seen", "last_seen_at"),
    )

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detections.detection_id", ondelete="CASCADE"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(String(10), primary_key=True)
    identity_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
