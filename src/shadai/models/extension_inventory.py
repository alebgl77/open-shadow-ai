"""Browser extension inventory: current installation state and version history (PostgreSQL).

ClickHouse keeps the raw inventory events; these tables hold the authoritative current state of
every installation the ingest worker has seen inside the identity window, keyed by host, user,
browser, profile and extension, plus one row per observed version change. Host and user labels
are the post-privacy values an event carries (plaintext in raw mode, an alias when identities
are pseudonymised); the digests are keyed identities, never raw identifiers.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from shadai.models.base import Base
from shadai.models.event import EXTENSION_INSTALL_SOURCES, ExtensionInstallSource

# Stored install sources: the eight agent-reportable values plus "" for a record a wire v1 agent
# sent without one. Keep in sync with the check constraint in migration 006_extension_inventory.
INVENTORY_INSTALL_SOURCES = ("", *EXTENSION_INSTALL_SOURCES)
INSTALL_SOURCE_CHECK = "install_source IN ({})".format(", ".join(f"'{value}'" for value in INVENTORY_INSTALL_SOURCES))
IdentityMode = Literal["pseudonymized", "raw"]


# ── SQLAlchemy ORM ───────────────────────────────────────────────
class ExtensionInventoryORM(Base):
    """One row per installation: tenant, device, user, browser, profile and extension."""

    __tablename__ = "extension_inventory"
    __table_args__ = (
        CheckConstraint(INSTALL_SOURCE_CHECK, name="valid_extension_install_source"),
        Index("idx_extension_inventory_last_seen", "last_seen_at"),
        Index("idx_extension_inventory_extension", "extension_id"),
        Index("idx_extension_inventory_browser", "browser"),
        Index("idx_extension_inventory_host", "host_label"),
        Index("idx_extension_inventory_catalog", "catalog_item_id"),
        Index("idx_extension_inventory_basis", "identity_basis"),
        Index("idx_extension_inventory_device", "device_digest"),
    )

    # sha256 of the JSON list [tenant_id, device_digest, user_digest or "", browser, profile, extension_id].
    inventory_key: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Identity (keyed digests plus the post-privacy labels the event itself carried)
    device_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    user_digest: Mapped[str | None] = mapped_column(String(64))
    host_label: Mapped[str] = mapped_column(String(255), nullable=False)
    user_label: Mapped[str | None] = mapped_column(String(255))
    browser: Mapped[str] = mapped_column(String(64), nullable=False)
    profile: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")

    # Installation state as last reported
    extension_id: Mapped[str] = mapped_column(Text, nullable=False)
    extension_name: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    version: Mapped[str | None] = mapped_column(String(100))
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    install_source: Mapped[str] = mapped_column(String(20), nullable=False, default="", server_default="")
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Observation window and provenance
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    catalog_item_id: Mapped[str | None] = mapped_column(String(100))
    collector_id: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")
    identity_basis: Mapped[str] = mapped_column(String(64), nullable=False)
    last_event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    # 1 when the record carried no per-installation state (no user/profile/install source).
    wire_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1, server_default="1")


class ExtensionVersionChangeORM(Base):
    """One row per observed version change of an installation; expires with its inventory row."""

    __tablename__ = "extension_version_changes"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_extension_version_change_event"),
        Index("idx_extension_version_changes_observed", "observed_at"),
        Index("idx_extension_version_changes_extension", "extension_id", "observed_at"),
        Index("idx_extension_version_changes_installation", "inventory_key", "observed_at"),
    )

    change_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    inventory_key: Mapped[str] = mapped_column(
        String(64), ForeignKey("extension_inventory.inventory_key", ondelete="CASCADE"), nullable=False
    )
    # The event that reported the new version; agent retries reuse the id, so a change is recorded once.
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Denormalised so the feed never joins a row that has since been replaced
    extension_id: Mapped[str] = mapped_column(Text, nullable=False)
    extension_name: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    browser: Mapped[str] = mapped_column(String(64), nullable=False)
    host_label: Mapped[str] = mapped_column(String(255), nullable=False)
    user_label: Mapped[str | None] = mapped_column(String(255))
    profile: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")

    from_version: Mapped[str | None] = mapped_column(String(100))
    to_version: Mapped[str | None] = mapped_column(String(100))
    previous_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    catalog_item_id: Mapped[str | None] = mapped_column(String(100))


# ── Pydantic Schemas ─────────────────────────────────────────────
class IdentityWindow(BaseModel):
    """The retention window every inventory response is bounded by."""

    days: int
    as_of: datetime


class ExtensionInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    inventory_key: str
    host_label: str
    user_label: str | None = None
    browser: str
    profile: str = ""
    extension_id: str
    extension_name: str = ""
    version: str | None = None
    enabled: bool | None = None
    install_source: ExtensionInstallSource = ""
    installed_at: datetime | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    catalog_item_id: str | None = None
    detection_id: uuid.UUID | None = None
    collector_id: str = ""
    last_event_id: uuid.UUID
    wire_version: int = 1
    # False once the same device reported a newer snapshot without this installation.
    present_in_latest_snapshot: bool = True


class ExtensionVersionChangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    change_id: uuid.UUID
    inventory_key: str
    event_id: uuid.UUID
    extension_id: str
    extension_name: str = ""
    browser: str
    host_label: str
    user_label: str | None = None
    profile: str = ""
    from_version: str | None = None
    to_version: str | None = None
    previous_observed_at: datetime
    observed_at: datetime
    catalog_item_id: str | None = None


class ExtensionInventoryListResponse(BaseModel):
    items: list[ExtensionInventoryRead]
    total: int
    page: int
    page_size: int
    identity_window: IdentityWindow
    identity_mode: IdentityMode


class ExtensionVersionChangeListResponse(BaseModel):
    items: list[ExtensionVersionChangeRead]
    total: int
    page: int
    page_size: int
    identity_window: IdentityWindow
    identity_mode: IdentityMode
