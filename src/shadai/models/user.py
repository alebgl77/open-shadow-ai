"""User ORM model and Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from shadai.models.base import Base, TimestampMixin


# ── SQLAlchemy ORM ───────────────────────────────────────────────
class UserORM(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (
        Index("uq_users_username_key", "username_key", unique=True),
        UniqueConstraint("oidc_issuer", "external_id", name="uq_users_external_identity"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    username_key: Mapped[str] = mapped_column(Text, nullable=False)
    identity_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="local", server_default="local")
    oidc_issuer: Mapped[str | None] = mapped_column(String(1024))
    external_id: Mapped[str | None] = mapped_column(String(255))
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    scim_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    display_name: Mapped[str | None] = mapped_column(String(255))
    given_name: Mapped[str | None] = mapped_column(String(255))
    family_name: Mapped[str | None] = mapped_column(String(255))
    scim_emails: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default="[]")

    @validates("username")
    def normalize_username(self, key, value):
        self.username_key = value.strip().casefold()
        return value.strip()

    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# ── Pydantic Schemas ─────────────────────────────────────────────
class UserBase(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    email: str | None = None
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class UserCreate(UserBase):
    password: str = Field(min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def bcrypt_limit(cls, value):
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    user_id: uuid.UUID
    identity_kind: Literal["local", "scim"] = "local"
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class UserUpdate(BaseModel):
    email: str | None = None
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=72)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class TokenPayload(BaseModel):
    sub: uuid.UUID
    role: str
    exp: int
    jti: uuid.UUID
    tenant_id: str
    session_version: int = Field(default=0, ge=0)
