"""Admin enrollment and scoped collector authentication.

POST /collectors issues a single-use response containing ``api_key``; inventories
never expose it. Rotation overlaps previous keys for at most 86400 seconds;
revoke permanently disables that immutable collector identity. Scoped keys use
``sc_<public UUID hex>.<opaque secret>`` in X-API-Key. Shared keys are explicitly
legacy/unattributed and cannot submit authenticated health metadata.
"""

from __future__ import annotations

import hmac
import re
import secrets
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.config import get_config
from shadai.database import get_postgres_session, postgres_session_factory
from shadai.models.collector import CollectorCredentialORM, CollectorORM
from shadai.models.user import UserORM
from shadai.security.audit import log_audit
from shadai.security.rbac import require_role

SOURCE_TYPES = ("dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb", "network")
TOKEN_PATTERN = re.compile(r"^sc_([a-f0-9]{32})\.([A-Za-z0-9_-]{43})$")
router = APIRouter(prefix="/api/v1/collectors", tags=["collectors"])


def utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value


@dataclass(frozen=True)
class CollectorPrincipal:
    collector_id: str
    allowed_source_types: frozenset[str]
    legacy: bool = False
    collector: CollectorORM | None = field(default=None, repr=False, compare=False)

    def require_sources(self, sources) -> None:
        if not set(sources).issubset(self.allowed_source_types):
            raise HTTPException(status_code=403, detail="Collector source is not allowed")

    def bind(self, collector_id: str) -> str:
        if self.legacy:
            return self.collector_id
        if collector_id != self.collector_id:
            raise HTTPException(status_code=403, detail="Collector identity does not match credential")
        return self.collector_id

    def contact(self, observed_at: datetime | None = None, *, heartbeat: bool = False) -> None:
        if self.collector is None:
            return
        now = datetime.now(UTC)
        self.collector.last_contact_at = now
        if heartbeat:
            self.collector.last_heartbeat_at = now
        previous = utc(self.collector.last_observed_at)
        if observed_at is not None and (previous is None or observed_at > previous):
            self.collector.last_observed_at = observed_at


def validate_legacy_key(value: str | None) -> str:
    config = get_config().security
    expected = config.agent_api_key
    if (
        not config.allow_legacy_agent_key
        or not value
        or len(value) > 4096
        or len(expected.encode()) < 32
        or not hmac.compare_digest(value.encode(), expected.encode())
    ):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return value


async def authenticate_collector(x_api_key: str | None = Header(None)) -> AsyncGenerator[CollectorPrincipal, None]:
    """Lock collector through accepted request, serializing rotation and revocation.

    Function-scoped dependency cleanup commits before FastAPI sends the response.
    No key cache may mask revoked/expired credentials. Legacy mode needs no registry.
    """
    if not x_api_key or len(x_api_key) > 4096:
        raise HTTPException(status_code=401, detail="Invalid API key")
    config = get_config().security
    if (
        config.allow_legacy_agent_key
        and len(config.agent_api_key.encode()) >= 32
        and hmac.compare_digest(x_api_key.encode(), config.agent_api_key.encode())
    ):
        yield CollectorPrincipal("legacy:unattributed", frozenset(SOURCE_TYPES), legacy=True)
        return
    if not x_api_key.startswith("sc_"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    parsed = TOKEN_PATTERN.fullmatch(x_api_key)
    if parsed is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    credential_id = uuid.UUID(hex=parsed[1])
    async with postgres_session_factory()() as session:
        try:
            collector = (
                await session.execute(
                    select(CollectorORM)
                    .join(CollectorCredentialORM, CollectorCredentialORM.collector_id == CollectorORM.collector_id)
                    .where(
                        CollectorCredentialORM.credential_id == credential_id,
                        CollectorORM.tenant_id == get_config().tenant_id,
                    )
                    .with_for_update(of=CollectorORM)
                )
            ).scalar_one_or_none()
            now = datetime.now(UTC)
            if collector is None:
                # Also compare for an unknown public id; token details never reach error text.
                hmac.compare_digest(sha256(parsed[2].encode()).hexdigest(), "0" * 64)
                raise HTTPException(status_code=401, detail="Invalid API key")
            # Fetch after obtaining the collector lock. A statement waiting on a
            # rotation must not use its earlier MVCC snapshot of the credential.
            credential = await session.get(CollectorCredentialORM, credential_id)
            matches = hmac.compare_digest(sha256(parsed[2].encode()).hexdigest(), credential.secret_digest)
            if (
                not matches
                or not collector.is_active
                or collector.revoked_at is not None
                or credential.revoked_at is not None
                or utc(credential.expires_at) <= now
            ):
                raise HTTPException(status_code=401, detail="Invalid API key")
            yield CollectorPrincipal(
                collector.collector_id, frozenset(collector.allowed_source_types), collector=collector
            )
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class CollectorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collector_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    display_name: str = Field(min_length=1, max_length=255)
    allowed_source_types: list[str] = Field(min_length=1, max_length=len(SOURCE_TYPES))
    expires_in_days: int = Field(default=365, ge=1, le=365, strict=True)

    @field_validator("collector_id")
    @classmethod
    def enrolled_namespace(cls, value):
        if value.startswith("legacy:"):
            raise ValueError("Legacy identity namespace is reserved")
        return value

    @field_validator("allowed_source_types")
    @classmethod
    def canonical_sources(cls, value):
        if len(set(value)) != len(value) or not set(value).issubset(SOURCE_TYPES):
            raise ValueError("Source types must be distinct canonical source names")
        return sorted(value)


class CollectorRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    overlap_seconds: int = Field(default=3600, ge=0, le=86400, strict=True)
    expires_in_days: int = Field(default=365, ge=1, le=365, strict=True)


def issue_credential(collector: CollectorORM, days: int) -> tuple[CollectorCredentialORM, str]:
    public_id, secret, now = uuid.uuid4(), secrets.token_urlsafe(32), datetime.now(UTC)
    credential = CollectorCredentialORM(
        credential_id=public_id,
        collector_id=collector.collector_id,
        secret_digest=sha256(secret.encode()).hexdigest(),
        generation=collector.credential_generation,
        created_at=now,
        expires_at=now + timedelta(days=days),
    )
    return credential, f"sc_{public_id.hex}.{secret}"


def collector_view(collector: CollectorORM) -> dict:
    now, contact, observed = datetime.now(UTC), utc(collector.last_contact_at), utc(collector.last_observed_at)
    if not collector.is_active:
        status = "revoked"
    elif contact is None:
        status = "unknown"
    elif (now - contact).total_seconds() >= 3600:
        status = "inactive"
    elif observed is None:
        status = "quiet"
    elif (now - observed).total_seconds() >= 3600:
        status = "replay_or_quiet"
    else:
        status = "active"
    return {
        "collector_id": collector.collector_id,
        "display_name": collector.display_name,
        "allowed_source_types": collector.allowed_source_types,
        "is_active": collector.is_active,
        "status": status,
        "last_contact_at": collector.last_contact_at,
        "last_heartbeat_at": collector.last_heartbeat_at,
        "last_observed_at": collector.last_observed_at,
        "client_version": collector.client_version,
        "client_last_success_at": collector.client_last_success_at,
        "client_counters": collector.client_counters,
        "created_at": collector.created_at,
        "revoked_at": collector.revoked_at,
    }


async def lifecycle_audit(session, admin, request, action, collector, details=None):
    await log_audit(
        session,
        admin.user_id,
        admin.username,
        action,
        resource_type="collector",
        resource_id=collector.collector_id,
        details=details or {},
        ip_address=request.client.host if request.client else None,
    )


@router.post("", status_code=201)
async def enroll_collector(
    body: CollectorCreate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    collector = CollectorORM(
        collector_id=body.collector_id,
        tenant_id=get_config().tenant_id,
        display_name=body.display_name,
        allowed_source_types=body.allowed_source_types,
        is_active=True,
        credential_generation=1,
        client_counters={},
    )
    session.add(collector)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise HTTPException(status_code=409, detail="Collector identity already exists") from None
    credential, token = issue_credential(collector, body.expires_in_days)
    session.add(credential)
    await lifecycle_audit(
        session, admin, request, "enroll_collector", collector, {"allowed_source_types": body.allowed_source_types}
    )
    await session.commit()
    return {
        "collector": collector_view(collector),
        "credential_id": credential.credential_id,
        "api_key": token,
        "expires_at": credential.expires_at,
    }


@router.get("")
async def list_collectors(
    offset: int = Query(0, ge=0, le=1000000),
    limit: int = Query(100, ge=1, le=500),
    _admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    query = select(CollectorORM).where(CollectorORM.tenant_id == get_config().tenant_id)
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await session.execute(query.order_by(CollectorORM.collector_id).offset(offset).limit(limit))).scalars()
    return {
        "items": [collector_view(collector) for collector in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


async def locked_collector(session: AsyncSession, collector_id: str) -> CollectorORM:
    collector = (
        await session.execute(
            select(CollectorORM)
            .where(CollectorORM.collector_id == collector_id, CollectorORM.tenant_id == get_config().tenant_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if collector is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    return collector


@router.post("/{collector_id}/rotate")
async def rotate_collector(
    collector_id: str,
    body: CollectorRotate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    collector = await locked_collector(session, collector_id)
    if not collector.is_active or collector.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Collector is revoked")
    deadline = datetime.now(UTC) + timedelta(seconds=body.overlap_seconds)
    # Only shorten existing deadlines: a second rotation cannot revive/extend an old overlap.
    await session.execute(
        update(CollectorCredentialORM)
        .where(
            CollectorCredentialORM.collector_id == collector_id,
            CollectorCredentialORM.expires_at > deadline,
            CollectorCredentialORM.revoked_at.is_(None),
        )
        .values(expires_at=deadline)
    )
    collector.credential_generation += 1
    credential, token = issue_credential(collector, body.expires_in_days)
    session.add(credential)
    await lifecycle_audit(
        session, admin, request, "rotate_collector", collector, {"overlap_seconds": body.overlap_seconds}
    )
    await session.commit()
    return {
        "credential_id": credential.credential_id,
        "api_key": token,
        "expires_at": credential.expires_at,
        "previous_valid_until": deadline,
    }


@router.post("/{collector_id}/revoke")
async def revoke_collector(
    collector_id: str,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    collector = await locked_collector(session, collector_id)
    if collector.is_active:
        collector.is_active, collector.revoked_at = False, datetime.now(UTC)
        await session.execute(
            update(CollectorCredentialORM)
            .where(CollectorCredentialORM.collector_id == collector_id, CollectorCredentialORM.revoked_at.is_(None))
            .values(revoked_at=collector.revoked_at)
        )
        await lifecycle_audit(session, admin, request, "revoke_collector", collector)
    await session.commit()
    return collector_view(collector)
