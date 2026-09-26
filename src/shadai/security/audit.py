"""Audit logging utility for tracking all user actions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from shadai.models.audit import AuditLogORM


async def log_audit(
    session: AsyncSession,
    user_id: uuid.UUID,
    username: str,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Insert an audit log entry. Called after every mutation."""
    entry = AuditLogORM(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        timestamp=datetime.now(UTC),
    )
    session.add(entry)
    # Don't commit here — let the caller's session context handle it
