"""Audit log API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.database import get_postgres_session
from shadai.models.audit import AuditLogORM, AuditLogRead
from shadai.models.user import UserORM
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogRead])
async def list_audit_logs(
    user_id: str | None = None,
    action: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=200),
    _admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    query = select(AuditLogORM)

    if user_id:
        query = query.where(AuditLogORM.user_id == user_id)
    if action:
        query = query.where(AuditLogORM.action == action)

    query = query.order_by(AuditLogORM.timestamp.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await session.execute(query)
    return [AuditLogRead.model_validate(entry) for entry in result.scalars().all()]
