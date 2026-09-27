"""Governance policy API routes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.database import get_postgres_session
from shadai.engine.governance import apply_policy
from shadai.models.detection import DetectionORM
from shadai.models.governance import GovernanceCreate, GovernanceORM, GovernanceRead, GovernanceUpdate
from shadai.models.user import UserORM
from shadai.security.audit import log_audit
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/governance", tags=["governance"])


@router.get("/", response_model=list[GovernanceRead])
async def list_governance(
    target_type: str | None = None,
    _user: UserORM = Depends(require_role("viewer")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    query = select(GovernanceORM)
    if target_type:
        query = query.where(GovernanceORM.target_type == target_type)
    result = await session.execute(query.order_by(GovernanceORM.created_at.desc()))
    return [GovernanceRead.model_validate(g) for g in result.scalars().all()]


@router.post("/", response_model=GovernanceRead, status_code=201)
async def create_governance(
    body: GovernanceCreate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    if body.target_type == "catalog_item":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": "catalog:" + body.target_id}
        )
    gov = GovernanceORM(
        target_type=body.target_type,
        target_id=body.target_id,
        org_classification=body.org_classification,
        owner=body.owner,
        exception_policy=body.exception_policy,
        enforcement_mode=body.enforcement_mode,
        justification=body.justification,
        approved_by=body.approved_by,
        approved_at=body.approved_at,
        approved_until=body.approved_until,
        created_by=admin.user_id,
    )
    session.add(gov)
    await session.flush()

    await _apply_policy_to_detections(session, gov)

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "create_governance",
        resource_type="governance",
        resource_id=str(gov.governance_id),
        details=body.model_dump(mode="json"),
        ip_address=request.client.host if request.client else None,
    )

    return GovernanceRead.model_validate(gov)


@router.put("/{governance_id}", response_model=GovernanceRead)
async def update_governance(
    governance_id: uuid.UUID,
    body: GovernanceUpdate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(GovernanceORM).where(GovernanceORM.governance_id == governance_id))
    gov = result.scalar_one_or_none()
    if not gov:
        raise HTTPException(status_code=404, detail="Governance policy not found")

    if gov.target_type == "catalog_item":
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": "catalog:" + gov.target_id}
        )
        # The initial read may predate a writer that held this lock. Reload its
        # committed fields before applying a partial update or cascading policy.
        await session.refresh(gov)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(gov, field, value)

    # Date changes can expire or reactivate approval without changing its label.
    await _apply_policy_to_detections(session, gov)

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "update_governance",
        resource_type="governance",
        resource_id=str(governance_id),
        details=body.model_dump(mode="json", exclude_none=True),
        ip_address=request.client.host if request.client else None,
    )

    await session.flush()
    await session.refresh(gov)
    return GovernanceRead.model_validate(gov)


async def _apply_policy_to_detections(session, policy):
    target = (
        DetectionORM.catalog_item_id == policy.target_id
        if policy.target_type == "catalog_item"
        else DetectionORM.governance_id == policy.governance_id
    )
    result = await session.execute(select(DetectionORM).where(target).with_for_update())
    for detection in result.scalars().all():
        apply_policy(detection, policy)
