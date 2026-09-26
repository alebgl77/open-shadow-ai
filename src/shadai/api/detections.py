"""Detections CRUD API routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.config import get_config
from shadai.database import get_clickhouse, get_postgres_session
from shadai.engine.governance import rescore_classification
from shadai.models.detection import DetectionListResponse, DetectionORM, DetectionRead, DetectionUpdate
from shadai.models.user import UserORM
from shadai.security.audit import log_audit
from shadai.security.auth import get_current_user
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/detections", tags=["detections"])


def _confidence_level(score: float) -> str:
    if score >= 0.90:
        return "very_high"
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def _risk_level(score: int) -> str:
    if score >= 86:
        return "critical"
    if score >= 71:
        return "high"
    if score >= 51:
        return "medium"
    if score >= 26:
        return "low"
    return "info"


RISK_THRESHOLDS = {"critical": 86, "high": 71, "medium": 51, "low": 26, "info": 0}
CONF_THRESHOLDS = {"very_high": 0.90, "high": 0.70, "medium": 0.40, "low": 0.0}


@router.get("/", response_model=DetectionListResponse)
async def list_detections(
    classification: str | None = None,
    risk_level: str | None = None,
    confidence_level: str | None = None,
    entity_type: str | None = None,
    analyst_status: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    query = select(DetectionORM).where(DetectionORM.shadow_ai_status.notin_(["archived"]))

    if classification:
        query = query.where(DetectionORM.classification.in_(classification.split(",")))
    if entity_type:
        query = query.where(DetectionORM.entity_type.in_(entity_type.split(",")))
    if analyst_status:
        query = query.where(DetectionORM.analyst_status.in_(analyst_status.split(",")))
    if search:
        query = query.where(
            or_(
                DetectionORM.entity_name.ilike(f"%{search}%"),
                DetectionORM.catalog_item_id.ilike(f"%{search}%"),
            )
        )
    if risk_level:
        levels = risk_level.split(",")
        conditions = []
        for lvl in levels:
            if lvl not in RISK_THRESHOLDS:
                raise HTTPException(status_code=422, detail="Invalid risk level")
            lo = RISK_THRESHOLDS[lvl]
            hi = {"critical": 100, "high": 85, "medium": 70, "low": 50, "info": 25}.get(lvl, 100)
            conditions.append(DetectionORM.risk_score.between(lo, hi))
        if conditions:
            query = query.where(or_(*conditions))

    if confidence_level:
        ranges = {"very_high": (0.90, 1.01), "high": (0.70, 0.90), "medium": (0.40, 0.70), "low": (0, 0.40)}
        levels = confidence_level.split(",")
        if any(level not in ranges for level in levels):
            raise HTTPException(status_code=422, detail="Invalid confidence level")
        query = query.where(
            or_(
                *[
                    (DetectionORM.confidence_score >= ranges[level][0])
                    & (DetectionORM.confidence_score < ranges[level][1])
                    for level in levels
                ]
            )
        )

    # Total count
    count_q = select(func.count()).select_from(query.subquery())
    total = await session.scalar(count_q) or 0

    # Sorting
    sort_columns = {
        key: getattr(DetectionORM, key)
        for key in (
            "last_seen_at",
            "first_seen_at",
            "risk_score",
            "confidence_score",
            "entity_name",
            "total_events_count",
        )
    }
    if sort_by not in sort_columns or sort_order not in {"asc", "desc"}:
        raise HTTPException(status_code=422, detail="Invalid sort")
    sort_col = sort_columns[sort_by]
    if sort_order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    # Pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await session.execute(query)
    detections = result.scalars().all()

    return DetectionListResponse(
        items=[DetectionRead.model_validate(d) for d in detections],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{detection_id}", response_model=DetectionRead)
async def get_detection(
    detection_id: uuid.UUID,
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    result = await session.execute(select(DetectionORM).where(DetectionORM.detection_id == detection_id))
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    return DetectionRead.model_validate(detection)


@router.patch("/{detection_id}", response_model=DetectionRead)
async def update_detection(
    detection_id: uuid.UUID,
    body: DetectionUpdate,
    request: Request,
    current_user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session),
):
    result = await session.execute(
        select(DetectionORM).where(DetectionORM.detection_id == detection_id).with_for_update()
    )
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    changes = {}
    if body.classification is not None:
        detection.classification = body.classification
        # An explicit analyst classification is a decision now, independent of the
        # last policy snapshot. A future collected event resolves the current policy.
        detection.governance_id = None
        bundle = dict(detection.evidence_bundle or {})
        bundle.pop("_governance", None)
        detection.evidence_bundle = bundle
        rescore_classification(detection)
        changes["classification"] = body.classification
    if body.analyst_status is not None:
        detection.analyst_status = body.analyst_status
        if body.analyst_status == "false_positive":
            detection.shadow_ai_status = "false_positive"
        elif detection.shadow_ai_status == "false_positive":
            detection.shadow_ai_status = "suspected"
        changes["analyst_status"] = body.analyst_status
    if body.analyst_notes is not None:
        # Append note with timestamp
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        note_line = f"[{ts}] {current_user.username}: {body.analyst_notes}"
        existing = detection.analyst_notes or ""
        detection.analyst_notes = f"{existing}\n{note_line}".strip()
        changes["note_added"] = True
    if body.recommended_action is not None:
        detection.recommended_action = body.recommended_action
        changes["recommended_action"] = body.recommended_action

    detection.analyst_id = current_user.user_id
    detection.reviewed_at = datetime.now(UTC)

    await log_audit(
        session,
        current_user.user_id,
        current_user.username,
        "update_detection",
        resource_type="detection",
        resource_id=str(detection_id),
        details=changes,
        ip_address=request.client.host if request.client else None,
    )

    return DetectionRead.model_validate(detection)


@router.post("/{detection_id}/notes")
async def add_note(
    detection_id: uuid.UUID,
    note: str = Query(..., min_length=1, max_length=2000),
    request: Request = None,
    current_user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session),
):
    result = await session.execute(select(DetectionORM).where(DetectionORM.detection_id == detection_id))
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    note_line = f"[{ts}] {current_user.username}: {note}"
    existing = detection.analyst_notes or ""
    detection.analyst_notes = f"{existing}\n{note_line}".strip()
    detection.analyst_id = current_user.user_id
    detection.reviewed_at = datetime.now(UTC)

    return {"message": "Note added"}


@router.get("/{detection_id}/events")
async def get_detection_events(
    detection_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Get ClickHouse events linked to this detection."""
    result = await session.execute(
        select(DetectionORM.catalog_item_id).where(DetectionORM.detection_id == detection_id)
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Detection not found")

    catalog_item_id = row[0]
    ch = get_clickhouse()
    offset = (page - 1) * page_size

    events = ch.execute(
        """
        SELECT * FROM (
            SELECT * FROM events WHERE catalog_match_id = %(cid)s AND tenant_id = %(tenant)s
            ORDER BY normalized_at DESC LIMIT 1 BY event_id
        ) ORDER BY timestamp DESC LIMIT %(limit)s OFFSET %(offset)s
        """,
        {"cid": catalog_item_id, "tenant": get_config().tenant_id, "limit": page_size, "offset": offset},
    )

    total = ch.execute(
        "SELECT uniqExact(event_id) FROM events WHERE catalog_match_id = %(cid)s AND tenant_id = %(tenant)s",
        {"cid": catalog_item_id, "tenant": get_config().tenant_id},
    )[0][0]

    return {"items": events, "total": total, "page": page, "page_size": page_size}


@router.get("/{detection_id}/timeline")
async def get_detection_timeline(
    detection_id: uuid.UUID,
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Build timeline from evidence bundle and audit logs."""
    result = await session.execute(select(DetectionORM).where(DetectionORM.detection_id == detection_id))
    detection = result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    timeline = []

    # First seen
    timeline.append(
        {
            "type": "first_seen",
            "timestamp": detection.first_seen_at.isoformat(),
            "description": "First detected",
        }
    )

    # Per-source first seen from evidence bundle
    for source_type, evidence in (detection.evidence_bundle or {}).items():
        if source_type in ("confidence_factors", "risk_factors"):
            continue
        if isinstance(evidence, dict) and "first_seen" in evidence:
            timeline.append(
                {
                    "type": "source_first_seen",
                    "timestamp": evidence["first_seen"],
                    "description": f"First seen via {source_type}",
                    "source_type": source_type,
                }
            )

    # Last seen
    timeline.append(
        {
            "type": "last_seen",
            "timestamp": detection.last_seen_at.isoformat(),
            "description": "Last activity",
        }
    )

    # Sort by timestamp
    timeline.sort(key=lambda x: x["timestamp"])
    return timeline
