"""Export API routes — CSV/JSON detection exports with anti-HR abuse warnings."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.api.detections import filter_detections, order_detections
from shadai.database import get_postgres_session
from shadai.models.detection import DetectionORM
from shadai.models.user import UserORM
from shadai.security.audit import log_audit
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])

ANTI_HR_WARNING = (
    "# WARNING: ShadAI is an IT governance tool. This data MUST NOT be used for individual employee "
    "surveillance, disciplinary action, performance evaluation, or behavioral profiling. "
    "Using this data for HR purposes without legal basis violates GDPR and labor law.\n"
)


@router.post("/detections")
async def export_detections(
    format: str = Query("csv", pattern="^(csv|json)$"),
    classification: str | None = None,
    risk_level: str | None = None,
    confidence_level: str | None = None,
    entity_type: str | None = None,
    analyst_status: str | None = None,
    search: str | None = None,
    sort_by: str = "risk_score",
    sort_order: str = "desc",
    request: Request = None,
    current_user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    now = datetime.now(UTC)
    filters = {
        "classification": classification,
        "risk_level": risk_level,
        "confidence_level": confidence_level,
        "entity_type": entity_type,
        "analyst_status": analyst_status,
        "search": search,
    }
    query = order_detections(filter_detections(select(DetectionORM), **filters), sort_by, sort_order, now=now)
    result = await session.execute(query)
    rows = list(result.scalars().all())
    from shadai.utils.privacy import refresh_identity_counts, sanitize_evidence

    detections = await refresh_identity_counts(session, rows, now=now)
    for detection in detections:
        detection.evidence_bundle = sanitize_evidence(detection.evidence_bundle, now=now)

    await log_audit(
        session,
        current_user.user_id,
        current_user.username,
        "export_detections",
        details={
            "format": format,
            "count": len(detections),
            "filters": {key: value for key, value in filters.items() if value},
        },
        ip_address=request.client.host if request.client else None,
    )

    if format == "csv":
        output = io.StringIO()
        output.write(ANTI_HR_WARNING)
        writer = csv.writer(output)
        writer.writerow(
            [
                "entity_name",
                "entity_type",
                "category",
                "classification",
                "confidence_score",
                "confidence_level",
                "risk_score",
                "risk_level",
                "risk_score_stale",
                "governance_status",
                "impacted_users",
                "first_seen",
                "last_seen",
                "analyst_status",
                "sources",
                "reasoning",
                "risk_calculated_at",
            ]
        )
        for d in detections:
            writer.writerow(
                [
                    d.entity_name,
                    d.entity_type,
                    d.entity_category,
                    d.classification,
                    d.confidence_score,
                    d.confidence_level,
                    d.risk_score,
                    d.risk_level,
                    d.risk_score_stale,
                    d.governance_status,
                    d.impacted_users_count,
                    d.first_seen_at.isoformat(),
                    d.last_seen_at.isoformat(),
                    d.analyst_status,
                    ";".join(d.source_types),
                    d.reasoning_summary or "",
                    d.risk_calculated_at.astimezone(UTC).isoformat() if d.risk_calculated_at else "",
                ]
            )
        output.seek(0)
        return StreamingResponse(
            output,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=shadai_detections_{datetime.now():%Y%m%d}.csv",
                "Cache-Control": "no-store",
            },
        )
    else:
        data = {
            "warning": ANTI_HR_WARNING.strip().lstrip("# "),
            "exported_at": datetime.now().isoformat(),
            "count": len(detections),
            "detections": [d.model_dump(mode="json") for d in detections],
        }
        return StreamingResponse(
            io.StringIO(json.dumps(data, indent=2, default=str)),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=shadai_detections_{datetime.now():%Y%m%d}.json",
                "Cache-Control": "no-store",
            },
        )
