"""Dashboard API routes — executive summary, trends, top tools, source health."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.api.ingestion import SOURCE_TYPES
from shadai.config import get_config
from shadai.database import get_clickhouse, get_postgres_session
from shadai.models.detection import DetectionORM
from shadai.models.user import UserORM
from shadai.security.auth import get_current_user

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
async def get_summary(
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Executive dashboard counters."""
    total = (
        await session.scalar(
            select(func.count())
            .select_from(DetectionORM)
            .where(DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]))
        )
        or 0
    )

    unsanctioned = (
        await session.scalar(
            select(func.count())
            .select_from(DetectionORM)
            .where(DetectionORM.classification == "unsanctioned")
            .where(DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]))
        )
        or 0
    )

    high_risk = (
        await session.scalar(
            select(func.count())
            .select_from(DetectionORM)
            .where(DetectionORM.risk_score >= 71)
            .where(DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]))
        )
        or 0
    )

    unreviewed = (
        await session.scalar(
            select(func.count())
            .select_from(DetectionORM)
            .where(DetectionORM.analyst_status == "new")
            .where(DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]))
        )
        or 0
    )

    return {
        "total": total,
        "unsanctioned": unsanctioned,
        "high_risk": high_risk,
        "unreviewed": unreviewed,
    }


@router.get("/trend")
async def get_trend(
    days: int = Query(30, ge=7, le=90),
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Discovery trend over last N days."""
    cutoff = datetime.now(UTC) - timedelta(days=days)
    result = await session.execute(
        select(
            func.date_trunc("day", DetectionORM.created_at).label("date"),
            func.count().label("count"),
        )
        .where(DetectionORM.created_at >= cutoff)
        .group_by(text("1"))
        .order_by(text("1"))
    )
    return [{"date": row.date.isoformat(), "count": row.count} for row in result.all()]


@router.get("/top-tools")
async def get_top_tools(
    limit: int = Query(10, ge=5, le=50),
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Top AI tools by event count."""
    result = await session.execute(
        select(
            DetectionORM.entity_name,
            DetectionORM.entity_type,
            DetectionORM.classification,
            DetectionORM.total_events_count,
            DetectionORM.impacted_users_count,
            DetectionORM.risk_score,
        )
        .where(DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]))
        .order_by(DetectionORM.total_events_count.desc())
        .limit(limit)
    )
    return [
        {
            "name": row.entity_name,
            "entity_type": row.entity_type,
            "classification": row.classification,
            "events_count": row.total_events_count,
            "users_count": row.impacted_users_count,
            "risk_score": row.risk_score,
        }
        for row in result.all()
    ]


@router.get("/source-health")
async def get_source_health(_user: UserORM = Depends(get_current_user)):
    """Last retained event and distinct volume in the rolling preceding hour."""
    rows = await asyncio.to_thread(
        get_clickhouse().execute,
        """
        SELECT source_type, max(timestamp), uniqExactIf(event_id, timestamp > now() - INTERVAL 1 HOUR)
        FROM events WHERE tenant_id = %(tenant)s GROUP BY source_type
    """,
        {"tenant": get_config().tenant_id},
    )
    observed = {row[0]: row[1:] for row in rows}
    now = datetime.now(UTC)
    sources = []
    for source in SOURCE_TYPES:
        last_event, count = observed.get(source, (None, 0))
        if last_event and last_event.tzinfo is None:
            last_event = last_event.replace(tzinfo=UTC)
        age = (now - last_event).total_seconds() if last_event else float("inf")
        sources.append(
            {
                "source_type": source,
                "status": "active" if age < 3600 else "warning" if age < 14400 else "inactive",
                "last_event": last_event.isoformat() if last_event else None,
                "events_per_minute": round(count / 60, 1),
                "events_1h": count,
                "window_hours": 1,
            }
        )
    return sources


@router.get("/evidence")
async def get_evidence(
    days: int = Query(30, ge=1, le=90),
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session),
):
    """Distinct collected evidence, never a proxy for AI calls or prompt inspection."""
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    params = {"tenant": get_config().tenant_id, "start": start, "end": end}
    # LIMIT BY chooses one version after an uncertain ClickHouse-write retry.
    base = """SELECT * FROM events WHERE tenant_id = %(tenant)s
              AND timestamp >= %(start)s AND timestamp <= %(end)s
              ORDER BY normalized_at DESC LIMIT 1 BY event_id"""
    ch = get_clickhouse()

    async def query(sql):
        return await asyncio.to_thread(ch.execute, sql, params)

    totals = (
        await query(f"""SELECT count(),
        uniqExactIf(if(user_id != '', user_id, username), user_id != '' OR username != ''),
        uniqExactIf(if(device_id != '', device_id, hostname), device_id != '' OR hostname != ''),
        countIf(model != '' AND model_provenance != 'unknown'),
        countIf(input_tokens IS NOT NULL OR output_tokens IS NOT NULL), countIf(cost_usd IS NOT NULL),
        sumOrNull(input_tokens), sumOrNull(output_tokens), sumOrNull(cost_usd)
        FROM ({base})""")
    )[0]
    by_source = await query(
        f"SELECT source_type, evidence_type, count() FROM ({base}) GROUP BY source_type, evidence_type"
    )
    model_rows = await query(f"""SELECT provider, model, model_provenance, count() FROM ({base})
                              WHERE model != '' AND model_provenance != 'unknown'
                              GROUP BY provider, model, model_provenance ORDER BY count() DESC LIMIT 100""")
    category_rows = await query(f"SELECT catalog_match_id, count() FROM ({base}) GROUP BY catalog_match_id")
    from shadai.models.catalog import CatalogItemORM

    result = await session.execute(select(CatalogItemORM.catalog_item_id, CatalogItemORM.category))
    categories = dict(result.all())
    grouped = {}
    for item_id, count in category_rows:
        category = categories.get(item_id, "unmatched")
        grouped[category] = grouped.get(category, 0) + count
    return {
        "window_days": days,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "total_events": totals[0],
        "unique_users": totals[1],
        "unique_devices": totals[2],
        "by_category": [{"category": category, "events": count} for category, count in sorted(grouped.items())],
        "by_source": [
            {"source_type": source, "evidence_type": kind, "events": count} for source, kind, count in by_source
        ],
        "models": [
            {"provider": provider, "model": model, "model_provenance": provenance, "events": count}
            for provider, model, provenance, count in model_rows
        ],
        "measurement": {
            "model_known_events": totals[3],
            "tokens_reported_events": totals[4],
            "cost_reported_events": totals[5],
            "input_tokens": totals[6],
            "output_tokens": totals[7],
            "cost_usd": totals[8],
        },
    }
