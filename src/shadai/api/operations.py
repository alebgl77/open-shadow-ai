"""Tenant-filtered collector health; admin-only deployment queue health."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import JSONResponse

from shadai.api.operations_schema import CollectorHealthPage, PipelineHealth
from shadai.config import get_config
from shadai.database import get_postgres_session, get_redis
from shadai.models.collector import CollectorORM
from shadai.models.user import UserORM
from shadai.security.auth import get_current_user, oauth2_scheme, request_token
from shadai.security.rbac import require_role
from shadai.utils.operations import SOURCES, integer, read_pipeline, unavailable_pipeline

router = APIRouter(prefix='/api/v1/operations', tags=['operations'])
CONTACT_FRESH_SECONDS = 3600
REPORTED_KEYS = ('queue_events', 'queued_bytes', 'dropped_events', 'expired_events', 'rejected_events')


def deployment_identity(user):
    # Console authentication validates the signed JWT tenant before loading the
    # deployment's users. Keep this explicit if a future user carries a tenant.
    if getattr(user, 'tenant_id', get_config().tenant_id) != get_config().tenant_id:
        raise HTTPException(403, 'Wrong organization')


def aware(value):
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def collector_health(row, now):
    contact, heartbeat, observed = (aware(getattr(row, key)) for key in
                                    ('last_contact_at', 'last_heartbeat_at', 'last_observed_at'))
    fresh = contact is not None and 0 <= (now - contact).total_seconds() <= CONTACT_FRESH_SECONDS
    report_fresh = heartbeat is not None and 0 <= (now - heartbeat).total_seconds() <= CONTACT_FRESH_SECONDS
    if not row.is_active or row.revoked_at is not None:
        status = 'revoked'
    elif contact is None:
        status = 'unknown'
    elif not fresh:
        status = 'stale'
    elif observed is None or (now - observed).total_seconds() > CONTACT_FRESH_SECONDS:
        status = 'quiet'
    else:
        status = 'active'
    counters = row.client_counters if isinstance(row.client_counters, dict) else {}
    return {'collector_id': row.collector_id, 'display_name': row.display_name,
            'allowed_source_types': [value for value in row.allowed_source_types if value in SOURCES],
            'status': status, 'last_server_contact_at': contact, 'last_heartbeat_at': heartbeat,
            'last_observed_at': observed, 'server_contact_fresh': fresh, 'capture_loss': None,
            'client_reported': {'provenance': 'client_reported', 'as_of': heartbeat, 'fresh': report_fresh,
                                **{key: integer(counters.get(key)) for key in REPORTED_KEYS},
                                'last_success_at': aware(row.client_last_success_at)}}


@router.get('/collectors', response_model=CollectorHealthPage)
async def collectors_health(
    offset: int = Query(0, ge=0, le=1000000), limit: int = Query(100, ge=1, le=500),
    user: UserORM = Depends(require_role('analyst')),
    session: AsyncSession = Depends(get_postgres_session, scope='function'),
):
    deployment_identity(user)
    now = datetime.now(UTC)
    query = select(CollectorORM).where(CollectorORM.tenant_id == get_config().tenant_id)
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = (await session.execute(query.order_by(CollectorORM.collector_id).offset(offset).limit(limit))).scalars()
    return {'items': [collector_health(row, now) for row in rows], 'total': total,
            'offset': offset, 'limit': limit, 'as_of': now}


async def current_pipeline():
    try:
        return await read_pipeline(await get_redis())
    except Exception:
        return unavailable_pipeline()


@router.get('/pipeline', response_model=PipelineHealth)
async def pipeline_health(user: UserORM = Depends(require_role('admin'))):
    deployment_identity(user)
    snapshot = await current_pipeline()
    return snapshot if snapshot['backend_available'] else JSONResponse(snapshot, status_code=503)


async def metrics_access(
    request: Request, bearer: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_postgres_session, scope='function'),
):
    """Scrape secret has read-only installation scope, separate from agent keys."""
    key = get_config().security.metrics_api_key
    if bearer and key and hmac.compare_digest(bearer.encode(), key.get_secret_value().encode()):
        return 'deployment_scrape'
    token = await request_token(request, bearer)
    user = await get_current_user(token, session)
    if user.role != 'admin':
        raise HTTPException(403, 'Requires admin role')
    deployment_identity(user)
    return 'deployment_admin'
