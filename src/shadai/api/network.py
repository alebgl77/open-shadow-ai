"""Tenant-scoped imported network metadata; catalog association never proves AI usage."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shadai.config import get_config
from shadai.database import get_clickhouse
from shadai.models.event import NETWORK_PROTOCOLS, NetworkProtocol
from shadai.models.user import UserORM
from shadai.security.rbac import require_role

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/network", tags=["network"])

EVENT_COLUMNS = (
    "event_id", "timestamp", "protocol", "domain", "sni", "url_host", "src_ip", "dst_ip", "dst_port",
    "collector_id", "parser_version", "catalog_match_id",
)
LIMITATIONS = [
    "Counts cover imported observations only; unobserved traffic and sensor outages are unknown.",
    "A catalog match associates a hostname with a service; it does not prove AI usage or a model.",
    "DNS records can reflect lookups, prefetching or caching without a connection.",
    "TLS and QUIC SNI, and HTTP Host, expose names only; encrypted content, prompts and tokens are unknown.",
    "Observations without a hostname remain unattributed; IP addresses do not identify users or AI services.",
    "Sensor summaries show at most 100 collectors in the selected window.",
]


class NetworkSensor(BaseModel):
    collector_id: str
    last_seen: datetime
    observations: int = Field(ge=0)


class NetworkOverview(BaseModel):
    hours: int
    total_observations: int = Field(ge=0)
    named_observations: int = Field(ge=0)
    matched_observations: int = Field(ge=0)
    unmatched_observations: int = Field(ge=0)
    protocols: dict[NetworkProtocol, int]
    sensors: list[NetworkSensor] = Field(max_length=100)
    limitations: list[str]


class NetworkEventRead(BaseModel):
    event_id: UUID
    timestamp: datetime
    protocol: NetworkProtocol
    domain: str
    sni: str
    url_host: str
    src_ip: str
    dst_ip: str
    dst_port: int
    collector_id: str
    parser_version: str
    matched: bool
    catalog_match_id: str | None


class NetworkEventPage(BaseModel):
    items: list[NetworkEventRead]
    total: int = Field(ge=0)
    page: int
    page_size: int


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _window(hours: int, protocol: NetworkProtocol | None = None) -> tuple[str, dict]:
    end = datetime.now(UTC)
    # The driver drops datetime fractions; UTC strings retain precise window bounds.
    params = {
        "tenant": get_config().tenant_id,
        "start": (end - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S.%f"),
        "end": end.strftime("%Y-%m-%d %H:%M:%S.%f"),
    }
    protocol_filter = ""
    if protocol is not None:
        # The protocol is a validated enum and remains a parameter, never SQL text.
        protocol_filter = " AND protocol = %(protocol)s"
        params["protocol"] = protocol
    columns = ", ".join(EVENT_COLUMNS)
    base = f"""SELECT {columns} FROM events
        WHERE tenant_id = %(tenant)s AND source_type = 'network'
        AND timestamp >= toDateTime64(%(start)s, 6, 'UTC')
        AND timestamp <= toDateTime64(%(end)s, 6, 'UTC'){protocol_filter}
        ORDER BY normalized_at DESC LIMIT 1 BY event_id"""
    return base, params


async def _query(sql: str, params: dict):
    try:
        return await asyncio.to_thread(get_clickhouse().execute, sql, params)
    except Exception as exc:
        logger.warning("network_store_unavailable", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="Network observations are temporarily unavailable") from None


@router.get("/overview", response_model=NetworkOverview)
async def get_network_overview(
    hours: int = Query(24, ge=1, le=168),
    _user: UserORM = Depends(require_role("analyst")),
):
    """Actual UUID-deduplicated imported observations, bounded to the configured tenant."""
    base, params = _window(hours)
    totals = (
        await _query(
            f"""SELECT count(), countIf(domain != ''), countIf(catalog_match_id != ''),
            countIf(protocol = 'DNS'), countIf(protocol = 'TLS'), countIf(protocol = 'QUIC'), countIf(protocol = 'HTTP')
            FROM ({base})""",
            params,
        )
    )[0]
    sensors = await _query(
        f"""SELECT collector_id, max(timestamp), count() FROM ({base})
        GROUP BY collector_id ORDER BY max(timestamp) DESC, collector_id ASC LIMIT 100""",
        params,
    )
    return NetworkOverview(
        hours=hours,
        total_observations=totals[0],
        named_observations=totals[1],
        matched_observations=totals[2],
        unmatched_observations=totals[0] - totals[2],
        protocols=dict(zip(NETWORK_PROTOCOLS, totals[3:], strict=True)),
        sensors=[
            NetworkSensor(collector_id=collector, last_seen=_utc(last_seen), observations=count)
            for collector, last_seen, count in sensors
        ],
        limitations=LIMITATIONS,
    )


@router.get("/events", response_model=NetworkEventPage)
async def get_network_events(
    hours: int = Query(24, ge=1, le=168),
    protocol: NetworkProtocol | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    _user: UserORM = Depends(require_role("analyst")),
):
    """Typed metadata only; the legacy detection event tuple contract is unchanged."""
    base, params = _window(hours, protocol)
    total = (await _query(f"SELECT count() FROM ({base})", params))[0][0]
    rows = await _query(
        f"SELECT {', '.join(EVENT_COLUMNS)} FROM ({base}) ORDER BY timestamp DESC, event_id DESC "
        "LIMIT %(limit)s OFFSET %(offset)s",
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    )
    items = []
    for row in rows:
        item = dict(zip(EVENT_COLUMNS, row, strict=True))
        item["timestamp"] = _utc(item["timestamp"])
        item["catalog_match_id"] = item["catalog_match_id"] or None
        item["matched"] = item["catalog_match_id"] is not None
        items.append(NetworkEventRead(**item))
    return NetworkEventPage(items=items, total=total, page=page, page_size=page_size)
