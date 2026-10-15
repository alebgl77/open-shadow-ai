"""Tenant-scoped imported network metadata; catalog association never proves AI usage."""

from __future__ import annotations

import asyncio
import math
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from shadai.config import get_config
from shadai.database import get_clickhouse
from shadai.models.event import NETWORK_PROTOCOLS, NetworkProtocol, network_hostname
from shadai.models.user import UserORM
from shadai.security.rbac import require_role

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1/network", tags=["network"])

EVENT_COLUMNS = (
    "event_id", "timestamp", "protocol", "domain", "sni", "url_host", "src_ip", "dst_ip", "dst_port",
    "collector_id", "parser_version", "catalog_match_id", "match_field", "match_confidence",
)
RELATION_SETTINGS = {
    "max_execution_time": 10,
    "max_memory_usage": 256 * 1024 * 1024,
    "max_rows_to_read": 5_000_000,
    "read_overflow_mode": "throw",
    "timeout_overflow_mode": "throw",
}
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
    match_field: str | None = None
    match_confidence: float | None = Field(default=None, ge=0, le=1)


class NetworkRelation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str
    domain: str
    catalog_match_id: str | None
    protocol: NetworkProtocol
    observations: int = Field(ge=1, strict=True)
    first_seen: datetime
    last_seen: datetime


class NetworkRelations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hours: int
    protocol: NetworkProtocol | None
    items: list[NetworkRelation] = Field(max_length=500)
    total_observations: int = Field(ge=0, strict=True)
    total_relations: int = Field(ge=0, strict=True)
    represented_observations: int = Field(ge=0, strict=True)
    represented_relations: int = Field(ge=0, strict=True)
    truncated: bool
    limitations: list[str]


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


def _unavailable(exc: Exception) -> HTTPException:
    logger.warning("network_store_unavailable", error_type=type(exc).__name__)
    return HTTPException(status_code=503, detail="Network observations are temporarily unavailable")


async def _query(sql: str, params: dict, *, settings: dict | None = None):
    try:
        execute = get_clickhouse().execute
        if settings is None:
            return await asyncio.to_thread(execute, sql, params)
        return await asyncio.to_thread(execute, sql, params, settings=settings)
    except Exception as exc:
        raise _unavailable(exc) from None


def _decode[T](build: Callable[[], T]) -> T:
    try:
        return build()
    except Exception as exc:
        raise _unavailable(exc) from None


def _source_ip(value: str) -> str:
    if value == "":
        return value
    if "%" in value:
        raise ValueError("Scoped addresses are not network metadata")
    return str(ip_address(value))


def _in_window(value: datetime, params: dict) -> datetime:
    value = _utc(value)
    start, end = (datetime.fromisoformat(params[key]).replace(tzinfo=UTC) for key in ("start", "end"))
    if not start <= value <= end:
        raise ValueError("Stored timestamp outside requested window")
    return value


def _event(row, params: dict) -> NetworkEventRead:
    item = dict(zip(EVENT_COLUMNS, row, strict=True))
    item["timestamp"] = _in_window(item["timestamp"], params)
    if _source_ip(item["src_ip"]) != item["src_ip"]:
        raise ValueError("Invalid stored source address")
    for parameter, column in (("source_ip", "src_ip"), ("catalog_match_id", "catalog_match_id"),
                              ("protocol", "protocol"), ("domain", "domain")):
        if parameter in params and item[column] != params[parameter]:
            raise ValueError("Stored event outside requested filters")
    item["catalog_match_id"] = item["catalog_match_id"] or None
    item["matched"] = item["catalog_match_id"] is not None
    item["match_field"] = item["match_field"] or None
    score = item["match_confidence"]
    item["match_confidence"] = score if score is not None and math.isfinite(score) else None
    if not item["matched"]:
        item["match_field"] = item["match_confidence"] = None
    event = NetworkEventRead(**item)
    if "event_id" in params and event.event_id != params["event_id"]:
        raise ValueError("Stored event outside requested UUID")
    return event


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
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    catalog_match_id: Annotated[str | None, Query(max_length=128)] = None,
    domain: Annotated[str | None, Query(max_length=253)] = None,
    _user: UserORM = Depends(require_role("analyst")),
):
    """Typed metadata only; the legacy detection event tuple contract is unchanged."""
    base, params = _window(hours, protocol)
    filters = []
    if source_ip is not None:
        try:
            params["source_ip"] = _source_ip(source_ip)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid source IP address") from None
        filters.append("src_ip = %(source_ip)s")
    if catalog_match_id is not None:
        params["catalog_match_id"] = catalog_match_id
        filters.append("catalog_match_id = %(catalog_match_id)s")
    if domain is not None:
        try:
            params["domain"] = network_hostname(domain)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid network hostname") from None
        filters.append("domain = %(domain)s")
    if filters:
        base = f"SELECT {', '.join(EVENT_COLUMNS)} FROM ({base}) WHERE {' AND '.join(filters)}"
    total_rows = await _query(f"SELECT count() FROM ({base})", params)
    rows = await _query(
        f"SELECT {', '.join(EVENT_COLUMNS)} FROM ({base}) ORDER BY timestamp DESC, event_id DESC "
        "LIMIT %(limit)s OFFSET %(offset)s",
        {**params, "limit": page_size, "offset": (page - 1) * page_size},
    )
    return _decode(lambda: NetworkEventPage(
        items=[_event(row, params) for row in rows], total=total_rows[0][0], page=page, page_size=page_size,
    ))


@router.get("/relations", response_model=NetworkRelations)
async def get_network_relations(
    hours: int = Query(24, ge=1, le=168),
    protocol: NetworkProtocol | None = Query(None),
    limit: int = Query(300, ge=1, le=500),
    _user: UserORM = Depends(require_role("analyst")),
):
    """Bounded stored IP/hostname associations; totals precede limiting in one query."""
    base, params = _window(hours, protocol)
    rows = await _query(
        f"""SELECT src_ip, domain, catalog_match_id, protocol, observations, first_seen, last_seen,
        sum(observations) OVER () AS total_observations, count() OVER () AS total_relations
        FROM (SELECT src_ip, domain, catalog_match_id, protocol, count() AS observations,
        min(timestamp) AS first_seen, max(timestamp) AS last_seen FROM ({base})
        GROUP BY src_ip, domain, catalog_match_id, protocol)
        ORDER BY observations DESC, last_seen DESC, src_ip ASC, domain ASC, catalog_match_id ASC, protocol ASC
        LIMIT %(limit)s""",
        {**params, "limit": limit}, settings=RELATION_SETTINGS,
    )

    def build() -> NetworkRelations:
        if not isinstance(rows, (list, tuple)):
            raise ValueError("Invalid aggregate result")
        items = []
        totals = (0, 0) if not rows else tuple(rows[0][7:])
        if len(totals) != 2 or any(type(value) is not int or value < 0 for value in totals):
            raise ValueError("Invalid aggregate totals")
        keys = set()
        for source, domain, catalog, row_protocol, count, first, last, total_obs, total_rel in rows:
            if (total_obs, total_rel) != totals or _source_ip(source) != source:
                raise ValueError("Invalid aggregate scope")
            if protocol is not None and row_protocol != protocol:
                raise ValueError("Invalid aggregate protocol")
            key = (source, domain, catalog, row_protocol)
            if key in keys:
                raise ValueError("Duplicate aggregate relation")
            keys.add(key)
            first, last = _in_window(first, params), _in_window(last, params)
            if first > last:
                raise ValueError("Invalid aggregate ordering")
            items.append(NetworkRelation(
                source_ip=source, domain=domain, catalog_match_id=catalog or None, protocol=row_protocol,
                observations=count, first_seen=first, last_seen=last,
            ))
        represented = sum(item.observations for item in items)
        if len(items) > limit or len(items) > totals[1] or represented > totals[0] or totals[1] > totals[0]:
            raise ValueError("Invalid aggregate coverage")
        if len(items) == totals[1] and represented != totals[0]:
            raise ValueError("Invalid complete aggregate totals")
        return NetworkRelations(
            hours=hours, protocol=protocol, items=items, total_observations=totals[0], total_relations=totals[1],
            represented_observations=represented, represented_relations=len(items),
            truncated=len(items) < totals[1], limitations=LIMITATIONS + [
                "Source IPs are stored observations, not attributed devices; "
                "blank sources may reflect privacy erasure.",
                "Relations are bounded and ordered by observation count; totals cover the full selected window.",
            ],
        )

    return _decode(build)


@router.get("/events/{event_id}", response_model=NetworkEventRead)
async def get_network_event(
    event_id: UUID,
    hours: int = Query(24, ge=1, le=168),
    _user: UserORM = Depends(require_role("analyst")),
):
    """Persisted observation provenance only, within the same tenant and bounded window."""
    base, params = _window(hours)
    params["event_id"] = event_id
    rows = await _query(
        f"SELECT {', '.join(EVENT_COLUMNS)} FROM ({base}) WHERE event_id = %(event_id)s LIMIT 1", params,
        settings=RELATION_SETTINGS,
    )
    if not isinstance(rows, (list, tuple)) or len(rows) > 1:
        raise _unavailable(ValueError("Invalid event result")) from None
    if not rows:
        raise HTTPException(status_code=404, detail="Network observation not found")
    return _decode(lambda: _event(rows[0], params))
