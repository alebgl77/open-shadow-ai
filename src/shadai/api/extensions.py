"""Browser extension inventory read API: current installations and their version history.

Every response is bounded to the identity retention window and to rows written under the
current encryption key, because the purge worker runs daily and the tables can hold rows past
either bound between cycles. Per-installation rows carry host and user labels, so they and the
version-change feed require the analyst role; any signed-in user may read the aggregate summary,
which never names a host or a user.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import case, distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from shadai.config import get_config
from shadai.database import get_postgres_session
from shadai.engine.extension_inventory import visible_installations
from shadai.models.detection import DetectionORM
from shadai.models.event import EXTENSION_INSTALL_SOURCES
from shadai.models.extension_inventory import (
    INVENTORY_INSTALL_SOURCES,
    ExtensionInstallationHistory,
    ExtensionInventoryListResponse,
    ExtensionInventoryORM,
    ExtensionInventoryRead,
    ExtensionInventorySummary,
    ExtensionVersionChangeListResponse,
    ExtensionVersionChangeORM,
    ExtensionVersionChangeRead,
    IdentityMode,
    IdentityWindow,
)
from shadai.models.user import UserORM
from shadai.security.auth import get_current_user
from shadai.security.rbac import require_role
from shadai.utils.privacy import identity_cutoff

router = APIRouter(prefix="/api/v1/extensions", tags=["extensions"])

# Keep in sync with INVENTORY_SORT_COLUMNS in frontend/src/api/inventory.ts.
INVENTORY_SORT_COLUMNS = (
    "last_seen_at",
    "first_seen_at",
    "extension_name",
    "browser",
    "version",
    "installed_at",
    "host_label",
)
# "unknown" selects installations whose agent did not report the state (wire v1 records).
ENABLED_FILTERS = {"true": True, "false": False, "unknown": None}
CATALOG_MATCH_FILTERS = ("matched", "unmatched")
LIMITATIONS = [
    "Installation is presence evidence, not usage; the inventory supports incident review, not employee monitoring.",
    "Rows describe the state an agent last reported; an installation missing from a host's latest snapshot is "
    "marked absent, not removed.",
    "A catalog match associates an extension identifier with a service; it does not prove AI usage.",
    "Only hosts running the endpoint agent with browser collection are covered; other browsers and hosts are unknown.",
    "Install time and install source are reported by the browser profile as found; the inventory stores them as given.",
    "Installations and version history are kept for the identity retention window only.",
]


def _aware(value: datetime) -> datetime:
    try:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    except OverflowError:
        raise HTTPException(status_code=422, detail="Timestamp is outside the UTC range") from None


def identity_window(now: datetime) -> IdentityWindow:
    return IdentityWindow(days=get_config().retention.identity_days, as_of=now)


def identity_mode() -> IdentityMode:
    """Whether host and user labels in the responses are pseudonyms (a configuration fact)."""
    return "pseudonymized" if get_config().security.pseudonymize_identities else "raw"


def inventory_filters(
    *,
    host: str | None = None,
    browser: str | None = None,
    enabled: str | None = None,
    install_source: str | None = None,
    catalog_match: str | None = None,
    extension_id: str | None = None,
    search: str | None = None,
) -> list:
    """The inventory list filters; the export reuses them so both return the same rows."""
    conditions = []
    if host:
        conditions.append(ExtensionInventoryORM.host_label.ilike(f"%{host}%"))
    if browser:
        conditions.append(ExtensionInventoryORM.browser.in_(browser.split(",")))
    if enabled:
        if enabled not in ENABLED_FILTERS:
            raise HTTPException(status_code=422, detail="Invalid enabled filter")
        conditions.append(ExtensionInventoryORM.enabled.is_(ENABLED_FILTERS[enabled]))
    if install_source:
        sources = install_source.split(",")
        if any(source not in EXTENSION_INSTALL_SOURCES for source in sources):
            raise HTTPException(status_code=422, detail="Invalid install source")
        conditions.append(ExtensionInventoryORM.install_source.in_(sources))
    if catalog_match:
        if catalog_match not in CATALOG_MATCH_FILTERS:
            raise HTTPException(status_code=422, detail="Invalid catalog match filter")
        column = ExtensionInventoryORM.catalog_item_id
        conditions.append(column.is_not(None) if catalog_match == "matched" else column.is_(None))
    if extension_id:
        conditions.append(ExtensionInventoryORM.extension_id == extension_id)
    if search:
        conditions.append(
            or_(
                ExtensionInventoryORM.extension_name.ilike(f"%{search}%"),
                ExtensionInventoryORM.extension_id.ilike(f"%{search}%"),
            )
        )
    return conditions


def order_inventory(query, sort_by: str, sort_order: str):
    if sort_by not in INVENTORY_SORT_COLUMNS or sort_order not in {"asc", "desc"}:
        raise HTTPException(status_code=422, detail="Invalid sort")
    column = getattr(ExtensionInventoryORM, sort_by)
    ordering = column.asc() if sort_order == "asc" else column.desc()
    if sort_by in {"version", "installed_at"}:
        # "Not reported" is not a value: those installations stay last in either direction.
        ordering = ordering.nulls_last()
    # The key tie-breaker keeps pages stable when many rows share a value (snapshot timestamps).
    return query.order_by(ordering, ExtensionInventoryORM.inventory_key)


def installations_select(conditions: list):
    """Each row with the discovery it matched and whether its host's latest snapshot still lists it."""
    snapshots = aliased(ExtensionInventoryORM)
    latest_snapshot = (
        select(func.max(snapshots.last_seen_at))
        .where(snapshots.device_digest == ExtensionInventoryORM.device_digest)
        .correlate(ExtensionInventoryORM)
        .scalar_subquery()
    )
    return (
        select(
            ExtensionInventoryORM,
            DetectionORM.detection_id,
            ExtensionInventoryORM.last_seen_at >= latest_snapshot,
        )
        .outerjoin(DetectionORM, DetectionORM.catalog_item_id == ExtensionInventoryORM.catalog_item_id)
        .where(*conditions)
    )


def read_installation(row: ExtensionInventoryORM, detection_id, present) -> ExtensionInventoryRead:
    return ExtensionInventoryRead.model_validate(row).model_copy(
        update={"detection_id": detection_id, "present_in_latest_snapshot": bool(present)}
    )


async def load_installations(
    session: AsyncSession,
    conditions: list,
    *,
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
    offset: int | None = None,
    limit: int | None = None,
) -> tuple[list[ExtensionInventoryRead], int]:
    """The matching installations in the requested order, and how many match in all."""
    total = await session.scalar(select(func.count()).select_from(ExtensionInventoryORM).where(*conditions)) or 0
    query = order_inventory(installations_select(conditions), sort_by, sort_order)
    if offset is not None:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    rows = await session.execute(query)
    return [read_installation(row, detection_id, present) for row, detection_id, present in rows], total


@router.get("/inventory", response_model=ExtensionInventoryListResponse)
async def list_inventory(
    host: str | None = None,
    browser: str | None = None,
    enabled: str | None = None,
    install_source: str | None = None,
    catalog_match: str | None = None,
    extension_id: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
    _user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """Current installations per host, user, browser and profile; identity-bearing, analyst only."""
    now = datetime.now(UTC)
    conditions = visible_installations(now) + inventory_filters(
        host=host,
        browser=browser,
        enabled=enabled,
        install_source=install_source,
        catalog_match=catalog_match,
        extension_id=extension_id,
        search=search,
    )
    items, total = await load_installations(
        session, conditions, sort_by=sort_by, sort_order=sort_order, offset=(page - 1) * page_size, limit=page_size
    )
    return ExtensionInventoryListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        identity_window=identity_window(now),
        identity_mode=identity_mode(),
    )


@router.get("/inventory/summary", response_model=ExtensionInventorySummary)
async def inventory_summary(
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """Aggregate counts over the visible inventory; never a host, user or profile value."""
    now = datetime.now(UTC)
    visible = visible_installations(now)
    enabled = ExtensionInventoryORM.enabled
    totals = (
        await session.execute(
            select(
                func.count(),
                func.count(distinct(ExtensionInventoryORM.device_digest)),
                func.count(distinct(ExtensionInventoryORM.extension_id)),
                func.count(ExtensionInventoryORM.catalog_item_id),
                func.count(case((enabled.is_(True), 1))),
                func.count(case((enabled.is_(False), 1))),
                func.count(case((enabled.is_(None), 1))),
            ).where(*visible)
        )
    ).one()
    by_browser = dict(
        (
            await session.execute(
                select(ExtensionInventoryORM.browser, func.count())
                .where(*visible)
                .group_by(ExtensionInventoryORM.browser)
                .order_by(ExtensionInventoryORM.browser)
            )
        ).all()
    )
    by_install_source = {source: 0 for source in INVENTORY_INSTALL_SOURCES}
    by_install_source.update(
        (
            await session.execute(
                select(ExtensionInventoryORM.install_source, func.count())
                .where(*visible)
                .group_by(ExtensionInventoryORM.install_source)
            )
        ).all()
    )
    # Changes are history of the visible rows only, and never from before the identity window.
    version_changes_7d = (
        await session.scalar(
            select(func.count())
            .select_from(ExtensionVersionChangeORM)
            .join(ExtensionInventoryORM, ExtensionInventoryORM.inventory_key == ExtensionVersionChangeORM.inventory_key)
            .where(
                *visible,
                ExtensionVersionChangeORM.observed_at >= max(now - timedelta(days=7), identity_cutoff(now)),
            )
        )
        or 0
    )
    return ExtensionInventorySummary(
        installations=totals[0],
        hosts=totals[1],
        extensions=totals[2],
        catalog_matched=totals[3],
        by_enabled={"true": totals[4], "false": totals[5], "unknown": totals[6]},
        by_browser=by_browser,
        by_install_source=by_install_source,
        version_changes_7d=version_changes_7d,
        identity_window=identity_window(now),
        identity_mode=identity_mode(),
        limitations=LIMITATIONS,
    )


@router.get("/inventory/{inventory_key}/versions", response_model=ExtensionInstallationHistory)
async def installation_versions(
    inventory_key: str = Path(min_length=64, max_length=64),
    _user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """One installation with every version change observed inside the identity window, newest first."""
    now = datetime.now(UTC)
    conditions = visible_installations(now) + [ExtensionInventoryORM.inventory_key == inventory_key]
    installations, _ = await load_installations(session, conditions, limit=1)
    if not installations:
        raise HTTPException(status_code=404, detail="Installation not found")
    changes = await session.scalars(
        select(ExtensionVersionChangeORM)
        .where(
            ExtensionVersionChangeORM.inventory_key == inventory_key,
            ExtensionVersionChangeORM.observed_at >= identity_cutoff(now),
        )
        .order_by(ExtensionVersionChangeORM.observed_at.desc(), ExtensionVersionChangeORM.change_id)
    )
    return ExtensionInstallationHistory(
        installation=installations[0],
        changes=[ExtensionVersionChangeRead.model_validate(change) for change in changes],
        identity_window=identity_window(now),
        identity_mode=identity_mode(),
    )


@router.get("/version-changes", response_model=ExtensionVersionChangeListResponse)
async def list_version_changes(
    extension_id: str | None = None,
    browser: str | None = None,
    host: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    _user: UserORM = Depends(require_role("analyst")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    """Version changes of visible installations, newest first; the window is clamped to the identity window."""
    now = datetime.now(UTC)
    cutoff = identity_cutoff(now)
    start = max(_aware(since), cutoff) if since is not None else cutoff
    end = min(_aware(until), now) if until is not None else now
    conditions = visible_installations(now) + [
        ExtensionVersionChangeORM.observed_at >= start,
        ExtensionVersionChangeORM.observed_at <= end,
    ]
    if extension_id:
        conditions.append(ExtensionVersionChangeORM.extension_id == extension_id)
    if browser:
        conditions.append(ExtensionVersionChangeORM.browser.in_(browser.split(",")))
    if host:
        conditions.append(ExtensionVersionChangeORM.host_label.ilike(f"%{host}%"))
    base = (
        select(ExtensionVersionChangeORM)
        .join(ExtensionInventoryORM, ExtensionInventoryORM.inventory_key == ExtensionVersionChangeORM.inventory_key)
        .where(*conditions)
    )
    total = await session.scalar(select(func.count()).select_from(base.subquery())) or 0
    changes = await session.scalars(
        base.order_by(ExtensionVersionChangeORM.observed_at.desc(), ExtensionVersionChangeORM.change_id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return ExtensionVersionChangeListResponse(
        items=[ExtensionVersionChangeRead.model_validate(change) for change in changes],
        total=total,
        page=page,
        page_size=page_size,
        since=start,
        until=end,
        identity_window=identity_window(now),
        identity_mode=identity_mode(),
    )
