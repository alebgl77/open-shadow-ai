"""Catalog management API routes."""

from __future__ import annotations

import io

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.database import get_postgres_session
from shadai.models.catalog import CatalogItemCreate, CatalogItemORM, CatalogItemRead, CatalogItemUpdate
from shadai.models.user import UserORM
from shadai.security.audit import log_audit
from shadai.security.auth import get_current_user
from shadai.security.rbac import require_role

router = APIRouter(prefix="/api/v1/catalog", tags=["catalog"])


# Also served without the trailing slash: a redirect breaks behind TLS-terminating proxies.
@router.get("", response_model=list[CatalogItemRead], include_in_schema=False)
@router.get("/", response_model=list[CatalogItemRead])
async def list_catalog(
    response: Response,
    search: str | None = None,
    category: str | None = None,
    status: str = "active",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    query = select(CatalogItemORM).where(CatalogItemORM.status == status)
    if search:
        query = query.where(CatalogItemORM.canonical_name.ilike(f"%{search}%"))
    if category:
        query = query.where(CatalogItemORM.category == category)

    response.headers["X-Total-Count"] = str(
        await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    )
    query = query.order_by(CatalogItemORM.canonical_name).offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return [CatalogItemRead.model_validate(item) for item in result.scalars().all()]


@router.get("/{catalog_item_id}", response_model=CatalogItemRead)
async def get_catalog_item(
    catalog_item_id: str,
    _user: UserORM = Depends(get_current_user),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(CatalogItemORM).where(CatalogItemORM.catalog_item_id == catalog_item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Catalog item not found")
    return CatalogItemRead.model_validate(item)


# Also served without the trailing slash: a redirect breaks behind TLS-terminating proxies.
@router.post("", response_model=CatalogItemRead, status_code=201, include_in_schema=False)
@router.post("/", response_model=CatalogItemRead, status_code=201)
async def create_catalog_item(
    body: CatalogItemCreate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    item = CatalogItemORM(
        catalog_item_id=body.catalog_item_id,
        canonical_name=body.canonical_name,
        aliases=body.aliases,
        category=body.category,
        vendor=body.vendor,
        description=body.description,
        domains=body.domains,
        url_patterns=body.url_patterns,
        processes=body.processes,
        extension_ids=body.extension_ids,
        oauth_app_ids=body.oauth_app_ids,
        local_ports=[str(p) for p in body.local_ports],
        local_paths=body.local_paths,
        container_patterns=body.container_patterns,
        user_agent_patterns=body.user_agent_patterns,
        rule_tags=body.rule_tags,
        default_trust_level=body.default_trust_level,
        source_of_truth="local",
        local_override=True,
    )
    session.add(item)
    await session.flush()

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "create_catalog_item",
        resource_type="catalog",
        resource_id=body.catalog_item_id,
        ip_address=request.client.host if request.client else None,
    )

    return CatalogItemRead.model_validate(item)


@router.put("/{catalog_item_id}", response_model=CatalogItemRead)
async def update_catalog_item(
    catalog_item_id: str,
    body: CatalogItemUpdate,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(CatalogItemORM).where(CatalogItemORM.catalog_item_id == catalog_item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Catalog item not found")

    for field, value in body.model_dump(exclude_none=True).items():
        if field == "local_ports" and value is not None:
            setattr(item, field, [str(p) for p in value])
        else:
            setattr(item, field, value)

    item.local_override = True

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "update_catalog_item",
        resource_type="catalog",
        resource_id=catalog_item_id,
        details=body.model_dump(exclude_none=True),
        ip_address=request.client.host if request.client else None,
    )

    return CatalogItemRead.model_validate(item)


@router.delete("/{catalog_item_id}")
async def delete_catalog_item(
    catalog_item_id: str,
    request: Request,
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(select(CatalogItemORM).where(CatalogItemORM.catalog_item_id == catalog_item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Catalog item not found")

    item.status = "disabled"
    item.local_override = True

    await log_audit(
        session,
        admin.user_id,
        admin.username,
        "disable_catalog_item",
        resource_type="catalog",
        resource_id=catalog_item_id,
        ip_address=request.client.host if request.client else None,
    )

    return {"message": f"Catalog item '{catalog_item_id}' disabled"}


@router.get("/export/yaml")
async def export_catalog(
    admin: UserORM = Depends(require_role("admin")),
    session: AsyncSession = Depends(get_postgres_session, scope="function"),
):
    result = await session.execute(
        select(CatalogItemORM).where(CatalogItemORM.status == "active").order_by(CatalogItemORM.catalog_item_id)
    )
    items = result.scalars().all()

    output = io.StringIO()
    for item in items:
        entry = {
            "id": item.catalog_item_id,
            "canonical_name": item.canonical_name,
            "category": item.category,
            "vendor": item.vendor,
            "domains": item.domains or [],
            "processes": item.processes or [],
        }
        yaml.dump(entry, output, default_flow_style=False)
        output.write("---\n")

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=catalog_export.yaml"},
    )
