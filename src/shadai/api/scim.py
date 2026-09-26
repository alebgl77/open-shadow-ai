"""Authenticated SCIM 2.0 Users/Groups subset for a single organization."""

import hmac
import json

from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse, Response

from shadai.config import get_config, validate_identity_settings
from shadai.database import get_postgres_session
from shadai.security.scim import GROUP_SCHEMA, LIST_SCHEMA, PREFIX, USER_SCHEMA, SCIMError, SCIMService


def response(data, status=200, headers=None):
    return JSONResponse(
        data,
        status_code=status,
        media_type="application/scim+json",
        headers={"Cache-Control": "no-store", **(headers or {})},
    )


async def authorize(request: Request):
    config = get_config()
    if not config.scim.enabled:
        raise SCIMError(404, "Not found", None)
    validate_identity_settings(config)
    authorization = request.headers.get("authorization", "")
    parts = authorization.split(" ", 1)
    if (
        len(parts) != 2
        or parts[0].lower() != "bearer"
        or not hmac.compare_digest(parts[1].encode(), config.scim.bearer_token.encode())
    ):
        raise SCIMError(401, "Invalid provisioning credential", None)


router = APIRouter(prefix=PREFIX, tags=["scim"], dependencies=[Depends(authorize)])


async def body(request):
    content_type = request.headers.get("content-type", "").split(";")[0].lower()
    if content_type not in {"application/json", "application/scim+json"}:
        raise SCIMError(415, "JSON content type required", None)
    try:
        value = await request.json()
    except (ValueError, UnicodeError) as exc:
        raise SCIMError(detail="Invalid JSON", scim_type="invalidSyntax") from exc
    if not isinstance(value, dict):
        raise SCIMError(detail="Object required")
    return value


@router.get("/ServiceProviderConfig")
async def service_provider_config():
    return response(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {
                    "type": "oauthbearertoken",
                    "name": "Provisioning bearer token",
                    "description": "Operator-configured provisioning credential",
                    "primary": True,
                }
            ],
        }
    )


def attributes():
    def attr(name, kind="string", multi=False, required=False, mutable="readWrite", sub=None):
        item = {
            "name": name,
            "type": kind,
            "multiValued": multi,
            "required": required,
            "caseExact": name == "externalId",
            "mutability": mutable,
            "returned": "default",
            "uniqueness": "none",
        }
        if sub:
            item["subAttributes"] = sub
        return item

    member = [attr("value", required=True), attr("display", mutable="readOnly")]
    return [
        {
            "id": USER_SCHEMA,
            "name": "User",
            "description": "Provisioned user",
            "attributes": [
                attr("userName", required=True),
                attr("externalId", required=True, mutable="immutable"),
                attr("active", "boolean"),
                attr("displayName"),
                attr("name", "complex", sub=[attr("givenName"), attr("familyName")]),
                attr(
                    "emails",
                    "complex",
                    True,
                    sub=[attr("value", required=True), attr("type"), attr("primary", "boolean")],
                ),
                attr("groups", "complex", True, mutable="readOnly", sub=member),
            ],
        },
        {
            "id": GROUP_SCHEMA,
            "name": "Group",
            "description": "Provisioned group",
            "attributes": [
                attr("displayName", required=True),
                attr("externalId", required=True, mutable="immutable"),
                attr("members", "complex", True, sub=member),
            ],
        },
    ]


def listing(resources):
    return {
        "schemas": [LIST_SCHEMA],
        "totalResults": len(resources),
        "startIndex": 1,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }


@router.get("/Schemas")
async def schemas():
    return response(
        listing([{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], **item} for item in attributes()])
    )


@router.get("/ResourceTypes")
async def resource_types():
    return response(
        listing(
            [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": name,
                    "name": name,
                    "endpoint": "/" + name + "s",
                    "schema": schema,
                    "schemaExtensions": [],
                }
                for name, schema in (("User", USER_SCHEMA), ("Group", GROUP_SCHEMA))
            ]
        )
    )


def check_resource(resource):
    if resource not in {"Users", "Groups"}:
        raise SCIMError(404, "Resource not found", None)


@router.get("/{resource}")
async def collection(resource: str, request: Request, session=Depends(get_postgres_session)):
    check_resource(resource)
    try:
        start, count = int(request.query_params.get("startIndex", "1")), int(request.query_params.get("count", "100"))
    except ValueError as exc:
        raise SCIMError(detail="Invalid pagination") from exc
    if any(key in request.query_params for key in ("sortBy", "sortOrder")):
        raise SCIMError(detail="Sorting is not supported")
    return response(await SCIMService(session).list(resource, start, count, request.query_params.get("filter")))


@router.post("/{resource}")
async def create(resource: str, request: Request, session=Depends(get_postgres_session)):
    check_resource(resource)
    service, payload = SCIMService(session), await body(request)
    row = await (service.create_user(payload) if resource == "Users" else service.create_group(payload))
    result = await service.represent(resource, row)
    await session.commit()
    return response(result, 201, {"Location": result["meta"]["location"]})


@router.get("/{resource}/{resource_id}")
async def read(resource: str, resource_id: str, session=Depends(get_postgres_session)):
    if resource == "Schemas":
        match = next((item for item in attributes() if item["id"] == resource_id), None)
        if match:
            return response({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"], **match})
    if resource == "ResourceTypes" and resource_id in {"User", "Group"}:
        result = await resource_types()
        return response(next(item for item in json.loads(result.body)["Resources"] if item["id"] == resource_id))
    check_resource(resource)
    service = SCIMService(session)
    return response(await service.represent(resource, await service.get(resource, resource_id)))


@router.put("/{resource}/{resource_id}")
@router.patch("/{resource}/{resource_id}")
async def update(resource: str, resource_id: str, request: Request, session=Depends(get_postgres_session)):
    check_resource(resource)
    service, payload, patch = SCIMService(session), await body(request), request.method == "PATCH"
    row = await (
        service.update_user(resource_id, payload, patch)
        if resource == "Users"
        else service.update_group(resource_id, payload, patch)
    )
    if resource == "Groups" and patch:
        await session.commit()
        return Response(status_code=204, headers={"Cache-Control": "no-store"})
    result = await service.represent(resource, row)
    await session.commit()
    return response(result)


@router.delete("/{resource}/{resource_id}")
async def remove(resource: str, resource_id: str, session=Depends(get_postgres_session)):
    check_resource(resource)
    service = SCIMService(session)
    await (service.delete_user(resource_id) if resource == "Users" else service.delete_group(resource_id))
    await session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
