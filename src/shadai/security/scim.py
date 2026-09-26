"""Bounded SCIM subset with atomic mutations and explicit external authority."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError

from shadai.config import get_config
from shadai.models.identity import GroupORM, MembershipORM
from shadai.models.user import UserORM
from shadai.security.audit import log_audit

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
PREFIX = "/api/v1/scim/v2"


class SCIMError(Exception):
    def __init__(self, status=400, detail="Invalid request", scim_type="invalidValue"):
        self.status, self.detail, self.scim_type = status, detail, scim_type

    def body(self):
        result = {"schemas": [ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            result["scimType"] = self.scim_type
        return result


def folded(value):
    """Case-insensitive attribute names, without ambiguous duplicate spellings."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lower = key.casefold()
            if lower in result:
                raise SCIMError(detail="Duplicate attribute names")
            result[lower] = folded(item)
        return result
    if isinstance(value, list):
        return [folded(item) for item in value]
    return value


def string(value, name, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 255 or any(ord(c) < 32 for c in value):
        raise SCIMError(detail=f"Invalid {name}")
    return value.strip()


def active(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.casefold() in {"true", "false"}:
        return value.casefold() == "true"
    raise SCIMError(detail="active must be a boolean")


def identifier(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SCIMError(404, "Resource not found", None) from exc


def normalize_user(body, *, complete):
    body = folded(body)
    if not isinstance(body, dict):
        raise SCIMError()
    if any(name in body for name in ("password", "roles", "groups")):
        raise SCIMError(detail="password, roles and groups are not writable", scim_type="mutability")
    result = {}
    for source, target in (("externalid", "external_id"), ("username", "username"), ("displayname", "display_name")):
        if source in body or (complete and source in {"externalid", "username"}):
            result[target] = string(body.get(source), source, required=source in {"externalid", "username"})
    if "active" in body or complete:
        result["is_active"] = active(body.get("active", True))
    if "name" in body or complete:
        name = body.get("name") or {}
        if not isinstance(name, dict):
            raise SCIMError(detail="Invalid name")
        for source, target in (("givenname", "given_name"), ("familyname", "family_name")):
            if complete or source in name or body.get("name") is None:
                result[target] = string(name.get(source), source)
    if "emails" in body or complete:
        emails = body.get("emails", [])
        if not isinstance(emails, list) or len(emails) > 20:
            raise SCIMError(detail="Invalid emails")
        cleaned = []
        for item in emails:
            if not isinstance(item, dict):
                raise SCIMError(detail="Invalid emails")
            email = {"value": string(item.get("value"), "email", required=True)}
            if "type" in item:
                email["type"] = string(item["type"], "email type")
            if "primary" in item:
                email["primary"] = active(item["primary"])
            cleaned.append(email)
        if sum(e.get("primary", False) for e in cleaned) > 1:
            raise SCIMError(detail="Only one email may be primary")
        result["scim_emails"] = cleaned
        result["email"] = next(
            (e["value"] for e in cleaned if e.get("primary")), cleaned[0]["value"] if cleaned else None
        )
    if complete:
        result.setdefault("display_name", None)
    return result


def member_ids(values):
    if not isinstance(values, list) or len(values) > 1000:
        raise SCIMError(detail="members must be an array of at most 1000 entries")
    result = set()
    for member in values:
        if not isinstance(member, dict):
            raise SCIMError(detail="Invalid member")
        try:
            result.add(uuid.UUID(str(member.get("value"))))
        except (ValueError, TypeError, AttributeError) as exc:
            raise SCIMError(detail="Invalid member ID") from exc
    return result


def operations(body):
    body = folded(body)
    if not isinstance(body, dict) or body.get("schemas") != [PATCH_SCHEMA]:
        raise SCIMError(detail="PatchOp schema required")
    ops = body.get("operations")
    if not isinstance(ops, list) or not 1 <= len(ops) <= 100:
        raise SCIMError(detail="PATCH requires 1 to 100 operations")
    for operation in ops:
        if not isinstance(operation, dict) or str(operation.get("op", "")).casefold() not in {
            "add",
            "replace",
            "remove",
        }:
            raise SCIMError(detail="Unsupported PATCH operation", scim_type="invalidSyntax")
    return ops


def user_patch_changes(value, op, current_emails):
    changes = normalize_user(value, complete=False)
    if op == "add" and "scim_emails" in changes:
        emails = list(current_emails)
        primary = next((email for email in changes["scim_emails"] if email.get("primary")), None)
        if primary is not None:
            emails = [
                dict(email, primary=False) if email.get("primary") and email != primary else email for email in emails
            ]
        for email in changes["scim_emails"]:
            if email not in emails:
                emails.append(email)
        changes.update(normalize_user({"emails": emails}, complete=False))
    return changes


def patch_user(body, current_emails=None):
    """Parse the complete patch before changing persistent state."""
    changes = {}
    emails = [dict(item) for item in (current_emails or [])]
    paths = {"username", "externalid", "displayname", "active", "name", "name.givenname", "name.familyname", "emails"}
    for operation in operations(body):
        op, path, value = operation["op"].casefold(), operation.get("path"), operation.get("value")
        if path is None:
            if op == "remove" or not isinstance(value, dict):
                raise SCIMError(detail="Object value required without path")
            changes.update(user_patch_changes(value, op, emails))
            emails = changes.get("scim_emails", emails)
            continue
        email_path = (
            re.fullmatch(r'emails\[type\s+eq\s+"([A-Za-z0-9_-]{1,40})"\](?:\.value)?', path, re.IGNORECASE)
            if isinstance(path, str)
            else None
        )
        if email_path:
            email_type = email_path[1]
            selected = [email for email in emails if str(email.get("type", "")).casefold() == email_type.casefold()]
            if op == "replace" and not selected:
                raise SCIMError(detail="No matching email", scim_type="noTarget")
            if op == "remove":
                emails = [email for email in emails if email not in selected]
            else:
                if not path.casefold().endswith(".value"):
                    raise SCIMError(detail="Only filtered email value updates are supported", scim_type="invalidPath")
                new_value = string(value, "email", required=True)
                if selected:
                    emails = [dict(email, value=new_value) if email in selected else email for email in emails]
                else:
                    emails.append({"value": new_value, "type": email_type})
            changes.update(normalize_user({"emails": emails}, complete=False))
            continue
        if not isinstance(path, str) or path.casefold() not in paths:
            raise SCIMError(detail="Unsupported or read-only path", scim_type="invalidPath")
        path = path.casefold()
        if op == "remove":
            if path in {"username", "externalid", "active"}:
                raise SCIMError(detail="Required attribute cannot be removed", scim_type="mutability")
            value = [] if path == "emails" else None
        if path.startswith("name."):
            payload = {"name": {path.split(".")[1]: value}}
        else:
            payload = {path: value}
        changes.update(user_patch_changes(payload, op, emails))
        emails = changes.get("scim_emails", emails)
    return changes


def filter_condition(resource, expression):
    if expression is None:
        return None
    if len(expression) > 1024:
        raise SCIMError(detail="Filter too long", scim_type="invalidFilter")
    match = re.fullmatch(r'\s*(\w+)\s+eq\s+("(?:[^"\\]|\\.)*")\s*', expression, re.IGNORECASE)
    if not match:
        raise SCIMError(detail="Only supported attribute eq string filters are available", scim_type="invalidFilter")
    attr = match[1].casefold()
    try:
        value = json.loads(match[2])
    except ValueError as exc:
        raise SCIMError(detail="Invalid quoted filter value", scim_type="invalidFilter") from exc
    columns = (
        {"username": UserORM.username_key, "externalid": UserORM.external_id, "id": UserORM.user_id}
        if resource == "Users"
        else {"displayname": GroupORM.display_name, "externalid": GroupORM.external_id, "id": GroupORM.group_id}
    )
    if attr not in columns:
        raise SCIMError(detail="Unsupported filter attribute", scim_type="invalidFilter")
    if attr == "id":
        try:
            value = uuid.UUID(value)
        except ValueError:
            return False
    if attr == "username":
        value = value.strip().casefold()
    if attr == "displayname":
        return func.lower(columns[attr]) == value.lower()
    return columns[attr] == value


class SCIMService:
    def __init__(self, session):
        self.session = session
        self.config = get_config()

    async def lock(self):
        # Serialize provisioning transactions, including read/modify/write group roles.
        # Always acquire BEFORE loading ORM state, avoiding stale partial-update races.
        await self.session.execute(text("SELECT pg_advisory_xact_lock(731041203)"))

    def visible(self, resource):
        if resource == "Users":
            return (
                UserORM.identity_kind == "scim",
                UserORM.oidc_issuer == self.config.oidc.issuer,
                UserORM.scim_deleted.is_(False),
            )
        return (GroupORM.deleted.is_(False),)

    async def get(self, resource, resource_id):
        model, column = (UserORM, UserORM.user_id) if resource == "Users" else (GroupORM, GroupORM.group_id)
        row = (
            await self.session.execute(select(model).where(column == identifier(resource_id), *self.visible(resource)))
        ).scalar_one_or_none()
        if row is None:
            raise SCIMError(404, "Resource not found", None)
        return row

    async def members(self, group_id):
        return set(
            (
                await self.session.execute(select(MembershipORM.user_id).where(MembershipORM.group_id == group_id))
            ).scalars()
        )

    async def represent(self, resource, row):
        user = resource == "Users"
        row_id = row.user_id if user else row.group_id
        result = {
            "schemas": [USER_SCHEMA if user else GROUP_SCHEMA],
            "id": str(row_id),
            "externalId": row.external_id,
            "meta": {
                "resourceType": "User" if user else "Group",
                "location": f"{PREFIX}/{resource}/{row_id}",
                "created": row.created_at.isoformat(),
                "lastModified": row.updated_at.isoformat(),
            },
        }
        if user:
            groups = (
                (
                    await self.session.execute(
                        select(GroupORM)
                        .join(MembershipORM, MembershipORM.group_id == GroupORM.group_id)
                        .where(MembershipORM.user_id == row_id, GroupORM.deleted.is_(False))
                    )
                )
                .scalars()
                .all()
            )
            result.update(
                userName=row.username,
                active=row.is_active,
                emails=row.scim_emails,
                groups=[{"value": str(g.group_id), "display": g.display_name, "type": "direct"} for g in groups],
            )
            if row.display_name is not None:
                result["displayName"] = row.display_name
            result["name"] = {
                key: value
                for key, value in (("givenName", row.given_name), ("familyName", row.family_name))
                if value is not None
            }
        else:
            result.update(
                displayName=row.display_name,
                members=[{"value": str(member)} for member in sorted(await self.members(row_id))],
            )
        return result

    async def list(self, resource, start, count, expression):
        if start < 1 or count < 0 or count > 200:
            raise SCIMError(detail="startIndex must be >=1 and count between 0 and 200")
        model, column = (UserORM, UserORM.user_id) if resource == "Users" else (GroupORM, GroupORM.group_id)
        conditions = list(self.visible(resource))
        condition = filter_condition(resource, expression)
        if condition is not None:
            conditions.append(condition)
        total = (await self.session.execute(select(func.count()).select_from(model).where(*conditions))).scalar_one()
        rows = (
            []
            if count == 0
            else (
                await self.session.execute(
                    select(model).where(*conditions).order_by(column).offset(start - 1).limit(count)
                )
            )
            .scalars()
            .all()
        )
        return {
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": len(rows),
            "Resources": [await self.represent(resource, row) for row in rows],
        }

    async def flush(self):
        try:
            await self.session.flush()
        except IntegrityError as exc:
            await self.session.rollback()
            raise SCIMError(409, "Resource identity or userName already exists", "uniqueness") from exc

    async def audit(self, action, resource, row_id):
        await log_audit(
            self.session,
            None,
            "SCIM provisioning",
            action,
            resource_type=resource,
            resource_id=str(row_id),
            actor_kind="scim",
            details={},
        )
        await self.flush()

    async def create_user(self, body):
        changes = normalize_user(body, complete=True)
        await self.lock()
        row = (
            await self.session.execute(
                select(UserORM).where(
                    UserORM.oidc_issuer == self.config.oidc.issuer, UserORM.external_id == changes["external_id"]
                )
            )
        ).scalar_one_or_none()
        if row is not None and not row.scim_deleted:
            raise SCIMError(409, "External identity already exists", "uniqueness")
        if row is None:
            row = UserORM(
                user_id=uuid.uuid4(),
                identity_kind="scim",
                oidc_issuer=self.config.oidc.issuer,
                password_hash="!",
                role="viewer",
                session_version=0,
            )
            self.session.add(row)
        else:
            row.session_version += 1
        for key, value in changes.items():
            setattr(row, key, value)
        row.scim_deleted = False
        await self.flush()
        await self.audit("scim_create_user", "user", row.user_id)
        await self.session.refresh(row)
        return row

    async def update_user(self, user_id, body, patch=False):
        await self.lock()
        row = await self.get("Users", user_id)
        changes = patch_user(body, row.scim_emails) if patch else normalize_user(body, complete=True)
        if "external_id" in changes and changes["external_id"] != row.external_id:
            raise SCIMError(detail="externalId is immutable", scim_type="mutability")
        if any(getattr(row, key) != value for key, value in changes.items()):
            row.session_version += 1
        for key, value in changes.items():
            setattr(row, key, value)
        await self.flush()
        await self.audit("scim_update_user", "user", row.user_id)
        await self.session.refresh(row)
        return row

    async def delete_user(self, user_id):
        await self.lock()
        row = await self.get("Users", user_id)
        row.is_active, row.scim_deleted = False, True
        row.session_version += 1
        row.username = f"__deleted__{row.user_id}"
        row.role = "viewer"
        await self.session.execute(delete(MembershipORM).where(MembershipORM.user_id == row.user_id))
        await self.audit("scim_delete_user", "user", row.user_id)

    async def set_members(self, group, members):
        old = await self.members(group.group_id)
        added, removed = members - old, old - members
        if added:
            found = set(
                (
                    await self.session.execute(
                        select(UserORM.user_id).where(UserORM.user_id.in_(added), *self.visible("Users"))
                    )
                ).scalars()
            )
            if found != added:
                raise SCIMError(detail="Members must reference provisioned users")
        removed_ids = list(removed)
        for offset in range(0, len(removed_ids), 1000):
            await self.session.execute(
                delete(MembershipORM).where(
                    MembershipORM.group_id == group.group_id,
                    MembershipORM.user_id.in_(removed_ids[offset : offset + 1000]),
                )
            )
        for user_id in added:
            self.session.add(MembershipORM(group_id=group.group_id, user_id=user_id))
        await self.flush()
        from shadai.security.auth import effective_roles

        affected = sorted(added | removed)
        for offset in range(0, len(affected), 1000):
            users = list(
                (
                    await self.session.execute(
                        select(UserORM).where(UserORM.user_id.in_(affected[offset : offset + 1000]))
                    )
                ).scalars()
            )
            roles = await effective_roles(self.session, users)
            for user in users:
                # Stored roles may predate the current role map. Every actual
                # membership change revokes sessions, even if that cache agrees.
                user.role = roles[user.user_id]
                user.session_version += 1
                # Group membership never activates a deprovisioned user.
        await self.flush()

    async def create_group(self, body):
        body = folded(body)
        if not isinstance(body, dict):
            raise SCIMError()
        external_id = string(body.get("externalid"), "externalId", required=True)
        display_name = string(body.get("displayname"), "displayName", required=True)
        members = member_ids(body.get("members", []))
        await self.lock()
        row = (
            await self.session.execute(select(GroupORM).where(GroupORM.external_id == external_id))
        ).scalar_one_or_none()
        if row is not None and not row.deleted:
            raise SCIMError(409, "Group externalId already exists", "uniqueness")
        if row is None:
            row = GroupORM(group_id=uuid.uuid4(), external_id=external_id)
            self.session.add(row)
        row.display_name, row.deleted = display_name, False
        await self.flush()
        await self.set_members(row, members)
        await self.audit("scim_create_group", "group", row.group_id)
        await self.session.refresh(row)
        return row

    async def update_group(self, group_id, body, patch=False):
        body = folded(body)
        if not isinstance(body, dict):
            raise SCIMError()
        ops = operations(body) if patch else [{"op": "replace", "value": body}]
        member_count = 0
        for operation in ops:
            value, path = operation.get("value"), operation.get("path")
            if isinstance(path, str) and path.casefold() == "members" and isinstance(value, list):
                member_count += len(value)
            elif path is None and isinstance(value, dict) and isinstance(value.get("members"), list):
                member_count += len(value["members"])
        if member_count > 1000:
            raise SCIMError(detail="At most 1000 member references are allowed per request")
        await self.lock()
        row = await self.get("Groups", group_id)
        members, display_name = await self.members(row.group_id), row.display_name
        if not patch:
            display_name = string(body.get("displayname"), "displayName", required=True)
            string(body.get("externalid"), "externalId", required=True)
            members = member_ids(body.get("members", []))
        for operation in ops:
            op, path, value = operation["op"].casefold(), operation.get("path"), operation.get("value")
            if path is None:
                if op == "remove" or not isinstance(value, dict):
                    raise SCIMError(detail="Object value required without path")
                items = list(value.items())
            elif isinstance(path, str):
                items = [(path.casefold(), value)]
            else:
                raise SCIMError(detail="Invalid path", scim_type="invalidPath")
            for path, value in items:
                if path == "externalid":
                    if value != row.external_id or op == "remove":
                        raise SCIMError(detail="externalId is immutable", scim_type="mutability")
                elif path == "displayname":
                    display_name = string(value if op != "remove" else None, "displayName", required=True)
                elif path == "members":
                    if op == "remove":
                        members = members - member_ids(value) if value is not None else set()
                    else:
                        new = member_ids(value)
                        members = members | new if op == "add" else new
                elif path.startswith("members["):
                    match = re.fullmatch(r'members\[value\s+eq\s+"([0-9a-f-]{36})"\]', path, re.IGNORECASE)
                    if not match or op != "remove":
                        raise SCIMError(detail="Unsupported member path", scim_type="invalidPath")
                    members.discard(identifier(match[1]))
                elif path in {"schemas", "id", "meta"} and operation.get("path") is None:
                    continue
                else:
                    raise SCIMError(detail="Unsupported group path", scim_type="invalidPath")
        # All operations are checked before mutating group state or membership.
        row.display_name, row.updated_at = display_name, datetime.now(UTC)
        await self.set_members(row, members)
        await self.audit("scim_update_group", "group", row.group_id)
        await self.session.refresh(row)
        return row

    async def delete_group(self, group_id):
        await self.lock()
        row = await self.get("Groups", group_id)
        row.deleted = True
        await self.set_members(row, set())
        await self.audit("scim_delete_group", "group", row.group_id)
