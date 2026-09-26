import importlib.util
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select

from shadai.config import trusted_url, validate_identity_settings
from shadai.database import get_postgres_session
from shadai.models.audit import AuditLogORM
from shadai.models.user import UserORM
from shadai.security.auth import create_access_token, hash_password
from shadai.security.scim import PATCH_SCHEMA, PREFIX, USER_SCHEMA, SCIMError, filter_condition, normalize_user


@pytest.fixture
async def scim_client(identity_config, identity_sessions, monkeypatch):
    from shadai.main import app

    async def database():
        async with identity_sessions.begin() as session:
            yield session

    redis = AsyncMock()
    redis.exists.return_value = 0
    redis.incr.return_value = 1
    monkeypatch.setattr("shadai.security.auth.get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.api.auth.get_redis", AsyncMock(return_value=redis))
    app.dependency_overrides[get_postgres_session] = database
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app),
            base_url=identity_config.oidc.public_base_url,
            headers={"Authorization": "Bearer " + identity_config.scim.bearer_token},
        ) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


def user_payload(name="alice", external_id="external-alice"):
    return {
        "schemas": [USER_SCHEMA],
        "externalId": external_id,
        "userName": name,
        "active": True,
        "displayName": "Alice",
        "name": {"givenName": "Alice", "familyName": "Example"},
        "emails": [{"value": "alice@example.test", "primary": True, "type": "work"}],
    }


def patch(*ops):
    return {"schemas": [PATCH_SCHEMA], "Operations": list(ops)}


async def create_user(client, name="alice", external_id="external-alice"):
    response = await client.post(PREFIX + "/Users", json=user_payload(name, external_id))
    assert response.status_code == 201, response.text
    return response.json()


async def test_scim_auth_disabled_and_constant_contract(scim_client, identity_config):
    for header in ("", "Bearer wrong", "Basic wrong", "Bearer é" * 20):
        if "é" in header:  # httpx correctly disallows non-ASCII header encoding.
            continue
        result = await scim_client.get(PREFIX + "/ServiceProviderConfig", headers={"Authorization": header})
        assert result.status_code == 401
        assert result.headers["content-type"].startswith("application/scim+json")
        assert result.json()["status"] == "401"
    assert (await scim_client.get(PREFIX + "/Schemas")).json()["totalResults"] == 2
    assert (await scim_client.get(PREFIX + "/ResourceTypes/User")).json()["name"] == "User"
    identity_config.scim.enabled = False
    assert (await scim_client.get(PREFIX + "/Users")).status_code == 404


async def test_user_lifecycle_filters_count_zero_and_audit(scim_client, identity_sessions):
    user = await create_user(scim_client)
    user_id = user["id"]
    assert user["active"] is True and user["groups"] == []
    assert user["emails"][0]["primary"] is True
    for expression in ('userName eq "ALICE"', 'EXTERNALID EQ "external-alice"', f'id eq "{user_id}"'):
        result = await scim_client.get(PREFIX + "/Users", params={"filter": expression, "count": 0})
        assert result.status_code == 200 and result.json()["totalResults"] == 1
        assert result.json()["Resources"] == [] and result.json()["itemsPerPage"] == 0
    result = await scim_client.get(PREFIX + "/Users", params={"filter": 'userName eq "nonexistent"'})
    assert result.json()["totalResults"] == 0
    for expression in ('userName co "a"', 'password eq "x"', 'id eq "x" or active eq true', "x" * 1025):
        result = await scim_client.get(PREFIX + "/Users", params={"filter": expression})
        assert result.status_code == 400 and result.json()["scimType"] == "invalidFilter"
    for params in ({"count": 201}, {"count": -1}, {"startIndex": 0}, {"count": "bad"}):
        assert (await scim_client.get(PREFIX + "/Users", params=params)).status_code == 400
    result = await scim_client.patch(
        PREFIX + "/Users/" + user_id,
        json=patch(
            {"Op": "Replace", "Value": {"Active": "false", "DisplayName": "Updated"}},
            {"op": "replace", "path": 'emails[type eq "work"].value', "value": "new@example.test"},
        ),
    )
    assert result.status_code == 200, result.text
    assert result.json()["active"] is False and result.json()["displayName"] == "Updated"
    assert result.json()["emails"][0]["value"] == "new@example.test"
    result = await scim_client.put(PREFIX + "/Users/" + user_id, json=user_payload("alice-renamed"))
    assert result.status_code == 200 and result.json()["active"] is True
    async with identity_sessions() as session:
        audits = (await session.execute(select(AuditLogORM))).scalars().all()
        assert len(audits) == 3
        assert all(a.user_id is None and a.actor_kind == "scim" and not a.details for a in audits)


async def test_local_collision_external_binding_and_local_password_protection(scim_client, identity_sessions):
    async with identity_sessions.begin() as session:
        local = UserORM(
            username="LOCAL", password_hash=hash_password("local-password12"), email="alice@example.test", role="admin"
        )
        session.add(local)
        await session.flush()
        local_id = str(local.user_id)
    collision = await scim_client.post(PREFIX + "/Users", json=user_payload("local"))
    assert collision.status_code == 409
    external = await create_user(scim_client)
    # Same email never links identities; local account is inaccessible to SCIM.
    assert external["id"] != local_id
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        kwargs = (
            {"json": user_payload()}
            if method == "PUT"
            else ({"json": patch({"op": "replace", "path": "active", "value": False})} if method == "PATCH" else {})
        )
        assert (await scim_client.request(method, PREFIX + "/Users/" + local_id, **kwargs)).status_code == 404
    login = await scim_client.post("/api/v1/auth/login", json={"username": "alice", "password": "local-password12"})
    assert login.status_code == 401
    local_login = await scim_client.post(
        "/api/v1/auth/login", json={"username": "local", "password": "local-password12"}
    )
    assert local_login.status_code == 200
    result = await scim_client.put(
        "/api/v1/settings/users/" + external["id"],
        json={"role": "admin", "is_active": True},
        headers={"Authorization": "Bearer " + local_login.json()["access_token"]},
    )
    assert result.status_code == 403
    result = await scim_client.patch(
        PREFIX + "/Users/" + external["id"], json=patch({"op": "replace", "path": "externalId", "value": "different"})
    )
    assert result.status_code == 400 and result.json()["scimType"] == "mutability"


async def test_patch_atomicity_and_hostile_input(scim_client):
    user = await create_user(scim_client)
    url = PREFIX + "/Users/" + user["id"]
    result = await scim_client.patch(
        url,
        json=patch(
            {"op": "replace", "path": "active", "value": False},
            {"op": "replace", "path": "roles", "value": [{"value": "admin"}]},
        ),
    )
    assert result.status_code == 400
    assert (await scim_client.get(url)).json()["active"] is True
    for value in (1, 0, "yes", None, []):
        result = await scim_client.patch(url, json=patch({"op": "replace", "path": "active", "value": value}))
        assert result.status_code == 400
    for value in ({"Password": "supersecret"}, {"Roles": ["admin"]}, {"userName": "alice", "UserName": "bob"}):
        result = await scim_client.patch(url, json=patch({"op": "replace", "value": value}))
        assert result.status_code == 400 and "supersecret" not in result.text
    assert (
        await scim_client.patch(url, json=patch(*([{"op": "replace", "value": {"active": True}}] * 101)))
    ).status_code == 400
    result = await scim_client.post(PREFIX + "/Users", content=b"x" * (2 * 1024 * 1024 + 1))
    assert result.status_code == 413 and result.json()["status"] == "413"


@pytest.mark.parametrize("with_path", [True, False])
async def test_email_add_appends_normalized_unique_values_and_replace_replaces(scim_client, with_path):
    user = await create_user(scim_client)
    url = PREFIX + "/Users/" + user["id"]
    home = {"value": "home@example.test", "type": "home"}
    values = [home, {"VALUE": " home@example.test ", "TYPE": "home"}]
    operation = (
        {"op": "Add", "path": "emails", "value": values} if with_path else {"op": "Add", "value": {"Emails": values}}
    )
    response = await scim_client.patch(url, json=patch(operation))
    assert response.status_code == 200, response.text
    assert response.json()["emails"] == [*user["emails"], home]
    # Replaying the same addition is idempotent and preserves the original primary.
    response = await scim_client.patch(url, json=patch(operation))
    assert response.status_code == 200 and response.json()["emails"] == [*user["emails"], home]
    replacement = (
        {"op": "Replace", "path": "emails", "value": [home]}
        if with_path
        else {"op": "Replace", "value": {"emails": [home]}}
    )
    response = await scim_client.patch(url, json=patch(replacement))
    assert response.status_code == 200 and response.json()["emails"] == [home]


@pytest.mark.parametrize("with_path", [True, False])
async def test_email_add_new_primary_demotes_existing_without_removing_it(scim_client, identity_sessions, with_path):
    user = await create_user(scim_client)
    home = {"value": "home@example.test", "type": "home", "primary": True}
    operation = (
        {"op": "add", "path": "emails", "value": [home]} if with_path else {"op": "add", "value": {"emails": [home]}}
    )
    url = PREFIX + "/Users/" + user["id"]
    response = await scim_client.patch(url, json=patch(operation))
    assert response.status_code == 200, response.text
    expected = [dict(user["emails"][0], primary=False), home]
    assert response.json()["emails"] == expected
    response = await scim_client.patch(url, json=patch(operation))
    assert response.status_code == 200 and response.json()["emails"] == expected
    async with identity_sessions() as session:
        assert (await session.get(UserORM, UUID(user["id"]))).email == home["value"]


async def test_email_patch_sequential_operations_preserve_each_filtered_match(scim_client):
    user = await create_user(scim_client)
    url = PREFIX + "/Users/" + user["id"]
    second_work = {"value": "second@example.test", "type": "WORK", "primary": False}
    home = {"value": "home@example.test", "type": "home"}
    response = await scim_client.patch(
        url,
        json=patch(
            {"op": "add", "path": "emails", "value": [second_work]},
            {"op": "add", "value": {"emails": [home]}},
            {"op": "replace", "path": 'emails[type eq "work"].value', "value": "updated@example.test"},
        ),
    )
    assert response.status_code == 200, response.text
    assert response.json()["emails"] == [
        dict(user["emails"][0], value="updated@example.test"),
        dict(second_work, value="updated@example.test"),
        home,
    ]
    response = await scim_client.patch(
        url,
        json=patch(
            {"op": "remove", "path": "emails"},
            {"op": "add", "path": "emails", "value": [home]},
        ),
    )
    assert response.status_code == 200 and response.json()["emails"] == [home]


@pytest.mark.parametrize("with_path", [True, False])
@pytest.mark.parametrize("failure", ["limit", "multiple-primary"])
async def test_email_patch_invalid_combined_array_rolls_back_entire_request(
    scim_client, identity_sessions, with_path, failure
):
    user = await create_user(scim_client)
    url = PREFIX + "/Users/" + user["id"]
    values = (
        [{"value": f"extra-{index}@example.test"} for index in range(20)]
        if failure == "limit"
        else [{"value": f"extra-{index}@example.test", "primary": True} for index in range(2)]
    )
    operation = (
        {"op": "add", "path": "emails", "value": values} if with_path else {"op": "add", "value": {"emails": values}}
    )
    response = await scim_client.patch(
        url,
        json=patch(
            {"op": "replace", "path": "active", "value": False},
            {"op": "add", "path": "emails", "value": [{"value": "earlier@example.test"}]},
            operation,
        ),
    )
    assert response.status_code == 400, response.text
    unchanged = (await scim_client.get(url)).json()
    assert unchanged["active"] is True and unchanged["emails"] == user["emails"]
    async with identity_sessions() as session:
        row = await session.get(UserORM, UUID(user["id"]))
        assert row.session_version == 0 and row.email == user["emails"][0]["value"]
        assert len((await session.execute(select(AuditLogORM))).scalars().all()) == 1


async def test_email_filtered_replace_missing_target_rolls_back(scim_client):
    user = await create_user(scim_client)
    url = PREFIX + "/Users/" + user["id"]
    response = await scim_client.patch(
        url,
        json=patch(
            {"op": "replace", "path": "active", "value": False},
            {"op": "replace", "path": 'emails[type eq "missing"].value', "value": "missing@example.test"},
        ),
    )
    assert response.status_code == 400 and response.json()["scimType"] == "noTarget"
    unchanged = (await scim_client.get(url)).json()
    assert unchanged["active"] is True and unchanged["emails"] == user["emails"]


async def test_groups_roles_remove_forms_and_deactivation_never_revives_tokens(
    scim_client, identity_config, identity_sessions
):
    user = await create_user(scim_client)
    uid, user_url = UUID(user["id"]), PREFIX + "/Users/" + user["id"]
    result = await scim_client.post(
        PREFIX + "/Groups",
        json={"externalId": "admins-group", "displayName": "Administrators", "members": [{"value": user["id"]}]},
    )
    assert result.status_code == 201, result.text
    group_url = PREFIX + "/Groups/" + result.json()["id"]
    async with identity_sessions() as session:
        row = await session.get(UserORM, uid)
        assert row.role == "admin"
        token = create_access_token(str(uid), row.role, row.session_version)
    auth = {"Authorization": "Bearer " + token}
    assert (await scim_client.get("/api/v1/auth/me", headers=auth)).json()["role"] == "admin"
    identity_config.scim.group_role_map = {}
    assert (await scim_client.get("/api/v1/auth/me", headers=auth)).json()["role"] == "viewer"
    identity_config.scim.group_role_map = {"admins-group": "admin"}
    assert (
        await scim_client.patch(user_url, json=patch({"op": "Replace", "path": "active", "value": "false"}))
    ).status_code == 200
    # Both member removal formats work, while membership changes leave inactive users inactive.
    for removal in (
        {"op": "Remove", "path": "members", "value": [{"value": str(uid), "$ref": None}]},
        {"op": "remove", "path": f'members[value eq "{uid}"]'},
    ):
        assert (await scim_client.patch(group_url, json=patch(removal))).status_code == 204
        assert (
            await scim_client.patch(group_url, json=patch({"op": "Add", "value": {"members": [{"value": str(uid)}]}}))
        ).status_code == 204
    assert (await scim_client.get(user_url)).json()["active"] is False
    assert (
        await scim_client.patch(user_url, json=patch({"op": "replace", "path": "active", "value": True}))
    ).status_code == 200
    assert (await scim_client.get("/api/v1/auth/me", headers=auth)).status_code == 401
    result = await scim_client.get(PREFIX + "/Groups", params={"filter": 'displayName eq "administrators"', "count": 0})
    assert result.json()["totalResults"] == 1 and result.json()["Resources"] == []
    assert (await scim_client.get(user_url)).json()["groups"][0]["value"] == group_url.rsplit("/", 1)[1]


async def test_membership_delta_revokes_tokens_with_stale_stored_role_and_noops_do_not(
    scim_client, identity_config, identity_sessions
):
    identity_config.scim.group_role_map = {}
    user = await create_user(scim_client)
    uid = UUID(user["id"])
    group = (
        await scim_client.post(
            PREFIX + "/Groups",
            json={"externalId": "admins-group", "displayName": "Admins", "members": [{"value": user["id"]}]},
        )
    ).json()
    url = PREFIX + "/Groups/" + group["id"]
    async with identity_sessions() as session:
        row = await session.get(UserORM, uid)
        assert row.role == "viewer" and row.session_version == 1
        token = create_access_token(str(uid), "viewer", row.session_version)
    auth = {"Authorization": "Bearer " + token}
    identity_config.scim.group_role_map = {"admins-group": "admin"}
    assert (await scim_client.get("/api/v1/auth/me", headers=auth)).json()["role"] == "admin"
    # Redundant adds, removes and net-zero changes must not revoke the token.
    for operations in (
        [{"op": "add", "path": "members", "value": [{"value": user["id"]}]}],
        [{"op": "remove", "path": "members", "value": [{"value": str(uuid4())}]}],
        [
            {"op": "remove", "path": "members", "value": [{"value": user["id"]}]},
            {"op": "add", "path": "members", "value": [{"value": user["id"]}]},
        ],
    ):
        assert (await scim_client.patch(url, json=patch(*operations))).status_code == 204
        assert (await scim_client.get("/api/v1/auth/me", headers=auth)).status_code == 200
    assert (
        await scim_client.patch(url, json=patch({"op": "remove", "path": "members", "value": [{"value": user["id"]}]}))
    ).status_code == 204
    assert (await scim_client.get("/api/v1/auth/me", headers=auth)).status_code == 401
    async with identity_sessions() as session:
        row = await session.get(UserORM, uid)
        assert row.role == "viewer" and row.session_version == 2
    assert (
        await scim_client.patch(url, json=patch({"op": "add", "path": "members", "value": [{"value": user["id"]}]}))
    ).status_code == 204
    async with identity_sessions() as session:
        row = await session.get(UserORM, uid)
        assert row.role == "admin" and row.session_version == 3


async def test_group_multioperation_failure_rolls_back_members_and_roles(scim_client, identity_sessions):
    user = await create_user(scim_client)
    group = (
        await scim_client.post(PREFIX + "/Groups", json={"externalId": "admins-group", "displayName": "Admins"})
    ).json()
    url = PREFIX + "/Groups/" + group["id"]
    result = await scim_client.patch(
        url,
        json=patch(
            {"op": "add", "path": "members", "value": [{"value": user["id"]}]},
            {"op": "replace", "path": "displayName", "value": "Changed"},
            {"op": "add", "path": "members", "value": [{"value": str(uuid4())}]},
        ),
    )
    assert result.status_code == 400
    unchanged = (await scim_client.get(url)).json()
    assert unchanged["displayName"] == "Admins" and unchanged["members"] == []
    async with identity_sessions() as session:
        row = await session.get(UserORM, UUID(user["id"]))
        assert row.role == "viewer" and row.session_version == 0
    result = await scim_client.put(
        url, json={"externalId": "admins-group", "displayName": "Admins updated", "members": [{"value": user["id"]}]}
    )
    assert result.status_code == 200
    assert (await scim_client.delete(url)).status_code == 204
    assert (await scim_client.get(url)).status_code == 404
    async with identity_sessions() as session:
        assert (await session.get(UserORM, UUID(user["id"]))).role == "viewer"


async def test_soft_delete_recreation_keeps_binding_and_old_tokens_invalid(scim_client, identity_sessions):
    user = await create_user(scim_client)
    token = create_access_token(user["id"], "viewer", 0)
    assert (await scim_client.delete(PREFIX + "/Users/" + user["id"])).status_code == 204
    assert (await scim_client.get(PREFIX + "/Users/" + user["id"])).status_code == 404
    assert (await scim_client.get(PREFIX + "/Users")).json()["totalResults"] == 0
    restored = await create_user(scim_client)
    assert restored["id"] == user["id"] and restored["groups"] == []
    assert (await scim_client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + token})).status_code == 401
    async with identity_sessions() as session:
        assert (await session.get(UserORM, UUID(user["id"]))).session_version >= 2


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.test",
        "https://user:pass@idp.example.test",
        "https://idp.example.test?secret=x",
        "https://idp.example.test#fragment",
        "https://idp.example.test\\@evil.test",
        " https://idp.example.test",
        "http://192.168.0.1",
        "http://127.0.0.2",
    ],
)
def test_identity_url_validation(url):
    with pytest.raises(ValueError):
        trusted_url(url, allow_local=True)


def test_identity_config_fail_closed_and_explicit_loopback(identity_config):
    validate_identity_settings(identity_config)
    identity_config.oidc.public_base_url = "HTTPS://console.example.test"
    assert identity_config.oidc.secure_cookies is True
    validate_identity_settings(identity_config)
    for value in ("http://localhost:8123", "http://127.0.0.1:8123", "http://[::1]:8123"):
        assert trusted_url(value, allow_local=True) == value
        with pytest.raises(ValueError):
            trusted_url(value)
    identity_config.scim.bearer_token = identity_config.security.agent_api_key
    with pytest.raises(ValueError):
        validate_identity_settings(identity_config)
    identity_config.scim.bearer_token = "short"
    with pytest.raises(ValueError):
        validate_identity_settings(identity_config)


def test_migration_collision_preflight_and_parameterized_filter():
    path = Path("migrations/versions/003_external_identity.py")
    spec = importlib.util.spec_from_file_location("identity_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for rows in (
        [(uuid4(), "Alice"), (uuid4(), "ALICE")],
        [(uuid4(), "Straße"), (uuid4(), "STRASSE")],
        [(uuid4(), " ")],
    ):
        with pytest.raises(RuntimeError, match="Rename conflicting local accounts"):
            module.normalized_usernames(rows)
    assert module.normalized_usernames([(uuid4(), "Alice")])[0]["key"] == "alice"
    expression = 'userName eq "x\' OR 1=1 --"'
    compiled = filter_condition("Users", expression).compile()
    assert "OR 1=1" not in str(compiled) and "x' or 1=1 --" in compiled.params.values()
    with pytest.raises(SCIMError):
        normalize_user({"externalId": "x", "userName": "", "active": True}, complete=True)


async def test_settings_lists_current_role_map_without_reprovision(scim_client, identity_sessions, identity_config):
    async with identity_sessions.begin() as session:
        admin = UserORM(username="breakglass", password_hash="!", role="admin")
        session.add(admin)
        await session.flush()
        token = create_access_token(str(admin.user_id), "admin")
    user = await create_user(scim_client)
    assert (
        await scim_client.post(
            PREFIX + "/Groups",
            json={"externalId": "new-group", "displayName": "New group", "members": [{"value": user["id"]}]},
        )
    ).status_code == 201
    headers = {"Authorization": "Bearer " + token}
    for mapping, expected in (({"new-group": "admin"}, "admin"), ({}, "viewer"), ({"new-group": "analyst"}, "analyst")):
        identity_config.scim.group_role_map = mapping
        result = await scim_client.get("/api/v1/settings/users/", headers=headers)
        assert result.status_code == 200
        rows = {item["user_id"]: item for item in result.json()}
        assert rows[user["id"]]["role"] == expected
        assert rows[str(admin.user_id)]["role"] == "admin"


async def test_member_limit_is_per_request_not_cumulative_group(scim_client, identity_sessions, identity_config):
    users = [uuid4() for _ in range(1001)]
    async with identity_sessions.begin() as session:
        session.add_all(
            [
                UserORM(
                    user_id=value,
                    username="user-" + str(value),
                    external_id=str(value),
                    oidc_issuer=identity_config.oidc.issuer,
                    identity_kind="scim",
                    password_hash="!",
                    role="viewer",
                )
                for value in users
            ]
        )
    result = await scim_client.post(
        PREFIX + "/Groups",
        json={
            "externalId": "large-group",
            "displayName": "Large group",
            "members": [{"value": str(value)} for value in users[:1000]],
        },
    )
    assert result.status_code == 201
    group_url = PREFIX + "/Groups/" + result.json()["id"]
    result = await scim_client.patch(
        group_url, json=patch({"op": "add", "path": "members", "value": [{"value": str(users[-1])}]})
    )
    assert result.status_code == 204
    assert len((await scim_client.get(group_url)).json()["members"]) == 1001
    result = await scim_client.patch(
        group_url,
        json=patch(
            {"op": "add", "path": "members", "value": [{"value": str(value)} for value in users[:600]]},
            {"op": "add", "path": "members", "value": [{"value": str(value)} for value in users[500:]]},
        ),
    )
    assert result.status_code == 400
    assert len((await scim_client.get(group_url)).json()["members"]) == 1001


async def test_local_disable_reactivate_invalidates_legacy_version_zero(scim_client, identity_sessions):
    import jwt

    from shadai.config import get_config

    async with identity_sessions.begin() as session:
        admin = UserORM(username="breakglass", password_hash="!", role="admin")
        user = UserORM(username="local", password_hash="!", role="viewer")
        session.add_all([admin, user])
        await session.flush()
        admin_token = create_access_token(str(admin.user_id), "admin")
        claims = jwt.decode(create_access_token(str(user.user_id), "viewer"), options={"verify_signature": False})
        del claims["session_version"]
        legacy = jwt.encode(claims, get_config().security.jwt_secret, algorithm="HS256")
    headers = {"Authorization": "Bearer " + legacy}
    assert (await scim_client.get("/api/v1/auth/me", headers=headers)).status_code == 200
    for active in (False, True):
        result = await scim_client.put(
            "/api/v1/settings/users/" + str(user.user_id),
            json={"is_active": active},
            headers={"Authorization": "Bearer " + admin_token},
        )
        assert result.status_code == 200
    assert (await scim_client.get("/api/v1/auth/me", headers=headers)).status_code == 401
