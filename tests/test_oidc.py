"""Signed mock-provider coverage of OIDC and the browser/session security boundary."""

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
import warnings
from types import SimpleNamespace
from urllib.parse import parse_qs, quote_plus, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadai.api import sso
from shadai.config import validate_identity_settings
from shadai.database import get_postgres_session
from shadai.models.audit import AuditLogORM
from shadai.models.identity import GroupORM, MembershipORM
from shadai.models.user import UserORM
from shadai.security.auth import decode_access_token
from shadai.security.oidc import HANDOFF_TTL, STATE_TTL, OIDCClient, OIDCError, consume_bound, digest, store_bound


class BoundRedis:
    """The Redis Lua contract, with deterministic TTL and atomic event-loop access."""

    def __init__(self):
        self.values = {}
        self.now = 0

    async def set(self, key, value, *, ex, nx):
        if key in self.values and self.values[key][1] > self.now:
            return None
        self.values[key] = (value, self.now + ex)
        return True

    async def eval(self, script, key_count, key, binding):
        assert key_count == 1 and "redis.call('DEL', KEYS[1])" in script
        entry = self.values.get(key)
        if entry is None:
            return None
        value, expires = entry
        if expires <= self.now:
            self.values.pop(key)
            return None
        if not hmac.compare_digest(json.loads(value)["binding"], binding):
            return None
        self.values.pop(key)
        return value


class SignedIdP:
    """Actual RS256 ID tokens served over a mock discovery/token/JWKS transport."""

    def __init__(self, config, key):
        self.config = config
        self.key = self.signing_key = key
        self.jwk = {
            **jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True),
            "kid": "current",
            "alg": "RS256",
            "use": "sig",
        }
        self.metadata = {
            "issuer": config.issuer,
            "authorization_endpoint": config.issuer + "/authorize",
            "token_endpoint": config.issuer + "/token",
            "jwks_uri": config.issuer + "/keys",
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.overrides = {}
        self.missing = set()
        self.codes = {}
        self.requests = []
        self.token_forms = []
        self.redirect_path = None
        self.transport = httpx.MockTransport(self.handle)

    def token(self, nonce="nonce", **overrides):
        now = int(time.time())
        claims = {
            "iss": self.config.issuer,
            "aud": self.config.client_id,
            "sub": "subject-123",
            "oid": "object-123",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
            "email": "person@example.test",
            **self.overrides,
            **overrides,
        }
        for name in self.missing:
            claims.pop(name, None)
        return jwt.api_jws.encode(
            json.dumps(claims).encode(), self.signing_key, algorithm="RS256", headers={"kid": "current"}
        )

    def authorize(self, url):
        query = {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}
        assert query["code_challenge_method"] == "S256"
        assert query["redirect_uri"] == self.config.callback_url
        assert query["client_id"] == self.config.client_id
        assert query["response_type"] == "code"
        code = secrets.token_urlsafe(24)
        self.codes[code] = query
        return code, query["state"]

    def handle(self, request):
        self.requests.append(request)
        if self.redirect_path and str(request.url).endswith(self.redirect_path):
            return httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
        if str(request.url).endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.metadata)
        if str(request.url).endswith("/keys"):
            return httpx.Response(200, json={"keys": [self.jwk]})
        if str(request.url).endswith("/token"):
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
            self.token_forms.append(form)
            flow = self.codes.pop(form["code"], None)
            challenge = jwt.utils.base64url_encode(hashlib.sha256(form["code_verifier"].encode()).digest()).decode()
            if not flow or flow["code_challenge"] != challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
            assert form["redirect_uri"] == self.config.callback_url
            return httpx.Response(
                200, json={"id_token": self.token(flow["nonce"]), "access_token": "never-use-idp-access"}
            )
        raise AssertionError(f"Unexpected mock-provider path: {request.url.path}")


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def idp(identity_config, rsa_key):
    return SignedIdP(identity_config.oidc, rsa_key)


@pytest.fixture
async def flow(identity_config, identity_sessions, idp, monkeypatch):
    redis = BoundRedis()

    async def get_store():
        return redis

    async def get_session():
        async with identity_sessions.begin() as session:
            yield session

    monkeypatch.setattr(sso, "get_redis", get_store)
    monkeypatch.setattr(sso, "OIDCClient", lambda config: OIDCClient(config, idp.transport))
    app = FastAPI()
    app.include_router(sso.router)
    app.dependency_overrides[get_postgres_session] = get_session
    async with identity_sessions.begin() as session:
        user = UserORM(
            username="person",
            email="person@example.test",
            password_hash="!",
            role="admin",
            identity_kind="scim",
            oidc_issuer=identity_config.oidc.issuer,
            external_id="subject-123",
        )
        session.add(user)
        await session.flush()
        user_id = user.user_id
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=identity_config.oidc.public_base_url
    ) as client:
        yield SimpleNamespace(
            client=client,
            redis=redis,
            idp=idp,
            config=identity_config,
            sessions=identity_sessions,
            user_id=user_id,
            app=app,
        )


def csrf(flow):
    return {"Origin": flow.config.oidc.public_base_url, "X-SSO-CSRF": "1"}


def session_cookie(response):
    """The console session is delivered only as a host-only, HttpOnly, SameSite=Strict cookie."""
    [cookie] = [c for c in response.headers.get_list("set-cookie") if c.startswith("__Host-shadai-session=")]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie
    return cookie.split(";", 1)[0].split("=", 1)[1]


async def begin(flow):
    response = await flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303
    code, state = flow.idp.authorize(response.headers["location"])
    return {"code": code, "state": state}


async def callback(flow):
    response = await flow.client.get("/api/v1/auth/sso/callback", params=await begin(flow))
    assert response.headers["location"] == flow.config.oidc.public_base_url + "/auth/callback"
    return response


@pytest.mark.parametrize("claim", ["sub", "oid"])
async def test_signed_flow_issues_only_local_session_and_clears_cookies(flow, claim):
    flow.config.oidc.identity_claim = claim
    if claim == "oid":
        async with flow.sessions.begin() as session:
            (await session.get(UserORM, flow.user_id)).external_id = "object-123"
    metadata = await flow.client.get("/api/v1/auth/providers")
    assert metadata.json() == {
        "local_enabled": True,
        "sso": {"enabled": True, "label": flow.config.oidc.label, "login_url": "/api/v1/auth/sso/login"},
    }
    response = await callback(flow)
    assert response.status_code == 303
    assert urlsplit(response.headers["location"]).query == urlsplit(response.headers["location"]).fragment == ""
    for cookie in response.headers.get_list("set-cookie"):
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
        assert "Domain=" not in cookie and cookie.startswith("__Host-")
    stored = " ".join(value for value, _ in flow.redis.values.values())
    assert "access_token" not in stored and "never-use-idp-access" not in stored
    response = await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
    assert response.status_code == 200
    token = decode_access_token(session_cookie(response))
    assert token.sub == flow.user_id and token.role == "viewer"  # stale stored admin is ignored
    body = response.json()
    assert body["access_token"] is None and body["token_type"] == "cookie" and body["csrf_token"]
    assert body["user"]["role"] == "viewer" and body["user"]["identity_kind"] == "scim"
    assert response.headers["cache-control"] == "no-store" and response.headers["referrer-policy"] == "no-referrer"
    # The one-use SSO cookies are gone; only the console session remains.
    assert [cookie.name for cookie in flow.client.cookies.jar] == ["__Host-shadai-session"] and not flow.redis.values
    async with flow.sessions() as session:
        user = await session.get(UserORM, flow.user_id)
        audit = (await session.execute(select(AuditLogORM))).scalar_one()
        assert user.last_login_at is not None and audit.action == "login"
        assert audit.user_id == flow.user_id and audit.actor_kind == "user" and audit.details == {"method": "oidc"}


async def test_wrong_browser_cannot_burn_state_and_callback_is_one_use(flow):
    query = await begin(flow)
    saved = list(flow.client.cookies.jar)[0]
    flow.client.cookies.clear()
    flow.client.cookies.set(saved.name, "wrong-browser-cookie-value", domain=saved.domain, path=saved.path)
    failed = await flow.client.get("/api/v1/auth/sso/callback", params=query)
    assert failed.headers["location"].endswith("/login?sso_error=failed")
    assert len(flow.redis.values) == 1 and not flow.idp.token_forms
    flow.client.cookies.clear()
    flow.client.cookies.jar.set_cookie(saved)
    ok = await flow.client.get("/api/v1/auth/sso/callback", params=query)
    assert ok.headers["location"].endswith("/auth/callback")
    replay = await flow.client.get("/api/v1/auth/sso/callback", params=query)
    assert replay.headers["location"].endswith("/login?sso_error=failed")
    assert len(flow.idp.token_forms) == 1


@pytest.mark.parametrize("stage", ["state", "handoff"])
async def test_expired_handles_fail_closed(flow, stage):
    if stage == "state":
        query = await begin(flow)
        flow.redis.now += STATE_TTL
        response = await flow.client.get("/api/v1/auth/sso/callback", params=query)
        assert response.headers["location"].endswith("/login?sso_error=failed")
        assert not flow.idp.token_forms
    else:
        await callback(flow)
        flow.redis.now += HANDOFF_TTL
        response = await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
        assert response.status_code == 401


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "null",
        "https://attacker.example",
        "https://console.example.test/path",
        "https://console.example.test?x=1",
        "https://@console.example.test",
        "https://user@console.example.test",
        "https://console.example.test#x",
        "https://console.example.test:bad",
        "https://console.example.test:0",
        "https://console.example.test/",
    ],
)
async def test_origin_rejected_without_consuming_handoff(flow, origin):
    await callback(flow)
    headers = {"X-SSO-CSRF": "1"}
    if origin is not None:
        headers["Origin"] = origin
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=headers)).status_code == 403
    assert len(flow.redis.values) == 1
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200


@pytest.mark.parametrize("csrf_value", [None, "0", "true"])
async def test_csrf_header_required_without_burning_ticket(flow, csrf_value):
    await callback(flow)
    headers = {"Origin": flow.config.oidc.public_base_url}
    if csrf_value is not None:
        headers["X-SSO-CSRF"] = csrf_value
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=headers)).status_code == 403
    assert len(flow.redis.values) == 1


async def test_default_https_port_origin_and_duplicate_headers(flow):
    await callback(flow)
    duplicate = [
        ("Origin", flow.config.oidc.public_base_url),
        ("Origin", flow.config.oidc.public_base_url),
        ("X-SSO-CSRF", "1"),
    ]
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=duplicate)).status_code == 403
    duplicate = [("Origin", flow.config.oidc.public_base_url), ("X-SSO-CSRF", "1"), ("X-SSO-CSRF", "1")]
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=duplicate)).status_code == 403
    assert (
        await flow.client.post(
            "/api/v1/auth/sso/session", headers={"Origin": flow.config.oidc.public_base_url + ":443", "X-SSO-CSRF": "1"}
        )
    ).status_code == 200


@pytest.mark.parametrize("change", ["unprovisioned", "local", "issuer", "inactive", "deleted"])
async def test_callback_never_creates_or_links_accounts(flow, change):
    async with flow.sessions.begin() as session:
        user = await session.get(UserORM, flow.user_id)
        if change == "unprovisioned":
            user.external_id = "different-subject"
        elif change == "local":
            user.identity_kind = "local"
        elif change == "issuer":
            user.oidc_issuer += "/"
        elif change == "inactive":
            user.is_active = False
        else:
            user.scim_deleted = True
    response = await flow.client.get("/api/v1/auth/sso/callback", params=await begin(flow))
    assert response.headers["location"].endswith("/login?sso_error=failed")
    async with flow.sessions() as session:
        assert (await session.scalar(select(func.count()).select_from(UserORM))) == 1


@pytest.mark.parametrize("change", ["inactive", "deleted", "reactivated", "issuer", "source"])
async def test_handoff_rechecks_account_and_cannot_retry_after_failure(flow, change):
    await callback(flow)
    saved_cookies = list(flow.client.cookies.jar)
    async with flow.sessions.begin() as session:
        user = await session.get(UserORM, flow.user_id)
        if change == "inactive":
            user.is_active = False
        elif change == "deleted":
            user.scim_deleted = True
        elif change == "reactivated":
            user.session_version += 2  # disable + reactivate preserves no previously issued handoff
        elif change == "issuer":
            user.oidc_issuer += "/changed"
        else:
            user.identity_kind = "local"
    response = await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
    assert response.status_code == 401 and not flow.redis.values
    async with flow.sessions.begin() as session:
        user = await session.get(UserORM, flow.user_id)
        user.is_active, user.scim_deleted, user.session_version = True, False, 0
        user.oidc_issuer, user.identity_kind = flow.config.oidc.issuer, "scim"
    for cookie in saved_cookies:
        flow.client.cookies.jar.set_cookie(cookie)
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 401


async def test_current_group_mapping_applied_at_handoff(flow):
    await callback(flow)
    async with flow.sessions.begin() as session:
        group = GroupORM(external_id="admins-group", display_name="Mapped group")
        session.add(group)
        await session.flush()
        session.add(MembershipORM(group_id=group.group_id, user_id=flow.user_id))
    flow.config.scim.group_role_map["admins-group"] = "analyst"
    response = await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
    assert response.status_code == 200 and response.json()["user"]["role"] == "analyst"
    assert decode_access_token(session_cookie(response)).role == "analyst"


async def test_disabled_provider_fails_closed_with_local_available(flow):
    flow.config.oidc.enabled = False
    assert (await flow.client.get("/api/v1/auth/providers")).json()["local_enabled"] is True
    assert (await flow.client.get("/api/v1/auth/providers")).json()["sso"]["enabled"] is False
    assert (await flow.client.get("/api/v1/auth/sso/login")).status_code == 404
    assert (await flow.client.get("/api/v1/auth/sso/callback")).status_code == 404
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 404
    assert not flow.idp.requests and not flow.redis.values


async def test_provider_failure_is_fixed_sanitized_redirect_and_consumes_state(flow):
    query = await begin(flow)
    query.update(
        error="provider-sensitive-error", error_description="secret-detail", return_to="https://attacker.example"
    )
    response = await flow.client.get("/api/v1/auth/sso/callback", params=query, headers={"Host": "attacker.example"})
    assert response.headers["location"] == flow.config.oidc.public_base_url + "/login?sso_error=failed"
    assert "secret-detail" not in response.text and "provider-sensitive-error" not in str(response.headers)


async def test_pkce_verifier_and_nonce_enforced_through_real_exchange(flow):
    query = await begin(flow)
    key = "oidc:state:" + digest(query["state"])
    raw, expires = flow.redis.values[key]
    item = json.loads(raw)
    item["verifier"] = secrets.token_urlsafe(32)
    flow.redis.values[key] = json.dumps(item), expires
    response = await flow.client.get("/api/v1/auth/sso/callback", params=query)
    assert response.headers["location"].endswith("/login?sso_error=failed")
    flow.idp.overrides["nonce"] = "wrong-nonce"
    response = await flow.client.get("/api/v1/auth/sso/callback", params=await begin(flow))
    assert response.headers["location"].endswith("/login?sso_error=failed")


async def test_redis_outage_is_generic_and_no_upstream_request(flow, monkeypatch):
    async def outage():
        raise RedisConnectionError("sensitive-redis-password")

    monkeypatch.setattr(sso, "get_redis", outage)
    response = await flow.client.get("/api/v1/auth/sso/login")
    assert response.headers["location"].endswith("/login?sso_error=failed")
    assert "sensitive" not in response.text and not flow.idp.requests


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://other.example"},
        {"iss": None},
        {"aud": "other-client"},
        {"aud": []},
        {"aud": ["console-client", "other-client"]},
        {"aud": ["console-client", 1]},
        {"azp": "other-client"},
        {"nonce": "wrong"},
        {"nonce": None},
        {"sub": ""},
        {"sub": "x" * 256},
        {"sub": 12},
        {"exp": 0},
        {"exp": "99999999999"},
        {"exp": True},
        {"exp": float("inf")},
        {"iat": float("nan")},
        {"iat": "1"},
        {"iat": True},
        {"iat": 1},
        {"iat": 99999999999},
        {"nbf": 99999999999},
        {"nbf": None},
    ],
)
def test_signed_invalid_claims_rejected(idp, overrides):
    with pytest.raises(OIDCError):
        OIDCClient(idp.config).validate(idp.token(**overrides), {"keys": [idp.jwk]}, "nonce")


@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "nonce", "exp", "iat"])
def test_required_signed_claims(idp, missing):
    idp.missing.add(missing)
    with pytest.raises(OIDCError):
        OIDCClient(idp.config).validate(idp.token(), {"keys": [idp.jwk]}, "nonce")


def test_multiple_audiences_need_correct_authorized_party(idp):
    token = idp.token(aud=["console-client", "other-client"], azp="console-client")
    assert OIDCClient(idp.config).validate(token, {"keys": [idp.jwk]}, "nonce") == "subject-123"


def test_bad_signature_algorithm_and_weak_or_ambiguous_keys_rejected(idp):
    client = OIDCClient(idp.config)
    token = idp.token()
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.signing_key = attacker
    bad_signature = idp.token()
    hs_token = jwt.encode(
        {"sub": "subject-123"},
        "attacker-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        algorithm="HS256",
        headers={"kid": "current"},
    )
    none_token = jwt.encode({"sub": "subject-123"}, "", algorithm="none", headers={"kid": "current"})
    for invalid in [bad_signature, hs_token, none_token, "malformed"]:
        with pytest.raises(OIDCError):
            client.validate(invalid, {"keys": [idp.jwk]}, "nonce")
    for keys in [
        [],
        [idp.jwk, idp.jwk],
        [{**idp.jwk, "kid": "old"}],
        [{**idp.jwk, "key_ops": "verify"}],
        [{**idp.jwk, "use": "enc"}],
        [{**idp.jwk, "alg": "RS512"}],
        [idp.jwk] * 101,
    ]:
        with pytest.raises(OIDCError):
            client.validate(token, {"keys": keys}, "nonce")
    weak = SignedIdP(idp.config, rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with warnings.catch_warnings(record=True):
        weak_token = weak.token()
    with pytest.raises(OIDCError):
        client.validate(weak_token, {"keys": [weak.jwk]}, "nonce")


@pytest.mark.parametrize(
    "key,value",
    [
        ("issuer", "https://other.example"),
        ("issuer", "https://idp.example.test/tenant/v2.0/"),
        ("authorization_endpoint", "https://other.example/authorize"),
        ("token_endpoint", "http://idp.example.test/token"),
        ("jwks_uri", "https://idp.example.test@evil.example/keys"),
        ("jwks_uri", "https://idp.example.test/keys?next=x"),
        ("token_endpoint", None),
        ("code_challenge_methods_supported", ["plain"]),
        ("code_challenge_methods_supported", "S256"),
        ("id_token_signing_alg_values_supported", ["none"]),
    ],
)
async def test_discovery_rejects_untrusted_endpoints_and_metadata(idp, key, value):
    idp.metadata[key] = value
    with pytest.raises(OIDCError):
        await OIDCClient(idp.config, idp.transport).authorization_url("state", "nonce", "verifier")
    assert len(idp.requests) == 1


@pytest.mark.parametrize("stage", ["/.well-known/openid-configuration", "/token", "/keys"])
async def test_http_redirects_never_followed(flow, stage):
    query = await begin(flow)
    flow.idp.redirect_path = stage
    response = await flow.client.get("/api/v1/auth/sso/callback", params=query)
    assert response.headers["location"].endswith("/login?sso_error=failed")
    assert all(request.url.host == "idp.example.test" for request in flow.idp.requests)


@pytest.mark.parametrize("payload", [b"x" * (256 * 1024 + 1), b"[]", b"not-json"], ids=["oversized", "list", "invalid"])
async def test_document_bounds_and_json_shape(identity_config, payload):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=payload))
    with pytest.raises(OIDCError):
        await OIDCClient(identity_config.oidc, transport).authorization_url("state", "nonce", "verifier")


async def test_atomic_consume_has_one_winner_and_wrong_binding_does_not_delete():
    redis = BoundRedis()
    binding = secrets.token_urlsafe(32)
    handle = await store_bound(redis, "state", {"nonce": "nonce"}, binding, STATE_TTL)
    with pytest.raises(OIDCError):
        await consume_bound(redis, "state", handle, secrets.token_urlsafe(32))
    outcomes = await asyncio.gather(
        *(consume_bound(redis, "state", handle, binding) for _ in range(10)), return_exceptions=True
    )
    assert len([value for value in outcomes if isinstance(value, dict)]) == 1
    assert len([value for value in outcomes if isinstance(value, OIDCError)]) == 9


async def test_storage_collision_fails_instead_of_returning_unwritten_handle(monkeypatch):
    redis = BoundRedis()
    monkeypatch.setattr(
        "shadai.security.oidc.secrets.token_urlsafe", lambda length: "fixed-handle-value-32-characters!"
    )
    binding = "browser-binding-value-32-characters"
    handle = await store_bound(redis, "state", {"original": True}, binding, STATE_TTL)
    with pytest.raises(OIDCError):
        await store_bound(redis, "state", {"original": False}, binding, STATE_TTL)
    assert (await consume_bound(redis, "state", handle, binding))["original"] is True


async def test_simultaneous_session_requests_have_one_winner_and_replay_fails(flow):
    await callback(flow)
    cookie_header = "; ".join(f"{cookie.name}={cookie.value}" for cookie in flow.client.cookies.jar)
    headers = {**csrf(flow), "Cookie": cookie_header}
    responses = await asyncio.gather(*(flow.client.post("/api/v1/auth/sso/session", headers=headers) for _ in range(3)))
    assert sorted(response.status_code for response in responses) == [200, 401, 401]
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=headers)).status_code == 401
    async with flow.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 1


async def test_wrong_browser_cannot_burn_handoff(flow):
    await callback(flow)
    saved = list(flow.client.cookies.jar)
    handoff = next(cookie for cookie in saved if cookie.name.endswith("handoff"))
    browser_name = sso.cookie_names(flow.config.oidc)[0]
    wrong = f"{browser_name}=wrong-browser-value-0123456789; {handoff.name}={handoff.value}"
    assert (
        await flow.client.post("/api/v1/auth/sso/session", headers={**csrf(flow), "Cookie": wrong})
    ).status_code == 401
    assert len(flow.redis.values) == 1
    for cookie in saved:
        flow.client.cookies.jar.set_cookie(cookie)
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200


async def test_jwks_rotation_observed_on_next_exchange(flow):
    await callback(flow)
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    flow.idp.signing_key = rotated
    flow.idp.jwk = {
        **jwt.algorithms.RSAAlgorithm.to_jwk(rotated.public_key(), as_dict=True),
        "kid": "current",
        "use": "sig",
        "alg": "RS256",
    }
    await callback(flow)
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200
    assert len([request for request in flow.idp.requests if request.url.path.endswith("/keys")]) == 2


@pytest.mark.parametrize("method", ["client_secret_basic", "client_secret_post"])
async def test_confidential_client_authentication_and_reserved_characters(flow, method):
    flow.config.oidc.client_id, flow.config.oidc.client_secret = "client:name+ space", "secret:with+ special/characters"
    flow.idp.metadata["token_endpoint_auth_methods_supported"] = [method]
    await callback(flow)
    request = next(request for request in flow.idp.requests if request.url.path.endswith("/token"))
    if method == "client_secret_basic":
        decoded = base64.b64decode(request.headers["Authorization"].removeprefix("Basic ")).decode()
        assert decoded == quote_plus(flow.config.oidc.client_id) + ":" + quote_plus(flow.config.oidc.client_secret)
        assert "client_secret" not in flow.idp.token_forms[0]
    else:
        assert flow.idp.token_forms[0]["client_secret"] == flow.config.oidc.client_secret
        assert "authorization" not in request.headers


async def test_explicit_loopback_development_uses_nonsecure_host_cookies(flow):
    flow.config.oidc.public_base_url = "http://localhost:5173"
    flow.config.oidc.allow_insecure_localhost = True
    validate_identity_settings(flow.config)
    flow.client.base_url = flow.config.oidc.public_base_url
    response = await callback(flow)
    for cookie in response.headers.get_list("set-cookie"):
        assert "HttpOnly" in cookie and "Secure" not in cookie and "Path=/" in cookie
        assert not cookie.startswith("__Host-")
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200


@pytest.mark.parametrize(
    "handle,binding",
    [(None, "x" * 32), ("x" * 32, None), ("short", "x" * 32), ("x" * 129, "x" * 32), ("x" * 32, "short")],
)
async def test_invalid_handle_shapes_fail_before_redis(handle, binding):
    with pytest.raises(OIDCError):
        await consume_bound(None, "state", handle, binding)


async def test_callback_missing_parameters_uses_fixed_error_redirect(flow):
    response = await flow.client.get("/api/v1/auth/sso/callback")
    assert response.status_code == 303 and response.headers["location"].endswith("/login?sso_error=failed")
    assert response.headers["cache-control"] == "no-store"


async def test_exact_issuer_trailing_slash_remains_identity_significant(idp):
    idp.config.issuer += "/"
    idp.metadata["issuer"] = idp.config.issuer
    client = OIDCClient(idp.config, idp.transport)
    await client.authorization_url("state", "nonce", "verifier")
    assert idp.requests[0].url.path.endswith("/v2.0/.well-known/openid-configuration")
    assert client.validate(idp.token(), {"keys": [idp.jwk]}, "nonce") == "subject-123"
    with pytest.raises(OIDCError):
        client.validate(idp.token(iss=idp.config.issuer.rstrip("/")), {"keys": [idp.jwk]}, "nonce")


async def test_entra_discovery_without_optional_pkce_metadata_still_uses_s256(flow):
    flow.idp.metadata.pop("code_challenge_methods_supported")
    flow.idp.metadata["token_endpoint_auth_methods_supported"] = ["client_secret_post"]
    await callback(flow)  # the mock verifies S256 challenge and the exchanged verifier
    assert len(flow.idp.token_forms[0]["code_verifier"]) >= 43
    response = await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
    assert response.status_code == 200 and decode_access_token(session_cookie(response)).sub == flow.user_id


async def test_uppercase_https_still_uses_secure_host_cookies(flow):
    flow.config.oidc.public_base_url = "HTTPS://console.example.test"
    validate_identity_settings(flow.config)
    response = await callback(flow)
    for cookie in response.headers.get_list("set-cookie"):
        assert "Secure" in cookie and cookie.startswith("__Host-")
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 200


async def test_failed_durable_commit_exposes_no_token_and_cannot_retry_ticket(flow, monkeypatch):
    await callback(flow)
    original_commit = AsyncSession.commit

    async def failed_commit(session):
        raise RuntimeError("Simulated durable write failure")

    monkeypatch.setattr(AsyncSession, "commit", failed_commit)
    with pytest.raises(RuntimeError, match="Simulated durable write failure"):
        await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))
    monkeypatch.setattr(AsyncSession, "commit", original_commit)
    assert not flow.redis.values
    async with flow.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(AuditLogORM)) == 0
        assert (await session.get(UserORM, flow.user_id)).last_login_at is None
    assert (await flow.client.post("/api/v1/auth/sso/session", headers=csrf(flow))).status_code == 401
