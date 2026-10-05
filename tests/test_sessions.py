from unittest.mock import AsyncMock

import httpx
import pytest

from shadai.config import get_config
from shadai.database import get_postgres_session
from shadai.models.user import UserORM
from shadai.security.auth import csrf_token_for, hash_password

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
async def console(identity_sessions, monkeypatch):
    from shadai.main import app

    async def database():
        async with identity_sessions.begin() as session:
            yield session

    async with identity_sessions.begin() as session:
        session.add(UserORM(username="admin", password_hash=hash_password(PASSWORD), role="admin"))
        session.add(UserORM(username="analyst", password_hash=hash_password(PASSWORD), role="analyst"))
    redis = AsyncMock()
    redis.exists.return_value = 0
    redis.incr.return_value = 1
    monkeypatch.setattr("shadai.security.auth.get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.api.auth.get_redis", AsyncMock(return_value=redis))
    app.dependency_overrides[get_postgres_session] = database
    transport = httpx.ASGITransport(app)
    try:
        yield app, transport, redis
    finally:
        app.dependency_overrides.clear()


def client(transport, base_url="https://console.example.test"):
    return httpx.AsyncClient(transport=transport, base_url=base_url)


async def browser_login(browser, username="admin"):
    response = await browser.post(
        "/api/v1/auth/login", json={"username": username, "password": PASSWORD}, headers={"X-Session-Mode": "cookie"}
    )
    assert response.status_code == 200, response.text
    return response


async def test_browser_login_sets_only_an_httponly_strict_cookie(console):
    _, transport, _ = console
    async with client(transport) as browser:
        response = await browser_login(browser)
        cookie = response.headers["set-cookie"]
        assert cookie.startswith("__Host-shadai-session=")
        for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/", "Max-Age=86400"):
            assert attribute in cookie
        assert "Domain=" not in cookie
        body = response.json()
        assert body["access_token"] is None and body["token_type"] == "cookie" and body["csrf_token"]
        assert response.headers["cache-control"] == "no-store"
        token = browser.cookies["__Host-shadai-session"]
        assert body["csrf_token"] == csrf_token_for(token) and body["csrf_token"] not in token


async def test_reload_restores_the_session_from_the_cookie_alone(console):
    _, transport, _ = console
    async with client(transport) as browser:
        csrf = (await browser_login(browser)).json()["csrf_token"]
        # A reload loses every script variable; only the browser's cookie jar survives.
        restored = await browser.get("/api/v1/auth/session")
        assert restored.status_code == 200
        assert restored.json()["csrf_token"] == csrf and restored.json()["user"]["username"] == "admin"
        assert restored.headers["cache-control"] == "no-store"
        assert (await browser.get("/api/v1/auth/me")).json()["role"] == "admin"
    async with client(transport) as stranger:
        assert (await stranger.get("/api/v1/auth/session")).status_code == 401


async def test_cookie_writes_require_the_session_csrf_token(console):
    _, transport, _ = console
    async with client(transport) as browser:
        csrf = (await browser_login(browser)).json()["csrf_token"]
        users = (await browser.get("/api/v1/settings/users/")).json()
        analyst = next(user for user in users if user["username"] == "analyst")
        url = f"/api/v1/settings/users/{analyst['user_id']}"
        assert (await browser.put(url, json={"email": "a@example.test"})).status_code == 403
        wrong = {"X-CSRF-Token": csrf_token_for("another-session")}
        assert (await browser.put(url, json={"email": "a@example.test"}, headers=wrong)).status_code == 403
        allowed = await browser.put(url, json={"email": "a@example.test"}, headers={"X-CSRF-Token": csrf})
        assert allowed.status_code == 200 and allowed.json()["email"] == "a@example.test"


async def test_collections_answer_without_a_trailing_slash_redirect(console):
    _, transport, _ = console
    async with client(transport) as browser:
        csrf = (await browser_login(browser)).json()["csrf_token"]
        listing = await browser.get("/api/v1/settings/users")
        assert listing.status_code == 200 and len(listing.json()) == 2
        created = await browser.post(
            "/api/v1/settings/users",
            json={"username": "reviewer", "password": PASSWORD, "role": "viewer"},
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201


async def test_bearer_clients_are_unchanged_and_need_no_csrf(console):
    _, transport, _ = console
    async with client(transport) as api:
        response = await api.post("/api/v1/auth/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 200 and "set-cookie" not in response.headers
        body = response.json()
        assert body["token_type"] == "bearer" and body["access_token"] and body["csrf_token"] is None
        auth = {"Authorization": "Bearer " + body["access_token"]}
        users = (await api.get("/api/v1/settings/users/", headers=auth)).json()
        analyst = next(user for user in users if user["username"] == "analyst")
        url = f"/api/v1/settings/users/{analyst['user_id']}"
        assert (await api.put(url, json={"email": "b@example.test"}, headers=auth)).status_code == 200


async def test_logout_revokes_the_session_and_clears_the_cookie(console):
    _, transport, redis = console
    async with client(transport) as browser:
        csrf = (await browser_login(browser)).json()["csrf_token"]
        assert (await browser.post("/api/v1/auth/logout")).status_code == 403
        response = await browser.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        assert response.status_code == 200
        assert redis.set.call_args.args[0].startswith("revoked:")
        cleared = response.headers["set-cookie"]
        assert cleared.startswith('__Host-shadai-session=""') and "Max-Age=0" in cleared
        assert not browser.cookies
        assert (await browser.get("/api/v1/auth/session")).status_code == 401


async def test_loopback_http_uses_a_plain_cookie_and_ignores_unprefixed_cookies_elsewhere(console, monkeypatch):
    _, transport, _ = console
    async with client(transport, "http://localhost:3000") as local:
        cookie = (await browser_login(local)).headers["set-cookie"]
        assert cookie.startswith("shadai-session=") and "Secure" not in cookie and "SameSite=strict" in cookie
        assert (await local.get("/api/v1/auth/session")).status_code == 200
        token = local.cookies["shadai-session"]
    # On a TLS host only the __Host- cookie counts: a sibling subdomain cannot plant a session.
    async with client(transport) as remote:
        remote.cookies.set("shadai-session", token, domain="console.example.test")
        assert (await remote.get("/api/v1/auth/session")).status_code == 401
    monkeypatch.setattr(get_config().server, "session_cookie_secure", True)
    async with client(transport, "http://localhost:3000") as forced:
        assert (await browser_login(forced)).headers["set-cookie"].startswith("__Host-shadai-session=")


def test_session_cookie_secure_environment_override(monkeypatch):
    from shadai.config import load_config

    for value, expected in (("true", True), ("false", False), ("auto", None), ("", None)):
        monkeypatch.setenv("SESSION_COOKIE_SECURE", value)
        assert load_config("/nonexistent.yaml").server.session_cookie_secure is expected
