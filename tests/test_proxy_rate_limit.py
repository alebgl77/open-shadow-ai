"""Exercise the login route behind Uvicorn's actual proxy-header middleware."""

import hashlib
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import yaml
from fastapi import FastAPI
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from shadai.api import auth
from shadai.database import get_postgres_session

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
FRONTEND_ADDRESS = COMPOSE["services"]["frontend"]["networks"]["edge"]["ipv4_address"]
FRONTEND_IP = re.fullmatch(r"\$\{SHADAI_EDGE_FRONTEND_IP:-(.+)}", FRONTEND_ADDRESS)[1]


@pytest.fixture
def login_app(monkeypatch):
    app = FastAPI()
    app.include_router(auth.router)
    counters = Counter()

    async def incr(key):
        counters[key] += 1
        return counters[key]

    redis = SimpleNamespace(incr=incr, expire=AsyncMock())
    monkeypatch.setattr(auth, "get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr(auth, "datetime", SimpleNamespace(now=lambda _: datetime(2026, 10, 5, tzinfo=UTC)))
    session = SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: None)))

    async def database():
        yield session

    app.dependency_overrides[get_postgres_session] = database
    return ProxyHeadersMiddleware(app, trusted_hosts=[FRONTEND_IP]), counters


class BundledProxy:
    """Model the two nginx header assignments checked against the shipped config below."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        headers = [(k, v) for k, v in scope["headers"] if k not in (b"x-forwarded-for", b"x-forwarded-proto")]
        headers.extend([(b"x-forwarded-for", scope["client"][0].encode()), (b"x-forwarded-proto", b"http")])
        await self.app({**scope, "client": (FRONTEND_IP, 1234), "headers": headers}, receive, send)


async def attempt(app, peer, spoofed="203.0.113.200"):
    transport = httpx.ASGITransport(app, client=(peer, 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://console.example.test") as client:
        return await client.post(
            "/api/v1/auth/login",
            json={"username": "missing", "password": "invalid-password"},
            headers={"X-Forwarded-For": spoofed, "X-Forwarded-Proto": "https"},
        )


def test_compose_trusts_only_the_bundled_proxy_and_nginx_overwrites_headers():
    services = COMPOSE["services"]
    assert services["api"]["environment"]["FORWARDED_ALLOW_IPS"] == FRONTEND_ADDRESS
    assert "*" not in FRONTEND_ADDRESS
    assert services["api"]["networks"]["edge"]["ipv4_address"] != FRONTEND_ADDRESS
    assert COMPOSE["networks"]["edge"]["ipam"]["config"] == [{"subnet": "${SHADAI_EDGE_SUBNET:-172.30.0.0/24}"}]
    for name, service in services.items():
        if name not in ("api", "frontend"):
            assert "edge" not in service.get("networks", [])
        if name != "api":
            assert "FORWARDED_ALLOW_IPS" not in service.get("environment", {})
    config = (ROOT / "frontend/nginx.conf").read_text(encoding="utf-8")
    assert config.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
    assert "$proxy_add_x_forwarded_for" not in config
    assert "real_ip_header" not in config and "set_real_ip_from" not in config
    assert '"--proxy-headers"' in (ROOT / "docker/Dockerfile.api").read_text(encoding="utf-8")


async def test_twenty_one_distinct_proxied_clients_have_separate_login_buckets(login_app):
    app, counters = login_app
    proxy = BundledProxy(app)
    for number in range(1, 22):
        response = await attempt(proxy, f"198.51.100.{number}")
        assert response.status_code == 401
    assert len(counters) == 21 and set(counters.values()) == {1}


async def test_proxied_client_cannot_evade_limit_with_forged_headers(login_app):
    app, counters = login_app
    proxy = BundledProxy(app)
    for number in range(21):
        response = await attempt(proxy, "198.51.100.42", f"203.0.113.{number}, 127.0.0.1")
        assert response.status_code == (401 if number < 20 else 429)
    assert response.headers["retry-after"] == "60"
    assert len(counters) == 1
    assert hashlib.sha256(b"198.51.100.42").hexdigest() in next(iter(counters))


@pytest.mark.parametrize("peer", ["198.51.100.50", "127.0.0.1", "172.30.0.20"])
async def test_direct_api_or_other_network_peer_cannot_choose_its_bucket(login_app, peer):
    app, counters = login_app
    for number in range(21):
        response = await attempt(app, peer, f"203.0.113.{number}")
        assert response.status_code == (401 if number < 20 else 429)
    assert len(counters) == 1
    assert hashlib.sha256(peer.encode()).hexdigest() in next(iter(counters))
