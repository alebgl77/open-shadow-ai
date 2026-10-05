"""Exercise the login route behind Uvicorn's actual proxy-header middleware."""

import hashlib
import re
import subprocess
import sys
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


@pytest.fixture
def proxy_config():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    frontend_address = compose["services"]["frontend"]["networks"]["edge"]["ipv4_address"]
    return SimpleNamespace(
        compose=compose,
        frontend_address=frontend_address,
        frontend_ip=re.fullmatch(r"\$\{SHADAI_EDGE_FRONTEND_IP:-(.+)}", frontend_address)[1],
        nginx=(ROOT / "frontend/nginx.conf").read_text(encoding="utf-8"),
        dockerfile=(ROOT / "docker/Dockerfile.api").read_text(encoding="utf-8"),
    )


@pytest.fixture
def login_app(monkeypatch, proxy_config):
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
    return ProxyHeadersMiddleware(app, trusted_hosts=[proxy_config.frontend_ip]), counters


class BundledProxy:
    """Model the two nginx header assignments checked against the shipped config below."""

    def __init__(self, app, frontend_ip):
        self.app = app
        self.frontend_ip = frontend_ip

    async def __call__(self, scope, receive, send):
        headers = [(k, v) for k, v in scope["headers"] if k not in (b"x-forwarded-for", b"x-forwarded-proto")]
        headers.extend([(b"x-forwarded-for", scope["client"][0].encode()), (b"x-forwarded-proto", b"http")])
        await self.app({**scope, "client": (self.frontend_ip, 1234), "headers": headers}, receive, send)


async def attempt(app, peer, spoofed="203.0.113.200"):
    transport = httpx.ASGITransport(app, client=(peer, 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://console.example.test") as client:
        return await client.post(
            "/api/v1/auth/login",
            json={"username": "missing", "password": "invalid-password"},
            headers={"X-Forwarded-For": spoofed, "X-Forwarded-Proto": "https"},
        )


def test_compose_trusts_only_the_bundled_proxy_and_nginx_overwrites_headers(proxy_config):
    services = proxy_config.compose["services"]
    assert services["api"]["environment"]["FORWARDED_ALLOW_IPS"] == proxy_config.frontend_address
    assert "*" not in proxy_config.frontend_address
    assert services["api"]["networks"]["edge"]["ipv4_address"] != proxy_config.frontend_address
    assert proxy_config.compose["networks"]["edge"]["ipam"]["config"] == [
        {"subnet": "${SHADAI_EDGE_SUBNET:-172.30.0.0/24}"}
    ]
    for name, service in services.items():
        if name not in ("api", "frontend"):
            assert "edge" not in service.get("networks", [])
        if name != "api":
            assert "FORWARDED_ALLOW_IPS" not in service.get("environment", {})
    config = proxy_config.nginx
    assert config.count("proxy_set_header X-Forwarded-For $remote_addr;") == 2
    assert "$proxy_add_x_forwarded_for" not in config
    assert "real_ip_header" not in config and "set_real_ip_from" not in config
    assert '"--proxy-headers"' in proxy_config.dockerfile


async def test_twenty_one_distinct_proxied_clients_have_separate_login_buckets(login_app, proxy_config):
    app, counters = login_app
    proxy = BundledProxy(app, proxy_config.frontend_ip)
    for number in range(1, 22):
        response = await attempt(proxy, f"198.51.100.{number}")
        assert response.status_code == 401
    assert len(counters) == 21 and set(counters.values()) == {1}


async def test_proxied_client_cannot_evade_limit_with_forged_headers(login_app, proxy_config):
    app, counters = login_app
    proxy = BundledProxy(app, proxy_config.frontend_ip)
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


def test_integration_collection_does_not_require_deployment_assets(tmp_path):
    isolated_tests = tmp_path / "tests"
    isolated_tests.mkdir()
    isolated_proxy = isolated_tests / Path(__file__).name
    isolated_proxy.write_text(Path(__file__).read_text(encoding="utf-8"), encoding="utf-8")
    assert not (tmp_path / "docker-compose.yml").exists()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-m",
            "integration",
            "-q",
            "-p",
            "no:cacheprovider",
            str(ROOT / "tests/test_integration.py"),
            str(isolated_proxy),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_live_concurrent_notes_preserve_both_notes_and_audits" in result.stdout
