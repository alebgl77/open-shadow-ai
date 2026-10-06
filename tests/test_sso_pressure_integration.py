"""Real SSO OOM fail-closed and recovery on the dedicated bounded lab Redis."""

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
import redis.asyncio as aioredis
from fastapi import FastAPI
from redis_pressure_fixture import sustained_pressure

from shadai.api import sso
from shadai.config import OIDCSettings, ShadAIConfig
from shadai.security.oidc import digest
from shadai.security.sso_admission import SSOAdmission

pytestmark = pytest.mark.redis_pressure


def pressure_settings(environment):
    required = environment.get("SHADAI_REQUIRE_REDIS_PRESSURE") == "1"
    keys = ("SHADAI_REDIS_PRESSURE_HOST", "SHADAI_REDIS_PRESSURE_PORT", "SHADAI_REDIS_PRESSURE_PASSWORD_FILE")
    if not all(environment.get(key) for key in keys):
        if required:
            pytest.fail("Mandatory Redis pressure configuration is missing")
        pytest.skip("Dedicated Redis pressure lab was not requested")
    if environment.get("SHADAI_REDIS_PRESSURE_LAB") != "1" or \
            tuple(environment[key] for key in keys) != \
            ("labredis-pressure", "6379", "/run/secrets/redis_pressure_password"):
        pytest.fail("SSO pressure tests require the isolated lab Redis and private secret file")
    return environment[keys[0]], int(environment[keys[1]]), Path(environment[keys[2]])


def verify_pressure_policy(policy, persistence):
    if int(policy.get("maxmemory", 0)) != 32 * 1024 * 1024 or policy.get("maxmemory-policy") != "noeviction" or \
            policy.get("appendonly") != "yes" or persistence.get("aof_enabled") != 1 or \
            persistence.get("aof_last_write_status") != "ok":
        pytest.fail("Redis pressure lab must actually use 32MiB/noeviction and healthy AOF")


@pytest.fixture
async def sso_pressure_redis():
    host, port, secret_file = pressure_settings(os.environ)
    password = secret_file.read_text(encoding="utf-8").strip()
    if not password:
        pytest.fail("Redis pressure private secret is empty")
    client = aioredis.Redis(host=host, port=port, password=password, decode_responses=True,
                           socket_connect_timeout=5, socket_timeout=5)
    try:
        await client.ping()
        verify_pressure_policy(await client.config_get("maxmemory", "maxmemory-policy", "appendonly"),
                               await client.info("persistence"))
        yield client
    finally:
        await client.aclose()


async def test_real_redis_oom_before_allocation_and_owned_release_recovers(
        sso_pressure_redis, monkeypatch, record_property):
    redis = sso_pressure_redis
    namespace = "test-sso-pressure-" + uuid4().hex
    config = ShadAIConfig(tenant_id=namespace, oidc=OIDCSettings(
        enabled=True, issuer="https://idp.example.test", client_id="synthetic-client",
        client_secret="synthetic-private-secret", public_base_url="https://console.example.test",
        login_peer_limit=2, login_installation_limit=2,
    ))
    provider = AsyncMock(return_value="https://idp.example.test/authorize")
    monkeypatch.setattr(sso, "get_config", lambda: config)
    monkeypatch.setattr(sso, "get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr(sso, "OIDCClient", lambda settings: SimpleNamespace(authorization_url=provider))
    original_store = sso.store_bound
    handles = []

    async def remember(*args):
        handle = await original_store(*args)
        handles.append(handle)
        return handle

    monkeypatch.setattr(sso, "store_bound", remember)
    admission = SSOAdmission(redis, namespace, config.oidc)
    sentinel = namespace + ":foreign-sentinel"
    await redis.set(sentinel, "preserve-peer-owned-state", ex=120)
    app = FastAPI()
    app.include_router(sso.router)
    primary = None
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=config.oidc.public_base_url
        ) as http:
            async with sustained_pressure(redis, prefix=namespace + ":filler:",
                                          chunk_bytes=1024 * 1024, max_fill=64) as proof:
                before = [await redis.dump(key) for key in admission.keys]
                response = await http.get("/api/v1/auth/sso/login")
                assert response.status_code == 503 and not provider.called and not handles
                assert [await redis.dump(key) for key in admission.keys] == before
                assert await redis.get(sentinel) == "preserve-peer-owned-state"
            for key, value in proof.items():
                record_property(key, value)
            seconds, _ = await redis.time()
            if seconds % 60 >= 55:
                await asyncio.sleep(61 - seconds % 60)
            assert (await http.get("/api/v1/auth/sso/login")).status_code == 303
            assert (await http.get("/api/v1/auth/sso/login")).status_code == 303
            before_denial = [await redis.dump(key) for key in admission.keys]
            assert (await http.get("/api/v1/auth/sso/login")).status_code == 429
            assert provider.await_count == len(handles) == 2
            assert [await redis.dump(key) for key in admission.keys] == before_denial
            assert await redis.zcard(admission.keys[2]) == 0
            assert await redis.get(sentinel) == "preserve-peer-owned-state"
    except BaseException as exc:
        primary = exc
        raise
    finally:
        owned = [*admission.keys, *("oidc:state:" + digest(handle) for handle in handles), sentinel]
        cleanup_error = None
        try:
            async with asyncio.timeout(5):
                await redis.delete(*owned)
        except BaseException as exc:
            cleanup_error = exc
            if primary is not None:
                primary.add_note("sso_pressure_owned_cleanup_failed")
        try:
            async with asyncio.timeout(5):
                verify_pressure_policy(await redis.config_get("maxmemory", "maxmemory-policy", "appendonly"),
                                       await redis.info("persistence"))
        except BaseException as exc:
            cleanup_error = cleanup_error or exc
            if primary is not None:
                primary.add_note("sso_pressure_policy_verification_failed")
        if primary is None and cleanup_error is not None:
            raise cleanup_error
