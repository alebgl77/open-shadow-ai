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
from redis.exceptions import OutOfMemoryError

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


async def test_real_redis_oom_before_allocation_and_owned_release_recovers(sso_pressure_redis, monkeypatch):
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
    handles, fillers = [], []

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
    try:
        for index in range(64):
            key = f"{namespace}:filler:{index}"
            fillers.append(key)  # Track even a lost reply; cleanup owns the entire namespace.
            try:
                await redis.set(key, "x" * (1024 * 1024), ex=120)
            except OutOfMemoryError:
                break
        else:
            pytest.fail("Bounded owned filler did not produce actual Redis OOM")
        # A large rejected SET may temporarily count its query buffer. Top up with
        # small owned keys until read-only INFO observes sustained pressure.
        for index in range(2048):
            memory = await redis.info("memory")
            if memory["used_memory"] - memory.get("mem_not_counted_for_evict", 0) > 32 * 1024 * 1024:
                break
            key = f"{namespace}:filler:small:{index}"
            fillers.append(key)
            try:
                await redis.set(key, "x" * 1024, ex=120)
            except OutOfMemoryError:
                await asyncio.sleep(0.001)
        else:
            pytest.fail("Redis OOM did not persist after the large query buffer was released")
        before = [await redis.dump(key) for key in admission.keys]
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=config.oidc.public_base_url
        ) as http:
            response = await http.get("/api/v1/auth/sso/login")
            assert response.status_code == 503 and not provider.called and not handles
            assert [await redis.dump(key) for key in admission.keys] == before
            assert await redis.get(sentinel) == "preserve-peer-owned-state"
            await redis.delete(*fillers)
            fillers.clear()
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
    finally:
        owned = [*fillers, *admission.keys, *("oidc:state:" + digest(handle) for handle in handles), sentinel]
        await redis.delete(*owned)
        verify_pressure_policy(await redis.config_get("maxmemory", "maxmemory-policy", "appendonly"),
                               await redis.info("persistence"))
