"""Real Redis admission atomicity and HTTP lifecycle, collected by Compose CI."""

import asyncio
import copy
import hashlib
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
import redis.asyncio as aioredis
from fastapi import FastAPI
from redis.exceptions import ConnectionError as RedisConnectionError

from shadai.api import sso
from shadai.config import OIDCSettings, ShadAIConfig, load_config
from shadai.security.oidc import STATE_TTL, OIDCError, consume_bound, digest, store_bound
from shadai.security.sso_admission import ADMIT, AdmissionDeniedError, AdmissionUnavailableError, SSOAdmission

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("SHADAI_INTEGRATION") != "1", reason="Disposable Redis not requested"),
]


@pytest.fixture
async def redis_pair():
    url = load_config().database.redis_url
    clients = [aioredis.from_url(url, decode_responses=True) for _ in range(2)]
    tenant = "test-sso-" + uuid4().hex
    try:
        await asyncio.gather(*(client.ping() for client in clients))
        yield clients, tenant
    finally:
        keys = SSOAdmission(clients[0], tenant, OIDCSettings()).keys
        await clients[0].delete(*keys)
        await asyncio.gather(*(client.aclose() for client in clients))


async def snapshot(redis, admission):
    return (
        await redis.hgetall(admission.keys[0]), await redis.hgetall(admission.keys[1]),
        await redis.zrange(admission.keys[2], 0, -1, withscores=True),
    )


async def fresh_minute(redis):
    seconds, _ = await redis.time()
    if seconds % 60 >= 55:
        await asyncio.sleep(61 - seconds % 60)


@pytest.mark.parametrize("multiple_peers", [False, True])
async def test_real_two_instances_50_concurrent_exact_quota_at_most_four_leases(redis_pair, multiple_peers):
    clients, tenant = redis_pair
    await fresh_minute(clients[0])
    config = OIDCSettings(login_installation_limit=20)
    instances = [SSOAdmission(client, tenant, config) for client in clients]
    barrier = asyncio.Event()
    maximum_live = 0

    async def attempt(index):
        nonlocal maximum_live
        admission = instances[index % 2]
        peer = f"192.0.2.{index + 1}" if multiple_peers else "192.0.2.1"
        token = admission.token()
        await barrier.wait()
        # Busy requests retry while these tiny synthetic jobs finish; quota
        # denials never retry. The 50 callers start together on separate pools.
        for _ in range(100):
            result = await admission.redis.eval(
                ADMIT, 3, *admission.keys, hashlib.sha256(peer.encode()).hexdigest(), token,
                config.login_peer_limit, config.login_installation_limit, config.login_concurrency,
                config.login_lease_seconds * 1000,
            )
            if result[0] == 1:
                return False
            if result[0] == 2:
                await asyncio.sleep(0.005)
                continue
            assert result == [0, 0]
            clock = await admission.redis.time()
            live = await admission.redis.zcount(admission.keys[2], clock[0] * 1000 + clock[1] // 1000, "+inf")
            maximum_live = max(maximum_live, live)
            assert live <= 4
            await admission.release(token)
            return True
        raise AssertionError("Synthetic jobs did not release their leases")

    tasks = [asyncio.create_task(attempt(index)) for index in range(50)]
    barrier.set()
    accepted = await asyncio.gather(*tasks)
    expected = 20 if multiple_peers else 10
    assert sum(accepted) == expected and maximum_live <= 4
    meta, peers, leases = await snapshot(clients[0], instances[0])
    assert int(meta["count"]) == expected and len(peers) <= expected and not leases
    before = await snapshot(clients[0], instances[0])
    with pytest.raises(AdmissionDeniedError):
        await instances[1].admit("192.0.2.1", instances[1].token())
    assert await snapshot(clients[0], instances[0]) == before
    ttls = await asyncio.gather(*(clients[0].ttl(key) for key in instances[0].keys[:2]))
    assert all(0 < ttl <= 120 for ttl in ttls)


async def test_real_50_concurrent_busy_denial_no_allocations_and_stale_lease_ttl(redis_pair):
    clients, tenant = redis_pair
    instances = [SSOAdmission(client, tenant, OIDCSettings()) for client in clients]

    async def attempt(index):
        admission = instances[index % 2]
        token = admission.token()
        try:
            await admission.admit(f"192.0.2.{index + 1}", token)
            return token
        except AdmissionDeniedError as exc:
            assert 1 <= exc.retry_after <= 60
            return None

    tokens = await asyncio.gather(*(attempt(index) for index in range(50)))
    assert sum(token is not None for token in tokens) == 4
    meta, peers, leases = await snapshot(clients[0], instances[0])
    assert int(meta["count"]) == len(peers) == len(leases) == 4
    before = await snapshot(clients[0], instances[0])
    with pytest.raises(AdmissionDeniedError):
        await instances[1].admit("192.0.2.100", instances[1].token())
    assert await snapshot(clients[0], instances[0]) == before
    assert 0 < await clients[0].pttl(instances[0].keys[2]) <= 16000
    # A crashed worker leaves a lease. Redis TIME, rather than a host clock,
    # determines expiry; seed already-expired leases without waiting 15 seconds.
    await clients[0].zadd(instances[0].keys[2], {token: 1 for token in tokens if token is not None})
    replacement = await attempt(100)
    assert replacement and await clients[0].zcard(instances[0].keys[2]) == 1
    await instances[1].release(instances[1].token())
    assert await clients[0].zcard(instances[0].keys[2]) == 1  # foreign release is harmless
    await instances[1].release(replacement)
    assert await clients[0].zcard(instances[0].keys[2]) == 0


@pytest.mark.parametrize("key_index, bad_type", [(0, "string"), (1, "list"), (2, "hash")])
async def test_real_wrongtype_validates_all_keys_before_first_write(redis_pair, key_index, bad_type):
    clients, tenant = redis_pair
    admission = SSOAdmission(clients[0], tenant, OIDCSettings())
    key = admission.keys[key_index]
    if bad_type == "string":
        await clients[0].set(key, "synthetic-corrupt")
    elif bad_type == "list":
        await clients[0].lpush(key, "synthetic-corrupt")
    else:
        await clients[0].hset(key, mapping={"synthetic": "corrupt"})
    before = {item: await clients[0].dump(item) for item in admission.keys}
    with pytest.raises(AdmissionUnavailableError):
        await admission.admit("192.0.2.1", admission.token())
    assert {item: await clients[0].dump(item) for item in admission.keys} == before


@pytest.mark.parametrize("corrupt", ["count", "peer", "lease", "cardinality", "counter_mismatch", "noncanonical"])
async def test_real_corrupt_numeric_ranges_and_cardinality_fail_closed(redis_pair, corrupt):
    clients, tenant = redis_pair
    admission = SSOAdmission(clients[0], tenant, OIDCSettings(login_installation_limit=10))
    token = admission.token()
    await admission.admit("192.0.2.1", token)
    if corrupt == "count":
        await clients[0].hset(admission.keys[0], "count", "not-a-number")
    elif corrupt == "peer":
        await clients[0].hset(admission.keys[1], digest("192.0.2.1"), -1)
    elif corrupt == "lease":
        await clients[0].zadd(admission.keys[2], {token: 1.5})
    elif corrupt == "cardinality":
        await clients[0].hset(admission.keys[1], mapping={digest(str(index)): 1 for index in range(11)})
    elif corrupt == "counter_mismatch":
        await clients[0].hset(admission.keys[1], mapping={digest(str(index)): 1 for index in range(5)})
    else:
        await clients[0].hset(admission.keys[1], digest("192.0.2.1"), "1.0")
    before = await snapshot(clients[0], admission)
    with pytest.raises(AdmissionUnavailableError):
        await admission.admit("192.0.2.2", admission.token())
    assert await snapshot(clients[0], admission) == before


async def test_real_minute_rollover_ignores_old_counts_then_resets_peers(redis_pair):
    clients, tenant = redis_pair
    admission = SSOAdmission(clients[0], tenant, OIDCSettings())
    token = admission.token()
    await admission.admit("192.0.2.1", token)
    await admission.release(token)
    clock = await clients[0].time()
    bucket = clock[0] // 60
    await clients[0].hset(admission.keys[0], mapping={"bucket": bucket - 1, "count": 120})
    await clients[0].hset(admission.keys[1], digest("192.0.2.1"), 10)
    await admission.admit("192.0.2.1", admission.token())
    meta = await clients[0].hgetall(admission.keys[0])
    after = await clients[0].time()
    assert bucket <= int(meta["bucket"]) <= after[0] // 60 and meta["count"] == "1"
    assert await clients[0].hgetall(admission.keys[1]) == {digest("192.0.2.1"): "1"}


@pytest.fixture
async def real_login(redis_pair, monkeypatch):
    clients, tenant = redis_pair
    config = ShadAIConfig(tenant_id=tenant, oidc=OIDCSettings(
        enabled=True, issuer="https://idp.example.test", client_id="synthetic-client",
        client_secret="synthetic-private-secret", public_base_url="https://console.example.test",
    ))
    provider = AsyncMock(return_value="https://idp.example.test/authorize")
    monkeypatch.setattr(sso, "get_config", lambda: config)
    monkeypatch.setattr(sso, "get_redis", AsyncMock(return_value=clients[0]))
    monkeypatch.setattr(sso, "OIDCClient", lambda settings: SimpleNamespace(authorization_url=provider))
    app = FastAPI()
    app.include_router(sso.router)
    handles = []
    original = sso.store_bound

    async def remember(*args):
        handle = await original(*args)
        handles.append(handle)
        return handle

    monkeypatch.setattr(sso, "store_bound", remember)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=config.oidc.public_base_url
    ) as http:
        try:
            yield SimpleNamespace(http=http, redis=clients[0], config=config, provider=provider, handles=handles)
        finally:
            if handles:
                await clients[0].delete(*("oidc:state:" + digest(handle) for handle in handles))


async def test_real_http_denial_no_idp_state_or_counter_allocation(real_login):
    await fresh_minute(real_login.redis)
    for _ in range(10):
        assert (await real_login.http.get("/api/v1/auth/sso/login")).status_code == 303
    admission = SSOAdmission(real_login.redis, real_login.config.tenant_id, real_login.config.oidc)
    before = await snapshot(real_login.redis, admission)
    states = copy.copy(real_login.handles)
    responses = await asyncio.gather(*(real_login.http.get("/api/v1/auth/sso/login", headers={
        "X-Forwarded-For": f"203.0.113.{index + 1}", "Forwarded": f"for=203.0.113.{index + 1}",
    }) for index in range(50)))
    assert all(response.status_code == 429 for response in responses)
    assert real_login.provider.await_count == len(real_login.handles) == 10
    assert real_login.handles == states and await snapshot(real_login.redis, admission) == before


async def test_real_provider_503_owned_cleanup_foreign_and_mismatch_preserved(real_login):
    binding = "synthetic-foreign-browser-binding-1234"
    foreign = await store_bound(real_login.redis, "state", {"nonce": "foreign"}, binding, STATE_TTL)
    real_login.handles.append(foreign)
    key = "oidc:state:" + digest(foreign)
    before = await real_login.redis.get(key)
    try:
        real_login.provider.side_effect = RedisConnectionError("synthetic-private-details")
        response = await real_login.http.get("/api/v1/auth/sso/login")
        assert response.status_code == 503 and "private-details" not in response.text
        owned = real_login.handles[-1]
        assert owned != foreign and not await real_login.redis.exists("oidc:state:" + digest(owned))
        assert await real_login.redis.get(key) == before
        with pytest.raises(OIDCError):
            await consume_bound(real_login.redis, "state", foreign, "wrong-binding-value-123456789")
        assert await real_login.redis.get(key) == before
    finally:
        await real_login.redis.delete(key)


async def test_real_total_deadline_cancel_and_state_ttl(real_login):
    real_login.config.oidc.login_timeout_seconds = 1
    started = asyncio.Event()

    async def drip(*args):
        started.set()
        while True:
            await asyncio.sleep(0.1)

    real_login.provider.side_effect = drip
    response = await real_login.http.get("/api/v1/auth/sso/login")
    assert response.status_code == 303 and response.headers["location"].endswith("/login?sso_error=failed")
    assert not await real_login.redis.exists("oidc:state:" + digest(real_login.handles[-1]))
    started.clear()
    task = asyncio.create_task(real_login.http.get("/api/v1/auth/sso/login"))
    await started.wait()
    handle = real_login.handles[-1]
    assert 0 < await real_login.redis.ttl("oidc:state:" + digest(handle)) <= 300
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not await real_login.redis.exists("oidc:state:" + digest(handle))
    admission = SSOAdmission(real_login.redis, real_login.config.tenant_id, real_login.config.oidc)
    assert not await real_login.redis.zcard(admission.keys[2])


async def test_real_crashed_lease_key_expires_without_cleanup(redis_pair):
    clients, tenant = redis_pair
    admission = SSOAdmission(clients[0], tenant, OIDCSettings(login_timeout_seconds=1, login_lease_seconds=4))
    await admission.admit("192.0.2.1", admission.token())
    assert 0 < await clients[0].pttl(admission.keys[2]) <= 5000
    await asyncio.sleep(5.1)
    assert not await clients[0].exists(admission.keys[2])
    assert await clients[0].hget(admission.keys[0], "count") == "1"  # quota is never refunded


async def test_real_unreachable_redis_is_503_no_provider_or_state(real_login, monkeypatch):
    unavailable = aioredis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.2, decode_responses=True)
    monkeypatch.setattr(sso, "get_redis", AsyncMock(return_value=unavailable))
    try:
        response = await real_login.http.get("/api/v1/auth/sso/login")
        assert response.status_code == 503 and not real_login.handles and not real_login.provider.called
    finally:
        await unavailable.aclose()
