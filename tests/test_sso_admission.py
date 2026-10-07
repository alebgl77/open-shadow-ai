"""Admission and login lifecycle contracts; real Lua is exercised separately."""

import asyncio
import copy
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from starlette.requests import Request

from shadai.api import sso
from shadai.config import OIDCSettings, RedisQueueSettings, ShadAIConfig, _apply_env_overrides
from shadai.security.oidc import OIDCClient, OIDCError, consume_bound, digest, store_bound
from shadai.security.sso_admission import (
    ADMIT,
    AdmissionDeniedError,
    AdmissionUnavailableError,
    SSOAdmission,
    normalized_peer,
)


class AdmissionRedis:
    """Atomic event-loop model, deliberately separate from the production Lua."""

    def __init__(self):
        self.now = 0
        self.hashes, self.leases, self.expirations, self.values = {}, {}, {}, {}
        self.admissions = self.releases = self.stores = 0
        self.failure = None

    async def eval(self, script, count, *args):
        if self.failure:
            raise self.failure
        if count == 1:
            key, binding = args
            entry = self.values.get(key)
            if not entry or entry[1] <= self.now:
                self.values.pop(key, None)
                return None
            if json.loads(entry[0])["binding"] != binding:
                return None
            self.values.pop(key)
            return entry[0]
        assert script == ADMIT and count == 3
        self.admissions += 1
        meta_key, peers_key, leases_key, peer, token, peer_limit, total_limit, concurrency, lease_ms = args
        meta = self.hashes.get(meta_key, {})
        peers = self.hashes.get(peers_key, {})
        leases = self.leases.get(leases_key, {})
        bucket, now_ms = int(self.now // 60), int(self.now * 1000)
        rollover = meta.get("bucket") != bucket
        total = 0 if rollover else meta.get("count", 0)
        peer_count = 0 if rollover else peers.get(peer, 0)
        if total >= total_limit or peer_count >= peer_limit:
            return [1, max(1, int(60 - self.now % 60))]
        live = [expiry for expiry in leases.values() if expiry >= now_ms]
        if len(live) >= concurrency:
            return [2, max(1, min(60, int((min(live) - now_ms + 999) // 1000)))]
        self.hashes[meta_key] = {"bucket": bucket, "count": total + 1}
        if rollover:
            peers = {}
        self.hashes[peers_key] = {**peers, peer: peer_count + 1}
        self.expirations[meta_key] = self.expirations[peers_key] = self.now + 120
        self.leases[leases_key] = {owned: expiry for owned, expiry in leases.items() if expiry > now_ms}
        self.leases[leases_key][token] = now_ms + lease_ms
        self.expirations[leases_key] = self.now + lease_ms / 1000 + 1
        return [0, 0]

    async def zrem(self, key, token):
        self.releases += 1
        if self.failure:
            raise self.failure
        return self.leases.get(key, {}).pop(token, None) is not None

    async def set(self, key, value, *, ex, nx):
        self.stores += 1
        if self.failure:
            raise self.failure
        if key in self.values and self.values[key][1] > self.now:
            return None
        self.values[key] = value, self.now + ex
        return True


def socket_request(host="192.0.2.1", headers=()):
    return Request({"type": "http", "client": (host, 1234) if host is not None else None, "headers": headers})


@pytest.mark.parametrize("host, expected", [
    ("2001:0db8:0000::1", "2001:db8::1"), ("192.0.2.1", "192.0.2.1"),
    ("bad-peer", "unknown"), (None, "unknown"), ("fe80::1%interface", "unknown"),
])
def test_peer_uses_normalized_socket_only(host, expected):
    assert normalized_peer(socket_request(host, [(b"forwarded", b"for=203.0.113.10")])) == expected
    assert normalized_peer(socket_request(host, [(b"x-forwarded-for", b"203.0.113.10")])) == expected


@pytest.mark.parametrize("field, value", [
    ("login_peer_limit", 0), ("login_peer_limit", 1001), ("login_installation_limit", 0),
    ("login_installation_limit", 10001), ("login_installation_limit", 9),
    ("login_concurrency", 0), ("login_concurrency", 65), ("login_timeout_seconds", 0),
    ("login_timeout_seconds", 31), ("login_lease_seconds", 14), ("login_lease_seconds", 61),
])
def test_oidc_admission_settings_reject_invalid_bounds(field, value):
    with pytest.raises(ValidationError):
        OIDCSettings(**{field: value})


@pytest.mark.parametrize("field, low, high", [
    ("stream_max_entries", 1, 10000000), ("dlq_max_entries", 1, 20000),
    ("retained_days", 1, 365), ("admission_max_batch_bytes", 1, 16777216),
])
def test_queue_settings_bounds(field, low, high):
    for value in (low - 1, high + 1):
        with pytest.raises(ValidationError):
            RedisQueueSettings(**{field: value})
    assert getattr(RedisQueueSettings(**{field: low}), field) == low
    assert getattr(RedisQueueSettings(**{field: high}), field) == high


def test_admission_environment_and_secret_repr(monkeypatch):
    settings = {
        "OIDC_LOGIN_PEER_LIMIT": "20", "OIDC_LOGIN_INSTALLATION_LIMIT": "200",
        "OIDC_LOGIN_CONCURRENCY": "6", "OIDC_LOGIN_TIMEOUT_SECONDS": "20", "OIDC_LOGIN_LEASE_SECONDS": "23",
        "REDIS_STREAM_MAX_ENTRIES": "1234", "REDIS_DLQ_MAX_ENTRIES": "100",
        "REDIS_RETAINED_DAYS": "10", "REDIS_ADMISSION_MAX_BATCH_BYTES": "3000",
    }
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    config = _apply_env_overrides(ShadAIConfig())
    assert (config.oidc.login_peer_limit, config.oidc.login_installation_limit, config.oidc.login_concurrency,
            config.oidc.login_timeout_seconds, config.oidc.login_lease_seconds) == (20, 200, 6, 20, 23)
    assert config.redis_queue.model_dump() == {
        "stream_max_entries": 1234, "dlq_max_entries": 100, "retained_days": 10, "admission_max_batch_bytes": 3000,
    }
    assert "private-test-secret" not in repr(OIDCSettings(client_secret="private-test-secret"))


@pytest.mark.parametrize("multiple_peers", [False, True])
async def test_two_instances_exact_quota_and_denial_no_allocation(multiple_peers):
    redis = AdmissionRedis()
    cfg = OIDCSettings(login_installation_limit=20)
    instances = [SSOAdmission(redis, "synthetic", cfg), SSOAdmission(redis, "synthetic", cfg)]

    async def attempt(index):
        admission = instances[index % 2]
        peer = f"192.0.2.{index + 1}" if multiple_peers else "192.0.2.1"
        before = copy.deepcopy((redis.hashes, redis.leases))
        token = admission.token()
        try:
            await admission.admit(peer, token)
        except AdmissionDeniedError:
            assert (redis.hashes, redis.leases) == before
            return False
        await admission.release(token)
        return True

    outcomes = await asyncio.gather(*(attempt(index) for index in range(50)))
    expected = 20 if multiple_peers else 10
    assert sum(outcomes) == expected
    assert redis.hashes[instances[0].keys[0]]["count"] == expected
    assert len(redis.hashes[instances[0].keys[1]]) <= expected
    assert not redis.leases[instances[0].keys[2]]


async def test_two_instances_live_leases_stale_expiry_and_rollover():
    redis = AdmissionRedis()
    instances = [SSOAdmission(redis, "synthetic", OIDCSettings()) for _ in range(2)]

    async def attempt(index):
        admission = instances[index % 2]
        token = admission.token()
        try:
            await admission.admit(f"192.0.2.{index + 1}", token)
            return token
        except AdmissionDeniedError:
            return None

    tokens = await asyncio.gather(*(attempt(index) for index in range(50)))
    assert sum(token is not None for token in tokens) == 4
    assert redis.hashes[instances[0].keys[0]]["count"] == 4
    assert len(redis.leases[instances[0].keys[2]]) == 4
    redis.now = 16
    assert await attempt(50)
    assert len(redis.leases[instances[0].keys[2]]) == 1
    redis.now = 61
    assert await attempt(51)
    assert redis.hashes[instances[0].keys[0]]["count"] == 1
    assert len(redis.hashes[instances[0].keys[1]]) == 1
    assert all(expiry > redis.now for expiry in redis.expirations.values())


@pytest.mark.parametrize("result", [[-1, 0], [0], None, [1, 0], [2, 61], [9, 0], [False, 0]])
async def test_invalid_admission_response_fails_closed(result):
    admission = SSOAdmission(SimpleNamespace(eval=AsyncMock(return_value=result)), "synthetic", OIDCSettings())
    with pytest.raises(AdmissionUnavailableError):
        await admission.admit("192.0.2.1", admission.token())


@pytest.fixture
async def login_flow(identity_config, monkeypatch):
    redis = AdmissionRedis()
    provider = AsyncMock(return_value="https://idp.example.test/authorize?synthetic=1")
    monkeypatch.setattr(sso, "get_config", lambda: identity_config)
    monkeypatch.setattr(sso, "get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr(sso, "OIDCClient", lambda config: SimpleNamespace(authorization_url=provider))
    app = FastAPI()
    app.include_router(sso.router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://console.example.test"
    ) as client:
        yield SimpleNamespace(redis=redis, provider=provider, client=client, config=identity_config)


async def test_http_quota_precedes_state_provider_and_forwarded_spoof(login_flow):
    for index in range(50):
        before = copy.deepcopy((login_flow.redis.hashes, login_flow.redis.leases, login_flow.redis.values))
        response = await login_flow.client.get("/api/v1/auth/sso/login", headers={
            "X-Forwarded-For": f"203.0.113.{index + 1}", "Forwarded": f"for=203.0.113.{index + 1}",
        })
        assert response.status_code == (303 if index < 10 else 429)
        if index >= 10:
            assert (login_flow.redis.hashes, login_flow.redis.leases, login_flow.redis.values) == before
            assert 1 <= int(response.headers["retry-after"]) <= 60
            assert response.json() == {"detail": "Single sign-on could not be completed"}
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
    assert login_flow.provider.await_count == login_flow.redis.stores == 10
    [peers] = [value for key, value in login_flow.redis.hashes.items() if key.endswith(":peers")]
    assert peers == {hashlib.sha256(b"127.0.0.1").hexdigest(): 10}


async def test_http_concurrency_blocks_before_state_and_provider(login_flow):
    entered, finish = asyncio.Event(), asyncio.Event()

    async def blocked(*args):
        if login_flow.provider.await_count == 4:
            entered.set()
        await finish.wait()
        return "https://idp.example.test/authorize"

    login_flow.provider.side_effect = blocked
    tasks = [asyncio.create_task(login_flow.client.get("/api/v1/auth/sso/login")) for _ in range(50)]
    await asyncio.wait_for(entered.wait(), 1)
    assert login_flow.redis.stores == login_flow.provider.await_count == 4
    assert sum(len(leases) for leases in login_flow.redis.leases.values()) == 4
    finish.set()
    responses = await asyncio.gather(*tasks)
    assert [response.status_code for response in responses].count(303) == 4
    assert [response.status_code for response in responses].count(429) == 46
    assert not any(login_flow.redis.leases.values())


@pytest.mark.parametrize("failure", [RedisConnectionError("private-details"), ResponseError("OOM private-details"),
                                     AdmissionUnavailableError()])
async def test_redis_failure_is_generic_503_before_state_provider(login_flow, failure):
    login_flow.redis.failure = failure
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 503 and "private-details" not in response.text
    assert not login_flow.redis.values and login_flow.redis.stores == 0
    assert not login_flow.provider.called


async def test_disabled_login_never_touches_redis(login_flow, monkeypatch):
    login_flow.config.oidc.enabled = False
    getter = AsyncMock(side_effect=AssertionError("Redis must not be called"))
    monkeypatch.setattr(sso, "get_redis", getter)
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 404 and not getter.called and not login_flow.provider.called


@pytest.mark.parametrize("failure", [OIDCError(), RedisConnectionError("private-details"), RuntimeError("synthetic")])
async def test_failed_provider_cleans_only_owned_state_and_lease(login_flow, failure):
    foreign_binding = "foreign-browser-binding-value-123456"
    foreign = await store_bound(login_flow.redis, "state", {"nonce": "foreign"}, foreign_binding, 300)
    foreign_key = "oidc:state:" + digest(foreign)
    foreign_entry = login_flow.redis.values[foreign_key]
    login_flow.provider.side_effect = failure
    if isinstance(failure, RuntimeError):
        with pytest.raises(RuntimeError, match="synthetic"):
            await login_flow.client.get("/api/v1/auth/sso/login")
    else:
        response = await login_flow.client.get("/api/v1/auth/sso/login")
        assert response.status_code == (503 if isinstance(failure, RedisConnectionError) else 303)
        assert "private-details" not in response.text
    assert login_flow.redis.values == {foreign_key: foreign_entry}
    assert not any(login_flow.redis.leases.values())
    with pytest.raises(OIDCError):
        await consume_bound(login_flow.redis, "state", foreign, "wrong-browser-binding-value-123456")
    assert login_flow.redis.values[foreign_key] == foreign_entry


async def test_provider_total_deadline_and_cancel_release_owned_resources(login_flow):
    login_flow.config.oidc.login_timeout_seconds = 1
    started = asyncio.Event()

    async def slow(*args):
        started.set()
        # Individual chunks make progress; only the total deadline stops the call.
        while True:
            await asyncio.sleep(0.1)

    login_flow.provider.side_effect = slow
    begin = time.monotonic()
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303 and response.headers["location"].endswith("/login?sso_error=failed")
    assert time.monotonic() - begin < 1.5
    assert not login_flow.redis.values and not any(login_flow.redis.leases.values())
    started.clear()
    task = asyncio.create_task(login_flow.client.get("/api/v1/auth/sso/login"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not login_flow.redis.values and not any(login_flow.redis.leases.values())


async def test_admission_time_consumes_the_same_deadline(login_flow, monkeypatch):
    login_flow.config.oidc.login_timeout_seconds = 1
    original = login_flow.redis.eval

    async def slow_admit(*args):
        if args[1] == 3:
            await asyncio.sleep(0.65)
        return await original(*args)

    monkeypatch.setattr(login_flow.redis, "eval", slow_admit)
    async def slow_provider(*args):
        await asyncio.sleep(10)
    login_flow.provider.side_effect = slow_provider
    started = time.monotonic()
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303 and time.monotonic() - started < 1.5
    assert not login_flow.redis.values and not any(login_flow.redis.leases.values())


async def test_hanging_redis_admission_times_out_without_state_provider(login_flow, monkeypatch):
    login_flow.config.oidc.login_timeout_seconds = 1
    async def hanging(*args):
        await asyncio.sleep(10)
    monkeypatch.setattr(login_flow.redis, "eval", hanging)
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 503 and not login_flow.redis.values and not login_flow.provider.called


async def test_lost_admission_reply_releases_owned_token(login_flow, monkeypatch):
    original = login_flow.redis.eval
    async def lost_reply(*args):
        await original(*args)
        raise RedisConnectionError("synthetic lost reply")
    monkeypatch.setattr(login_flow.redis, "eval", lost_reply)
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 503 and not any(login_flow.redis.leases.values())
    assert not login_flow.redis.values and not login_flow.provider.called


async def test_cleanup_outage_uses_state_and_lease_ttl_fallback(login_flow):
    async def offline_after_state(*args):
        login_flow.redis.failure = RedisConnectionError("synthetic cleanup outage")
        raise OIDCError()
    login_flow.provider.side_effect = offline_after_state
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303
    assert len(login_flow.redis.values) == 1 and next(iter(login_flow.redis.values.values()))[1] == 300
    assert len(next(iter(login_flow.redis.leases.values()))) == 1
    assert next(expiry for key, expiry in login_flow.redis.expirations.items() if key.endswith(":leases")) == 16


async def test_slow_drip_discovery_obeys_total_budget_and_closes_stream(login_flow, monkeypatch):
    login_flow.config.oidc.login_timeout_seconds = 1

    class Drip(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            for _ in range(30):
                await asyncio.sleep(0.1)
                yield b" "

        async def aclose(self):
            self.closed = True

    stream = Drip()
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    monkeypatch.setattr(sso, "OIDCClient", lambda config: OIDCClient(config, transport))
    started = time.monotonic()
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303 and response.headers["location"].endswith("/login?sso_error=failed")
    assert time.monotonic() - started < 1.5 and stream.closed
    assert not login_flow.redis.values and not any(login_flow.redis.leases.values())


async def test_state_store_lost_reply_uses_ttl_without_claiming_ownership(login_flow, monkeypatch):
    login_flow.config.oidc.login_timeout_seconds = 1
    original = login_flow.redis.set

    async def stored_without_reply(*args, **kwargs):
        await original(*args, **kwargs)
        await asyncio.sleep(10)

    monkeypatch.setattr(login_flow.redis, "set", stored_without_reply)
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 503 and not login_flow.provider.called
    assert len(login_flow.redis.values) == 1 and next(iter(login_flow.redis.values.values()))[1] == 300
    assert not any(login_flow.redis.leases.values())


async def test_independent_bounded_cleanup_does_not_block_lease_release(login_flow, monkeypatch):
    original = login_flow.redis.eval

    async def hanging_consume(script, key_count, *args):
        if key_count == 1:
            await asyncio.sleep(10)
        return await original(script, key_count, *args)

    monkeypatch.setattr(login_flow.redis, "eval", hanging_consume)
    login_flow.provider.side_effect = OIDCError()
    started = time.monotonic()
    response = await login_flow.client.get("/api/v1/auth/sso/login")
    assert response.status_code == 303 and time.monotonic() - started < 2.5
    assert len(login_flow.redis.values) == 1  # state expiry remains the fallback
    assert not any(login_flow.redis.leases.values())
