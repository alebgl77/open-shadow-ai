import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Lock
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from shadai.api.ingestion import prepare_event
from shadai.config import DatabaseSettings, RetentionSettings
from shadai.models.event import CanonicalEvent


def test_receipt_horizon_and_old_event_rejection():
    with pytest.raises(ValidationError):
        RetentionSettings(ingestion_max_age_days=90, events_days=90, receipt_days=180)
    with pytest.raises(ValueError, match="retention window"):
        prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=datetime.now(UTC) - timedelta(days=91)))
    with pytest.raises(ValueError, match="future"):
        prepare_event(CanonicalEvent(tenant_id="test-org", timestamp=datetime.now(UTC) + timedelta(minutes=10)))


def test_clickhouse_factory_serializes_native_client(monkeypatch):
    from clickhouse_driver import Client

    from shadai.database import SerializedClickHouseClient, init_clickhouse

    state = {"active": 0, "peak": 0}
    lock = Lock()

    def execute(self, *args, **kwargs):
        with lock:
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
        time.sleep(0.01)
        with lock:
            state["active"] -= 1
        return [(1,)]

    monkeypatch.setattr(Client, "execute", execute)
    client = init_clickhouse(DatabaseSettings())
    assert isinstance(client, SerializedClickHouseClient)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: client.execute("SELECT 1"), range(8)))
    assert state["peak"] == 1 and all(result == [(1,)] for result in results)
    client.disconnect()
    monkeypatch.setattr("shadai.database._ch_client", None)


async def test_partial_startup_cleans_connections(monkeypatch):
    from shadai.main import app, lifespan

    close = AsyncMock()
    monkeypatch.setattr("shadai.main.init_postgres", AsyncMock(side_effect=RuntimeError("unavailable")))
    monkeypatch.setattr("shadai.main.close_all", close)
    with pytest.raises(RuntimeError):
        async with lifespan(app):
            pass
    close.assert_awaited_once()


async def test_disabled_purge_touches_nothing():
    from shadai.config import get_config
    from shadai.workers.purge import purge_once

    config = get_config().model_copy(deep=True)
    config.retention.purge_enabled = False
    sessions = SimpleNamespace(begin=lambda: pytest.fail("unexpected database mutation"))
    ch = SimpleNamespace(execute=lambda *a: pytest.fail("unexpected ClickHouse mutation"))
    await purge_once(config, sessions, ch)


async def test_logout_revokes_exact_token_until_expiry(monkeypatch):
    from shadai.api.auth import logout
    from shadai.security.auth import create_access_token, decode_access_token

    user = SimpleNamespace(user_id=uuid4(), username="alice")
    token = create_access_token(str(user.user_id), "viewer")
    redis = AsyncMock()
    monkeypatch.setattr("shadai.api.auth.get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.api.auth.log_audit", AsyncMock())
    request = Request(
        {"type": "http", "headers": [(b"authorization", f"Bearer {token}".encode())], "client": ("127.0.0.1", 123)}
    )
    await logout(request, user, AsyncMock())
    assert redis.set.call_args.args == (f"revoked:{decode_access_token(token).jti}", "1")
    assert 0 < redis.set.call_args.kwargs["ex"] <= 24 * 3600
