import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Lock
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from starlette.requests import Request
from starlette.responses import Response
from test_evidence_privacy import evidence_sessions as evidence_sessions
from test_evidence_privacy import installation, version_change

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


async def test_purge_expires_installations_outside_the_identity_window_or_under_a_stale_basis(
    evidence_sessions, monkeypatch
):
    """Inventory rows and version history age with the identity window; a rotated key forgets them."""
    from shadai.config import get_config
    from shadai.models.extension_inventory import ExtensionInventoryORM, ExtensionVersionChangeORM
    from shadai.utils.privacy import membership_basis
    from shadai.workers.purge import purge_once

    config = get_config().model_copy(deep=True)
    config.retention.identity_days = 7
    now = datetime(2026, 10, 6, 12, tzinfo=UTC)
    cutoff = now - timedelta(days=7)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr("shadai.workers.purge.datetime", Clock)
    basis = membership_basis(config)
    current = installation(key="c" * 64, now=now, identity_basis=basis)
    edge = installation(
        key="e" * 64, now=now, identity_basis=basis, first_seen_at=cutoff - timedelta(days=2), last_seen_at=cutoff
    )
    expired = installation(
        key="x" * 64,
        now=now,
        identity_basis=basis,
        first_seen_at=cutoff - timedelta(days=2),
        last_seen_at=cutoff - timedelta(microseconds=1),
    )
    rotated = installation(key="r" * 64, now=now, identity_basis="0" * 64)
    async with evidence_sessions.begin() as session:
        session.add_all([current, edge, expired, rotated])
        await session.flush()
        session.add_all(
            [
                # History older than the window expires while its installation is still reported.
                version_change(
                    current,
                    observed_at=cutoff - timedelta(microseconds=1),
                    previous_observed_at=cutoff - timedelta(days=1),
                ),
                version_change(current, observed_at=cutoff, previous_observed_at=cutoff - timedelta(days=1)),
                version_change(edge),
                version_change(expired),
                # A change observed today still goes with a row whose digests were keyed under another key.
                version_change(rotated),
            ]
        )
    statements = []
    await purge_once(config, evidence_sessions, SimpleNamespace(execute=lambda query, *args: statements.append(query)))
    assert len(statements) == 2 and all(statement.startswith("ALTER TABLE events") for statement in statements)
    async with evidence_sessions() as session:
        keys = await session.scalars(
            select(ExtensionInventoryORM.inventory_key).order_by(ExtensionInventoryORM.inventory_key)
        )
        assert keys.all() == ["c" * 64, "e" * 64]
        changes = await session.scalars(
            select(ExtensionVersionChangeORM).order_by(ExtensionVersionChangeORM.inventory_key)
        )
        assert [(change.inventory_key, change.observed_at.replace(tzinfo=UTC)) for change in changes] == [
            ("c" * 64, cutoff),
            ("e" * 64, cutoff),
        ]


async def test_logout_revokes_exact_token_until_expiry(monkeypatch):
    from shadai.api.auth import logout
    from shadai.security.auth import create_access_token, decode_access_token

    user = SimpleNamespace(user_id=uuid4(), username="alice")
    token = create_access_token(str(user.user_id), "viewer")
    redis = AsyncMock()
    monkeypatch.setattr("shadai.api.auth.get_redis", AsyncMock(return_value=redis))
    monkeypatch.setattr("shadai.api.auth.log_audit", AsyncMock())
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/logout",
            "headers": [(b"authorization", f"Bearer {token}".encode()), (b"host", b"console.example.test")],
            "client": ("127.0.0.1", 123),
        }
    )
    response = Response()
    await logout(request, response, token, user, AsyncMock())
    assert redis.set.call_args.args == (f"revoked:{decode_access_token(token).jti}", "1")
    assert 0 < redis.set.call_args.kwargs["ex"] <= 24 * 3600
    cookie = response.headers["set-cookie"]
    assert cookie.startswith('__Host-shadai-session=""') and "Max-Age=0" in cookie and "Secure" in cookie


def test_clickhouse_tls_is_verified_and_configurable(monkeypatch):
    from shadai.config import load_config
    from shadai.database import init_clickhouse

    plain = init_clickhouse(DatabaseSettings()).connection
    assert list(plain.hosts) == [("clickhouse", 9000)] and not plain.secure_socket
    settings = DatabaseSettings(
        clickhouse_secure=True,
        clickhouse_ca_certs="/run/secrets/clickhouse-ca.pem",
        clickhouse_certfile="/run/secrets/client.pem",
        clickhouse_keyfile="/run/secrets/client.key",
        clickhouse_server_hostname="clickhouse.internal.example",
    )
    secure = init_clickhouse(settings).connection
    assert list(secure.hosts) == [("clickhouse", 9440)]
    assert secure.secure_socket and secure.verify_cert and secure.check_hostname
    assert secure.server_hostname == "clickhouse.internal.example"
    assert secure.ssl_options == {
        "ca_certs": "/run/secrets/clickhouse-ca.pem",
        "certfile": "/run/secrets/client.pem",
        "keyfile": "/run/secrets/client.key",
    }
    assert list(init_clickhouse(settings.model_copy(update={"clickhouse_port": 19440})).connection.hosts) == [
        ("clickhouse", 19440)
    ]
    monkeypatch.setattr("shadai.database._ch_client", None)

    monkeypatch.setenv("CLICKHOUSE_SECURE", "true")
    monkeypatch.setenv("CLICKHOUSE_CA_CERTS", "/run/secrets/clickhouse-ca.pem")
    config = load_config("/nonexistent.yaml")
    assert config.database.clickhouse_secure and config.database.clickhouse_effective_port == 9440
    assert config.database.clickhouse_ca_certs == "/run/secrets/clickhouse-ca.pem"
    monkeypatch.setenv("CLICKHOUSE_SECURE", "false")
    with pytest.raises(ValueError, match="require clickhouse_secure"):
        load_config("/nonexistent.yaml")
    with pytest.raises(ValueError, match="requires clickhouse_certfile"):
        DatabaseSettings(clickhouse_secure=True, clickhouse_keyfile="/run/secrets/client.key")
