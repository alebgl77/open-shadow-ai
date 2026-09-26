from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from shadai.api.agent import TelemetryBatch, _validate_api_key
from shadai.api.ingestion import EventBatch, InputEvent, prepare_event
from shadai.config import ServerSettings, get_config, validate_security
from shadai.models.event import CanonicalEvent
from shadai.models.user import UserCreate, UserUpdate
from shadai.security.auth import (
    create_access_token,
    decode_access_token,
    get_current_user,
    hash_password,
    verify_password,
)


def test_secrets_fail_closed_even_debug():
    config = get_config().model_copy(deep=True)
    validate_security(config)
    config.server.debug = True
    config.security.jwt_secret = "x" * 64
    with pytest.raises(ValueError):
        validate_security(config)


@pytest.mark.parametrize(
    "origin", ["*", "https://*.example.com", "https://example.com/path", "https://u:p@example.com", "null"]
)
def test_exact_cors(origin):
    with pytest.raises(ValidationError):
        ServerSettings(cors_origins=[origin])


def test_jwt_requires_organization_and_valid_claims():
    token = create_access_token(str(uuid4()), "viewer")
    assert decode_access_token(token).tenant_id == "test-org"
    config = get_config()
    body = jwt.decode(token, options={"verify_signature": False})
    for mutation in ({"tenant_id": "elsewhere"}, {"sub": "not-a-uuid"}, {"jti": None}):
        forged = jwt.encode({**body, **mutation}, config.security.jwt_secret, algorithm="HS256")
        with pytest.raises(HTTPException) as error:
            decode_access_token(forged)
        assert error.value.status_code == 401


async def test_revoked_token_never_queries_user(monkeypatch):
    token = create_access_token(str(uuid4()), "viewer")
    redis = AsyncMock()
    redis.exists.return_value = 1
    monkeypatch.setattr("shadai.security.auth.get_redis", AsyncMock(return_value=redis))
    session = AsyncMock()
    with pytest.raises(HTTPException):
        await get_current_user(token, session)
    session.execute.assert_not_called()


def test_key_validation_and_roles():
    assert _validate_api_key(get_config().security.agent_api_key)
    for key in ("", "wrong", "é" * 64):
        with pytest.raises(HTTPException):
            _validate_api_key(key)
    for role in ("owner", "superadmin", ""):
        with pytest.raises(ValidationError):
            UserUpdate(role=role)
    for password in ("short", "é" * 40):
        with pytest.raises(ValidationError):
            UserCreate(username="admin", password=password)
    assert not verify_password("é" * 40, hash_password("valid-password12"))


def test_tenant_and_sensitive_fields():
    event = InputEvent(
        event_id=uuid4(),
        timestamp=datetime.now(UTC),
        collector_id="test",
        source_type="proxy",
        url_path="/prompt?api_key=secret",
        process_path="/secret",
    )
    prepared = prepare_event(event)
    assert prepared.tenant_id == "test-org"
    assert prepared.url_path == prepared.process_path == ""
    event.tenant_id = "foreign"
    with pytest.raises(ValueError):
        prepare_event(event)
    with pytest.raises(ValidationError):
        CanonicalEvent(prompt="sensitive")
    with pytest.raises(ValueError):
        prepare_event(CanonicalEvent(tenant_id="test-org", domain="example.com/?key=secret"))


@pytest.mark.parametrize(
    "fields",
    [
        {"source_type": "dns", "model": "gpt", "model_provenance": "reported"},
        {"source_type": "dns", "evidence_type": "usage"},
        {"source_type": "directory", "evidence_type": "usage"},
        {"source_type": "instrumented", "model": "gpt"},
        {"input_tokens": 12},
        {"cost_usd": float("nan")},
        {"dst_port": 65536},
        {"timestamp": datetime(2026, 1, 1)},
        {"bytes_out": -1},
    ],
)
def test_truthful_evidence_and_bounds(fields):
    with pytest.raises(ValidationError):
        CanonicalEvent(**fields)


def test_measurement_unknown_stays_null():
    event = CanonicalEvent()
    assert event.input_tokens is None and event.cost_usd is None and event.model == ""
    measured = CanonicalEvent(
        source_type="instrumented", evidence_type="usage", input_tokens=0, measurement_provenance="instrumented"
    )
    assert measured.input_tokens == 0
    with pytest.raises(ValidationError):
        EventBatch(events=[])
    with pytest.raises(ValidationError):
        TelemetryBatch(hostname="a", timestamp="2026-01-01T00:00:00Z", processes=[{"name": {"bad": "value"}}])


def test_api_auth_cors_size_and_error_redaction():
    from shadai.main import app

    client = TestClient(app)
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    assert client.post("/api/v1/ingest/events", json={"events": []}).status_code == 401
    response = client.post("/api/v1/ingest/events", content=b"x" * (2 * 1024 * 1024 + 1))
    assert response.status_code == 413
    response = client.options(
        "/api/v1/ingest/events", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "POST"}
    )
    assert "access-control-allow-origin" not in response.headers
    from shadai.database import get_postgres_session

    async def no_database():
        yield AsyncMock()

    app.dependency_overrides[get_postgres_session] = no_database
    try:
        response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "secret" * 100})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 422 and "secretsecret" not in response.text


@pytest.mark.parametrize(
    "mutation,algorithm,key",
    [
        ({"exp": 1}, "HS256", None),
        ({}, "none", ""),
        ({}, "HS384", None),
    ],
)
def test_expired_or_disallowed_jwt_algorithm(mutation, algorithm, key):
    config = get_config()
    body = jwt.decode(create_access_token(str(uuid4()), "viewer"), options={"verify_signature": False})
    token = jwt.encode({**body, **mutation}, config.security.jwt_secret if key is None else key, algorithm=algorithm)
    with pytest.raises(HTTPException) as error:
        decode_access_token(token)
    assert error.value.status_code == 401


def test_canonical_ingestion_authenticates_missing_empty_wrong_and_valid_keys(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from shadai.main import app

    pipe = SimpleNamespace(xadd=Mock(), execute=AsyncMock())
    redis = SimpleNamespace(pipeline=Mock(return_value=pipe))
    get_redis = AsyncMock(return_value=redis)
    monkeypatch.setattr("shadai.api.ingestion.get_redis", get_redis)
    client = TestClient(app)
    timestamp = datetime.now(UTC).isoformat()
    payload = {
        "events": [
            {
                "event_id": str(uuid4()),
                "timestamp": timestamp,
                "source_type": "dns",
                "collector_id": "ci-dns",
                "domain": "chatgpt.com",
                "src_ip": "192.0.2.10",
            },
            {
                "event_id": str(uuid4()),
                "timestamp": timestamp,
                "source_type": "directory",
                "evidence_type": "inventory",
                "collector_id": "ci-ad",
                "identity_provider": "active_directory",
                "identity_object_id": str(uuid4()),
                "device_id": "ci-device",
                "hostname": "ci.example.test",
            },
        ]
    }
    for headers in ({}, {"X-API-Key": ""}, {"X-API-Key": "incorrect"}):
        response = client.post("/api/v1/ingest/events", json=payload, headers=headers)
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid API key"}
    get_redis.assert_not_awaited()
    pipe.xadd.assert_not_called()
    headers = {"X-API-Key": get_config().security.agent_api_key}
    response = client.post("/api/v1/ingest/events", json=payload, headers=headers)
    assert response.status_code == 202
    assert response.json() == {"received": 2, "tenant_id": "test-org"}
    get_redis.assert_awaited_once()
    pipe.execute.assert_awaited_once()
    assert [call.args[0] for call in pipe.xadd.call_args_list] == ["events:dns", "events:directory"]
    assert client.get("/api/v1/agent/config").status_code == 401
    assert client.get("/api/v1/agent/config", headers=headers).status_code == 200
