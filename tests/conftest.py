import pytest
from cryptography.fernet import Fernet

from shadai.config import get_config


@pytest.fixture(autouse=True)
def safe_config(monkeypatch, request):
    if request.node.get_closest_marker("integration"):
        yield
        return
    monkeypatch.setenv("JWT_SECRET", "test-jwt-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    monkeypatch.setenv("AGENT_API_KEY", "test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("SHADAI_TENANT_ID", "test-org")
    monkeypatch.setenv("CORS_ORIGINS", '["https://example.test"]')
    for name in ("JWT_SECRET_FILE", "ENCRYPTION_KEY_FILE", "AGENT_API_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OIDC_ENABLED", "false")
    monkeypatch.setenv("SCIM_ENABLED", "false")
    for name in ("OIDC_CLIENT_SECRET_FILE", "SCIM_BEARER_TOKEN_FILE", "SCIM_GROUP_ROLE_MAP"):
        monkeypatch.delenv(name, raising=False)
    get_config.cache_clear()
    yield
    get_config.cache_clear()


@pytest.fixture
def identity_config(monkeypatch, safe_config):
    """Valid identity settings without any external network or tenant."""
    monkeypatch.setenv("OIDC_ENABLED", "true")
    monkeypatch.setenv("OIDC_ISSUER", "https://idp.example.test/tenant/v2.0")
    monkeypatch.setenv("OIDC_CLIENT_ID", "console-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-idp-client-secret-0123456789-ABCDEF")
    monkeypatch.setenv("OIDC_PUBLIC_BASE_URL", "https://console.example.test")
    monkeypatch.setenv("OIDC_ALLOW_INSECURE_LOCALHOST", "false")
    monkeypatch.setenv("OIDC_IDENTITY_CLAIM", "sub")
    monkeypatch.setenv("SCIM_ENABLED", "true")
    monkeypatch.setenv("SCIM_BEARER_TOKEN", "test-provisioning-secret-0123456789-ABCDEF")
    monkeypatch.setenv("SCIM_GROUP_ROLE_MAP", '{"admins-group":"admin","analysts-group":"analyst"}')
    get_config.cache_clear()
    return get_config()


@pytest.fixture
async def identity_sessions(tmp_path, monkeypatch):
    """Real transactions locally; live integration separately verifies PostgreSQL locks."""
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.ext.compiler import compiles

    from shadai.models.audit import AuditLogORM
    from shadai.models.base import Base
    from shadai.models.identity import GroupORM, MembershipORM
    from shadai.models.user import UserORM
    from shadai.security.scim import SCIMService

    @compiles(JSONB, "sqlite")
    def jsonb_sqlite(element, compiler, **kwargs):
        return "JSON"

    async def no_pg_lock(self):
        pass

    monkeypatch.setattr(SCIMService, "lock", no_pg_lock)
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "identity.db"))
    async with engine.begin() as connection:
        await connection.run_sync(
            lambda conn: Base.metadata.create_all(
                conn, tables=[UserORM.__table__, GroupORM.__table__, MembershipORM.__table__, AuditLogORM.__table__]
            )
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()
