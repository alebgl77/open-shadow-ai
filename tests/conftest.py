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
    get_config.cache_clear()
    yield
    get_config.cache_clear()
