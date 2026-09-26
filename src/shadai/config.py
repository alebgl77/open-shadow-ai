"""Configuration loading from YAML with environment variable overrides."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class ServerSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8443
    debug: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = Field(default_factory=list)

    @field_validator("cors_origins")
    @classmethod
    def exact_origins(cls, origins):
        from urllib.parse import urlsplit

        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"https", "http"}
                or not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or "*" in origin
            ):
                raise ValueError("CORS origins must be exact http(s) origins without paths")
        return origins


class DatabaseSettings(BaseModel):
    postgres_url: str = "postgresql+asyncpg://shadai:changeme@postgres:5432/shadai"
    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 9000
    clickhouse_database: str = "shadai"
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    redis_url: str = "redis://redis:6379/0"


class SecuritySettings(BaseModel):
    jwt_secret: str = "CHANGE_ME_IMMEDIATELY"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = Field(default=24, ge=1, le=168)
    encryption_key: str = "CHANGE_ME_IMMEDIATELY"
    agent_api_key: str = ""


class RetentionSettings(BaseModel):
    events_days: int = Field(default=90, ge=1, le=365)
    ingestion_max_age_days: int = Field(default=90, ge=1, le=365)
    receipt_days: int = Field(default=181, ge=1, le=1096)
    detections_days: int = Field(default=365, ge=1, le=3650)
    audit_logs_days: int = Field(default=365, ge=1, le=3650)
    purge_enabled: bool = True
    purge_schedule: str = "0 3 * * *"

    @model_validator(mode="after")
    def receipt_horizon(self):
        if self.receipt_days < self.ingestion_max_age_days + self.events_days + 1:
            raise ValueError("receipt_days must exceed ingestion_max_age_days + events_days")
        return self


class CatalogSettings(BaseModel):
    builtin_path: str = "/app/catalog/builtin"
    local_path: str = "/app/catalog/local"
    reload_interval_seconds: int = Field(default=60, ge=1, le=3600)


class PrivacySettings(BaseModel):
    strip_query_params: bool = True
    no_url_path_retention: bool = False


class ShadAIConfig(BaseModel):
    tenant_id: str = Field(default="default", min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    server: ServerSettings = ServerSettings()
    database: DatabaseSettings = DatabaseSettings()
    security: SecuritySettings = SecuritySettings()
    retention: RetentionSettings = RetentionSettings()
    catalog: CatalogSettings = CatalogSettings()
    privacy: PrivacySettings = PrivacySettings()


def _read_secret_file(path: str) -> str:
    """Read a Docker secret file, stripping trailing whitespace."""
    return Path(path).read_text().strip()


def _apply_env_overrides(config: ShadAIConfig) -> ShadAIConfig:
    """Override config values with environment variables and Docker secrets."""
    if url := os.environ.get("DATABASE_URL"):
        config.database.postgres_url = url
    if host := os.environ.get("CLICKHOUSE_HOST"):
        config.database.clickhouse_host = host
    if port := os.environ.get("CLICKHOUSE_PORT"):
        config.database.clickhouse_port = int(port)
    if db := os.environ.get("CLICKHOUSE_DATABASE"):
        config.database.clickhouse_database = db
    if url := os.environ.get("REDIS_URL"):
        config.database.redis_url = url
    if tenant := os.environ.get("SHADAI_TENANT_ID"):
        config.tenant_id = tenant
    if origins := os.environ.get("CORS_ORIGINS"):
        config.server.cors_origins = json.loads(origins)
    if path := os.environ.get("AGENT_API_KEY_FILE"):
        config.security.agent_api_key = _read_secret_file(path)
    elif key := os.environ.get("AGENT_API_KEY"):
        config.security.agent_api_key = key
    if user := os.environ.get("CLICKHOUSE_USER"):
        config.database.clickhouse_user = user
    if path := os.environ.get("CLICKHOUSE_PASSWORD_FILE"):
        config.database.clickhouse_password = _read_secret_file(path)
    elif password := os.environ.get("CLICKHOUSE_PASSWORD"):
        config.database.clickhouse_password = password

    # JWT secret: file takes priority, then env var
    if path := os.environ.get("JWT_SECRET_FILE"):
        config.security.jwt_secret = _read_secret_file(path)
    elif secret := os.environ.get("JWT_SECRET"):
        config.security.jwt_secret = secret

    # Encryption key: file takes priority, then env var
    if path := os.environ.get("ENCRYPTION_KEY_FILE"):
        config.security.encryption_key = _read_secret_file(path)
    elif key := os.environ.get("ENCRYPTION_KEY"):
        config.security.encryption_key = key

    return ShadAIConfig.model_validate(config.model_dump())


def validate_security(config: ShadAIConfig) -> None:
    """Fail closed in every runtime, including debug; tests inject valid configuration."""
    from cryptography.fernet import Fernet

    for name in ("jwt_secret", "agent_api_key"):
        value = getattr(config.security, name)
        if len(value.encode()) < 32 or len(set(value)) < 12 or "change_me" in value.lower():
            raise ValueError(f"{name} must be a randomly generated secret of at least 32 bytes")
    if config.security.jwt_algorithm != "HS256":
        raise ValueError("Only HS256 is supported")
    Fernet(config.security.encryption_key.encode())


def load_config(path: str | None = None) -> ShadAIConfig:
    """Load configuration from YAML file with env var overrides."""
    config_path = path or os.environ.get("SHADAI_CONFIG", "/app/config/shadai.yaml")

    if Path(config_path).exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
        config = ShadAIConfig(**raw)
    else:
        config = ShadAIConfig()

    return _apply_env_overrides(config)


@lru_cache
def get_config() -> ShadAIConfig:
    """Return cached global configuration singleton."""
    return load_config()
