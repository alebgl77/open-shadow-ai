"""Configuration loading from YAML with environment variable overrides."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class ServerSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8443
    debug: bool = False
    log_level: str = "INFO"
    cors_origins: list[str] = Field(default_factory=list)
    # None: Secure session cookie except on loopback hosts (the default HTTP install).
    session_cookie_secure: bool | None = None

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
    clickhouse_port: int | None = Field(default=None, ge=1, le=65535)  # None: 9440 with TLS, else 9000
    clickhouse_database: str = "shadai"
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    # Native-protocol TLS. Certificate and hostname verification are always enforced.
    clickhouse_secure: bool = False
    clickhouse_ca_certs: str = ""  # PEM bundle for a private CA; default: certifi
    clickhouse_certfile: str = ""  # client certificate for mutual TLS
    clickhouse_keyfile: str = ""
    clickhouse_server_hostname: str = ""  # certificate name when it differs from clickhouse_host
    redis_url: str = "redis://redis:6379/0"

    @model_validator(mode="after")
    def clickhouse_tls(self):
        tls_options = (
            self.clickhouse_ca_certs,
            self.clickhouse_certfile,
            self.clickhouse_keyfile,
            self.clickhouse_server_hostname,
        )
        if any(tls_options) and not self.clickhouse_secure:
            raise ValueError("ClickHouse TLS options require clickhouse_secure")
        if self.clickhouse_keyfile and not self.clickhouse_certfile:
            raise ValueError("clickhouse_keyfile requires clickhouse_certfile")
        return self

    @property
    def clickhouse_effective_port(self) -> int:
        return self.clickhouse_port or (9440 if self.clickhouse_secure else 9000)


class SecuritySettings(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)
    jwt_secret: str = "CHANGE_ME_IMMEDIATELY"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = Field(default=24, ge=1, le=168)
    encryption_key: str = "CHANGE_ME_IMMEDIATELY"
    agent_api_key: str = ""
    metrics_api_key: SecretStr | None = None
    allow_legacy_agent_key: bool = True
    pseudonymize_identities: bool = False

    @field_validator('metrics_api_key')
    @classmethod
    def valid_metrics_key(cls, value):
        if value is not None and (len(value.get_secret_value()) < 32 or
                                  any(char.isspace() for char in value.get_secret_value())):
            raise ValueError('Metrics scrape key requires at least 32 characters without whitespace')
        return value


class RetentionSettings(BaseModel):
    events_days: int = Field(default=90, ge=1, le=365)
    identity_days: int = Field(default=30, ge=1, le=365)
    ingestion_max_age_days: int = Field(default=90, ge=1, le=365)
    receipt_days: int = Field(default=181, ge=1, le=1096)
    detections_days: int = Field(default=365, ge=1, le=3650)
    audit_logs_days: int = Field(default=365, ge=1, le=3650)
    purge_enabled: bool = True
    purge_schedule: str = "0 3 * * *"

    @model_validator(mode="before")
    @classmethod
    def compatible_identity_horizon(cls, values):
        if isinstance(values, dict) and "identity_days" not in values:
            values = {**values, "identity_days": min(30, int(values.get("events_days", 90)))}
        return values

    @model_validator(mode="after")
    def receipt_horizon(self):
        if self.identity_days > self.events_days:
            raise ValueError("identity_days must not exceed events_days")
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
    # Evaluate URL paths (never query strings) and user agents against catalog patterns at
    # the ingestion boundary, keep only the resulting catalog match, then discard them.
    match_transient_signals: bool = True


def trusted_url(value: str, allow_local: bool = False, *, origin_only: bool = False) -> str:
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("Identity URL contains whitespace or control characters")
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (parsed.scheme != "https" and not (allow_local and loopback and parsed.scheme == "http")) or not parsed.hostname:
        raise ValueError("Identity URLs require HTTPS; explicit HTTP development is limited to loopback")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or "\\" in value:
        raise ValueError("Identity URLs cannot contain credentials, query or fragment")
    if origin_only and parsed.path not in {"", "/"}:
        raise ValueError("Public base URL must be an origin")
    _ = parsed.port  # Validate malformed ports.
    return value.rstrip("/") if origin_only else value


class OIDCSettings(BaseModel):
    enabled: bool = False
    issuer: str = Field(default="", max_length=1024)
    client_id: str = Field(default="", max_length=255)
    client_secret: str = Field(default="", repr=False)
    public_base_url: str = ""
    label: str = Field(default="Organization sign-in", max_length=100)
    identity_claim: Literal["sub", "oid"] = "sub"
    allow_insecure_localhost: bool = False

    @property
    def secure_cookies(self) -> bool:
        return urlsplit(self.public_base_url).scheme == "https"

    @property
    def callback_url(self) -> str:
        return self.public_base_url + "/api/v1/auth/sso/callback"


class SCIMSettings(BaseModel):
    enabled: bool = False
    bearer_token: str = Field(default="", repr=False)
    group_role_map: dict[str, Literal["viewer", "analyst", "admin"]] = Field(default_factory=dict)


class ShadAIConfig(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)
    tenant_id: str = Field(default="default", min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    server: ServerSettings = ServerSettings()
    database: DatabaseSettings = DatabaseSettings()
    security: SecuritySettings = SecuritySettings()
    retention: RetentionSettings = RetentionSettings()
    catalog: CatalogSettings = CatalogSettings()
    privacy: PrivacySettings = PrivacySettings()
    oidc: OIDCSettings = OIDCSettings()
    scim: SCIMSettings = SCIMSettings()


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
    if path := os.environ.get('METRICS_API_KEY_FILE'):
        config.security.metrics_api_key = SecuritySettings(metrics_api_key=_read_secret_file(path)).metrics_api_key
    elif key := os.environ.get('METRICS_API_KEY'):
        config.security.metrics_api_key = SecuritySettings(metrics_api_key=key).metrics_api_key
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

    env_fields = {
        "OIDC_ENABLED": ("oidc", "enabled"),
        "OIDC_ISSUER": ("oidc", "issuer"),
        "OIDC_CLIENT_ID": ("oidc", "client_id"),
        "OIDC_PUBLIC_BASE_URL": ("oidc", "public_base_url"),
        "OIDC_LABEL": ("oidc", "label"),
        "OIDC_IDENTITY_CLAIM": ("oidc", "identity_claim"),
        "OIDC_ALLOW_INSECURE_LOCALHOST": ("oidc", "allow_insecure_localhost"),
        "SCIM_ENABLED": ("scim", "enabled"),
        "ALLOW_LEGACY_AGENT_KEY": ("security", "allow_legacy_agent_key"),
        "PSEUDONYMIZE_IDENTITIES": ("security", "pseudonymize_identities"),
        "IDENTITY_RETENTION_DAYS": ("retention", "identity_days"),
    }
    for name in ("SECURE", "CA_CERTS", "CERTFILE", "KEYFILE", "SERVER_HOSTNAME"):
        env_fields["CLICKHOUSE_" + name] = ("database", "clickhouse_" + name.lower())
    raw = config.model_dump()
    if (secure := os.environ.get("SESSION_COOKIE_SECURE")) is not None:
        raw["server"]["session_cookie_secure"] = None if secure.strip().lower() in {"", "auto"} else secure
    for name, (section, field) in env_fields.items():
        if name in os.environ:
            raw[section][field] = os.environ[name]
    for name, section, field in (
        ("OIDC_CLIENT_SECRET", "oidc", "client_secret"),
        ("SCIM_BEARER_TOKEN", "scim", "bearer_token"),
    ):
        if path := os.environ.get(name + "_FILE"):
            raw[section][field] = _read_secret_file(path)
        elif name in os.environ:
            raw[section][field] = os.environ[name]
    if role_map := os.environ.get("SCIM_GROUP_ROLE_MAP"):
        raw["scim"]["group_role_map"] = json.loads(role_map)
    return ShadAIConfig.model_validate(raw)


def validate_security(config: ShadAIConfig) -> None:
    """Fail closed in every runtime, including debug; tests inject valid configuration."""
    from cryptography.fernet import Fernet

    required_secrets = ("jwt_secret", "agent_api_key") if config.security.allow_legacy_agent_key else ("jwt_secret",)
    for name in required_secrets:
        value = getattr(config.security, name)
        if len(value.encode()) < 32 or len(set(value)) < 12 or "change_me" in value.lower():
            raise ValueError(f"{name} must be a randomly generated secret of at least 32 bytes")
    if config.security.jwt_algorithm != "HS256":
        raise ValueError("Only HS256 is supported")
    metrics_key = config.security.metrics_api_key
    if metrics_key and metrics_key.get_secret_value() in {
        config.security.jwt_secret, config.security.agent_api_key, config.security.encryption_key,
        config.oidc.client_secret, config.scim.bearer_token,
    }:
        raise ValueError('Metrics scrape key must be distinct from other credentials')
    Fernet(config.security.encryption_key.encode())
    validate_identity_settings(config)


def validate_identity_settings(config: ShadAIConfig) -> None:
    oidc, scim = config.oidc, config.scim
    if oidc.enabled or scim.enabled:
        trusted_url(oidc.issuer, oidc.allow_insecure_localhost)
    if oidc.enabled:
        if not oidc.client_id or not oidc.client_secret:
            raise ValueError("Enabled OIDC requires client ID and secret")
        trusted_url(oidc.public_base_url, oidc.allow_insecure_localhost, origin_only=True)
        if oidc.public_base_url.endswith("/"):
            raise ValueError("OIDC_PUBLIC_BASE_URL must not end with a slash")
    if len(scim.group_role_map) > 1000 or any(not key or len(key) > 255 for key in scim.group_role_map):
        raise ValueError("SCIM group role map exceeds supported limits")
    if scim.enabled:
        secret = scim.bearer_token
        if len(secret.encode()) < 32 or len(set(secret)) < 12:
            raise ValueError("SCIM token must be a randomly generated secret of at least 32 bytes")
        if secret in {config.security.agent_api_key, config.security.jwt_secret, oidc.client_secret}:
            raise ValueError("SCIM token must be distinct from other credentials")


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
