"""Database connection management for PostgreSQL, ClickHouse, and Redis."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from threading import RLock

import redis.asyncio as aioredis
from clickhouse_driver import Client as ClickHouseClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from shadai.config import DatabaseSettings


class SerializedClickHouseClient(ClickHouseClient):
    """Serialize access to the native client's single connection across API threads."""

    def __init__(self, *args, **kwargs):
        self._query_lock = RLock()
        super().__init__(*args, **kwargs)

    def execute(self, *args, **kwargs):
        with self._query_lock:
            return super().execute(*args, **kwargs)

    def disconnect(self):
        with self._query_lock:
            return super().disconnect()


# ── Module-level singletons ──────────────────────────────────────
_async_engine = None
_async_session_factory: async_sessionmaker[AsyncSession] | None = None
_ch_client: ClickHouseClient | None = None
_redis_pool: aioredis.Redis | None = None


# ── PostgreSQL ───────────────────────────────────────────────────
async def init_postgres(settings: DatabaseSettings) -> None:
    global _async_engine, _async_session_factory
    _async_engine = create_async_engine(
        settings.postgres_url,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
        echo=False,
    )
    _async_session_factory = async_sessionmaker(
        _async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def get_postgres_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a Postgres session."""
    if _async_session_factory is None:
        raise RuntimeError("PostgreSQL not initialized. Call init_postgres first.")
    async with _async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── ClickHouse ───────────────────────────────────────────────────
def init_clickhouse(settings: DatabaseSettings) -> ClickHouseClient:
    global _ch_client
    tls = {}
    if settings.clickhouse_secure:
        tls = {"secure": True, "verify": True}
        for option in ("ca_certs", "certfile", "keyfile", "server_hostname"):
            if value := getattr(settings, "clickhouse_" + option):
                tls[option] = value
    _ch_client = SerializedClickHouseClient(
        host=settings.clickhouse_host,
        port=settings.clickhouse_effective_port,
        database=settings.clickhouse_database,
        user=settings.clickhouse_user,
        password=settings.clickhouse_password,
        connect_timeout=5,
        send_receive_timeout=15,
        **tls,
    )
    return _ch_client


def get_clickhouse() -> ClickHouseClient:
    if _ch_client is None:
        raise RuntimeError("ClickHouse not initialized. Call init_clickhouse first.")
    return _ch_client


# ── Redis ────────────────────────────────────────────────────────
async def init_redis(settings: DatabaseSettings) -> aioredis.Redis:
    global _redis_pool
    _redis_pool = aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=50,
    )
    return _redis_pool


async def get_redis() -> aioredis.Redis:
    if _redis_pool is None:
        raise RuntimeError("Redis not initialized. Call init_redis first.")
    return _redis_pool


# ── Cleanup ──────────────────────────────────────────────────────
async def close_all() -> None:
    global _async_engine, _async_session_factory, _redis_pool, _ch_client
    if _async_engine:
        await _async_engine.dispose()
        _async_engine = None
        _async_session_factory = None
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None
    if _ch_client:
        _ch_client.disconnect()
        _ch_client = None
