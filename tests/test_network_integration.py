"""Real-store network ingestion, replay deduplication and typed analytics on isolated fixtures."""

import asyncio
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.api import network
from shadai.api.ingestion import prepare_event
from shadai.config import get_config, load_config
from shadai.database import init_clickhouse
from shadai.engine.catalog_loader import build_catalog_index
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.models.receipts import IngestReceiptORM
from shadai.workers.ingest import EventProcessor

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SHADAI_INTEGRATION") != "1",
        reason="Disposable PostgreSQL/Redis/ClickHouse services not requested",
    ),
]


async def test_live_network_worker_to_typed_metrics_deduplicates_replays_and_keeps_unknowns(monkeypatch):
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True, text=True)
    unique = uuid4().hex
    tenant, foreign_tenant = "network-test-" + unique, "foreign-test-" + unique
    monkeypatch.setenv("SHADAI_TENANT_ID", tenant)
    get_config.cache_clear()
    config = load_config()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    ch = init_clickhouse(config.database)
    stream = "network-test-matches:" + unique
    # Apply the existing schema only; the network source introduces no database columns.
    for path in ("docker/clickhouse-init/001_create_database.sql", "migrations/clickhouse/002_event_metadata.sql"):
        for statement in Path(path).read_text().split(";"):
            if statement.strip():
                await asyncio.to_thread(ch.execute, statement)
    domain, item_id = unique + ".example.test", "network-fixture-" + unique
    item = CatalogItemRead(
        catalog_item_id=item_id, canonical_name="Network fixture", category="ai_platform", domains=[domain]
    )
    anchor = (datetime.now(UTC) - timedelta(seconds=2)).replace(microsecond=900000)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return anchor

    events = [
        CanonicalEvent(
            source_type="network", protocol="DNS", domain=domain, collector_id="fixture-sensor", tenant_id=tenant,
            timestamp=anchor - timedelta(hours=24),
        ),
        CanonicalEvent(
            source_type="network", protocol="TLS", sni=domain, collector_id="fixture-sensor", tenant_id=tenant,
            timestamp=anchor,
        ),
        CanonicalEvent(
            source_type="network", protocol="QUIC", collector_id="nameless-sensor", tenant_id=tenant,
            dst_ip="192.0.2.1", dst_port=443, timestamp=anchor - timedelta(milliseconds=100),
        ),
        CanonicalEvent(
            source_type="network", protocol="HTTP", url_host="unknown.example.test", collector_id="fixture-sensor",
            tenant_id=tenant, timestamp=anchor - timedelta(milliseconds=200),
        ),
    ]
    stale = CanonicalEvent(
        source_type="network", protocol="DNS", domain=domain, collector_id="fixture-sensor", tenant_id=tenant,
        timestamp=anchor - timedelta(hours=24, milliseconds=1),
    )
    future = CanonicalEvent(
        source_type="network", protocol="DNS", domain=domain, collector_id="fixture-sensor", tenant_id=tenant,
        timestamp=anchor + timedelta(milliseconds=1),
    )
    foreign = CanonicalEvent(
        source_type="network", protocol="DNS", domain=domain, collector_id="foreign-sensor", tenant_id=foreign_tenant,
    )

    async def isolated_xadd(_name, data):
        return await redis.xadd(stream, data)

    processor = EventProcessor(
        SimpleNamespace(xadd=isolated_xadd), ch, sessions, CatalogMatcher(build_catalog_index([item]))
    )
    try:
        for event in events + [stale, future]:
            await processor({"data": prepare_event(event).model_dump_json()})
        # Successful receipt retries must not create rows or duplicate matched records.
        await asyncio.gather(*[processor({"data": events[0].model_dump_json()}) for _ in range(3)])
        # A possible write-before-receipt crash leaves a duplicate row; reads still count UUIDs.
        values = events[0].to_clickhouse_dict() | {"catalog_match_id": item_id}
        columns = ", ".join(values)
        await asyncio.to_thread(ch.execute, f"INSERT INTO events ({columns}) VALUES", [values])
        await asyncio.to_thread(ch.execute, f"INSERT INTO events ({columns}) VALUES", [foreign.to_clickhouse_dict()])
        monkeypatch.setattr(network, "get_clickhouse", lambda: ch)
        monkeypatch.setattr(network, "datetime", FrozenDatetime)
        overview = await network.get_network_overview(hours=24, _user=SimpleNamespace(role="analyst"))
        assert overview.total_observations == 4
        assert overview.named_observations == 3
        assert overview.matched_observations == overview.unmatched_observations == 2
        assert overview.protocols == {"DNS": 1, "TLS": 1, "QUIC": 1, "HTTP": 1}
        assert {sensor.collector_id: sensor.observations for sensor in overview.sensors} == {
            "fixture-sensor": 3, "nameless-sensor": 1,
        }
        page = await network.get_network_events(
            hours=24, protocol=None, page=1, page_size=100, _user=SimpleNamespace(role="analyst")
        )
        assert page.total == 4 and len(page.items) == 4
        assert {event.event_id for event in page.items} == {event.event_id for event in events}
        assert sum(event.matched for event in page.items) == 2
        unknown = next(event for event in page.items if event.protocol == "QUIC")
        assert unknown.domain == "" and unknown.catalog_match_id is None and not unknown.matched
        assert unknown.timestamp.tzinfo is not None
        tls = await network.get_network_events(
            hours=24, protocol="TLS", page=1, page_size=20, _user=SimpleNamespace(role="analyst")
        )
        assert tls.total == 1 and tls.items[0].event_id == events[1].event_id
        assert tls.items[0].catalog_match_id == item_id
        assert await redis.xlen(stream) == 4  # DNS, TLS and both out-of-window DNS fixtures.
    finally:
        # Own UUID tenant/receipt/stream fixtures only; never touch an operator's observations.
        await redis.delete(stream)
        async with sessions.begin() as session:
            await session.execute(
                delete(IngestReceiptORM).where(
                    IngestReceiptORM.event_id.in_([e.event_id for e in events + [stale, future]])
                )
            )
        await asyncio.to_thread(
            ch.execute,
            "ALTER TABLE events DELETE WHERE tenant_id IN %(tenants)s SETTINGS mutations_sync=1",
            {"tenants": (tenant, foreign_tenant)},
        )
        ch.disconnect()
        await redis.aclose()
        await engine.dispose()
        get_config.cache_clear()
