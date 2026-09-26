"""Live dialect/transaction acceptance against disposable local/CI services.

Run SHADAI_INTEGRATION=1 pytest -q -m integration after setting DATABASE_URL,
REDIS_URL and CLICKHOUSE_HOST/PORT/DATABASE/USER/PASSWORD. Never use production.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.config import CatalogSettings, get_config, load_config
from shadai.database import init_clickhouse
from shadai.engine.catalog_loader import load_database_catalog, sync_catalog
from shadai.engine.correlator import Correlator
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemORM
from shadai.models.detection import DetectionORM
from shadai.models.event import CanonicalEvent
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM
from shadai.workers.ingest import EventProcessor
from shadai.workers.streams import StreamConsumer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SHADAI_INTEGRATION") != "1",
        reason="Disposable PostgreSQL/Redis/ClickHouse services not requested",
    ),
]


async def test_live_migration_catalog_ingestion_concurrency_and_reclaim():
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True, capture_output=True, text=True)
    config = load_config()
    get_config.cache_clear()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    ch = init_clickhouse(config.database)
    # Execute the same fresh-install schema files as container initialization.
    for path in ("docker/clickhouse-init/001_create_database.sql", "migrations/clickhouse/002_event_metadata.sql"):
        for statement in Path(path).read_text().split(";"):
            if statement.strip():
                await asyncio.to_thread(ch.execute, statement)
    unique = uuid4().hex
    item_id, domain = "test-" + unique, unique + ".example.test"
    stream = "test-events:" + unique
    group = "test-ingest:" + unique
    events = [
        CanonicalEvent(
            tenant_id=config.tenant_id,
            domain=domain,
            user_id="test-user",
            device_id="test-device",
            collector_id="integration",
        )
        for _ in range(2)
    ]
    try:
        async with sessions.begin() as session:
            count = await sync_catalog(
                session, CatalogSettings(builtin_path="catalog/builtin", local_path="catalog/local")
            )
            assert count > 0
            session.add(
                CatalogItemORM(
                    catalog_item_id=item_id,
                    canonical_name="Integration fixture",
                    category="ai_platform",
                    domains=[domain],
                    status="active",
                    source_of_truth="local",
                    local_override=True,
                )
            )
        async with sessions() as session:
            catalog = await load_database_catalog(session)
        processor = EventProcessor(redis, ch, sessions, CatalogMatcher(catalog))
        consumer = StreamConsumer(redis, group, "worker-a", [stream], reclaim_ms=0)
        await consumer.initialize()
        message_id = await redis.xadd(stream, {"data": events[0].model_dump_json()})
        await redis.xreadgroup(group, "crashed-worker", {stream: ">"}, count=1)
        recovered = await consumer.read()
        assert recovered[0][1][0][0] == message_id
        await consumer.process(stream, message_id, recovered[0][1][0][1], processor)
        assert (await redis.xpending(stream, group))["pending"] == 0
        assert await redis.xlen(stream) == 0
        # An extra consumer group prevents deletion of its unread work.
        await redis.xgroup_create(stream, "other-group", id="0")
        shared_id = await redis.xadd(stream, {"data": events[0].model_dump_json()})
        shared = await redis.xreadgroup(group, "worker-a", {stream: ">"}, count=1)
        await consumer.process(stream, shared_id, shared[0][1][0][1], processor)
        assert await redis.xlen(stream) == 1
        # Same event concurrently retried must not persist/enqueue again after success.
        await asyncio.gather(
            processor({"data": events[0].model_dump_json()}), processor({"data": events[0].model_dump_json()})
        )
        await processor({"data": events[1].model_dump_json()})
        raw_count = (
            await asyncio.to_thread(
                ch.execute, "SELECT count() FROM events WHERE catalog_match_id=%(item)s", {"item": item_id}
            )
        )[0][0]
        assert raw_count == 2
        correlator = Correlator(sessions)
        item = catalog.items[item_id]
        await asyncio.gather(
            *[
                correlator.upsert_detection(event, item, "domain", 0.6)
                for event in [events[0], events[0], events[1], events[1]]
            ]
        )
        async with sessions() as session:
            rows = (
                (await session.execute(select(DetectionORM).where(DetectionORM.catalog_item_id == item_id)))
                .scalars()
                .all()
            )
            assert len(rows) == 1
            assert rows[0].total_events_count == 2
            assert rows[0].impacted_users_count == rows[0].impacted_devices_count == 1
            receipts = (
                (
                    await session.execute(
                        select(CorrelationReceiptORM).where(CorrelationReceiptORM.catalog_item_id == item_id)
                    )
                )
                .scalars()
                .all()
            )
            assert len(receipts) == 2
        # Administrator changes are visible in the next database index refresh.
        async with sessions.begin() as session:
            row = await session.get(CatalogItemORM, item_id)
            row.status = "disabled"
        async with sessions() as session:
            assert item_id not in (await load_database_catalog(session)).items
    finally:
        await redis.delete(stream)
        async with sessions.begin() as session:
            for model in (CorrelationReceiptORM, IngestReceiptORM):
                await session.execute(delete(model).where(model.event_id.in_([event.event_id for event in events])))
            await session.execute(delete(DetectionORM).where(DetectionORM.catalog_item_id == item_id))
            await session.execute(delete(CatalogItemORM).where(CatalogItemORM.catalog_item_id == item_id))
        await asyncio.to_thread(
            ch.execute,
            "ALTER TABLE events DELETE WHERE catalog_match_id=%(item)s SETTINGS mutations_sync=1",
            {"item": item_id},
        )
        # Match records may remain in the disposable test queue; no live workers run in this test.
        ch.disconnect()
        await redis.aclose()
        await engine.dispose()
