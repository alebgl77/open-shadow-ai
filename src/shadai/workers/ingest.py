"""At-least-once ingestion. PostgreSQL receipts suppress completed retries.

A crash between ClickHouse persistence and receipt commit can leave duplicate raw
rows. Analytics deduplicate event_id; correlation has a separate atomic ledger.
"""

import asyncio
import os
import time

import redis.asyncio as aioredis
import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.api.ingestion import SOURCE_TYPES, prepare_event
from shadai.config import load_config, validate_security
from shadai.database import init_clickhouse
from shadai.engine.catalog_loader import load_database_catalog
from shadai.engine.matcher import CatalogMatcher
from shadai.models.event import CanonicalEvent
from shadai.models.receipts import IngestReceiptORM
from shadai.workers.streams import StreamConsumer

logger = structlog.get_logger()
GROUP_NAME = "ingest_group"
STREAMS = [f"events:{source}" for source in SOURCE_TYPES]


async def load_ready_matcher(session):
    index = await load_database_catalog(session)
    if not index.items:
        raise RuntimeError("No active catalog entries; sync/enable the catalog before starting ingestion")
    return CatalogMatcher(index)


class EventProcessor:
    def __init__(self, redis, clickhouse, session_factory, matcher):
        self.redis, self.clickhouse = redis, clickhouse
        self.session_factory, self.matcher = session_factory, matcher

    async def __call__(self, data):
        event = prepare_event(CanonicalEvent.model_validate_json(data["data"]))
        async with self.session_factory() as session:
            async with session.begin():
                await session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                    {"key": "event:" + str(event.event_id)},
                )
                if await session.get(IngestReceiptORM, event.event_id):
                    return
                match = self.matcher.match_event(event)
                if match:
                    event.catalog_match_id = match.catalog_item_id
                    event.match_field = match.matched_field
                    event.match_confidence = match.match_confidence
                values = event.to_clickhouse_dict()
                columns = ", ".join(values)
                await asyncio.to_thread(self.clickhouse.execute, f"INSERT INTO events ({columns}) VALUES", [values])
                if match:
                    await self.redis.xadd(
                        "matches",
                        {
                            "event": event.model_dump_json(),
                            "catalog_item_id": match.catalog_item_id,
                            "match_field": match.matched_field,
                            "match_confidence": str(match.match_confidence),
                        },
                    )
                session.add(IngestReceiptORM(event_id=event.event_id))


async def run_ingest_worker(worker_id=None):
    config = load_config()
    validate_security(config)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    ch = init_clickhouse(config.database)
    consumer = StreamConsumer(redis, GROUP_NAME, worker_id or f"ingest-{os.getpid()}", STREAMS)
    try:
        await consumer.initialize()
        async with sessions() as session:
            matcher = await load_ready_matcher(session)
        processor = EventProcessor(redis, ch, sessions, matcher)
        last_reload = time.monotonic()
        while True:
            try:
                if time.monotonic() - last_reload >= config.catalog.reload_interval_seconds:
                    async with sessions() as session:
                        processor.matcher = await load_ready_matcher(session)
                    last_reload = time.monotonic()
                for stream, messages in await consumer.read():
                    for message_id, data in messages:
                        await consumer.process(stream, message_id, data, processor)
            except Exception as exc:
                logger.error("ingest_loop_failed", error_type=type(exc).__name__)
                await asyncio.sleep(2)
    finally:
        ch.disconnect()
        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_ingest_worker())
