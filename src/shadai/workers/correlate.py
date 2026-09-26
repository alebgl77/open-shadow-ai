"""Retryable correlation; acknowledge only after the detection transaction commits."""

import asyncio
import os

import redis.asyncio as aioredis
import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.api.ingestion import prepare_event
from shadai.config import load_config, validate_security
from shadai.engine.correlator import Correlator
from shadai.models.catalog import CatalogItemORM, CatalogItemRead
from shadai.models.event import CanonicalEvent
from shadai.workers.streams import StreamConsumer

logger = structlog.get_logger()
GROUP_NAME = "correlate_group"


async def run_correlation_worker(worker_id=None):
    config = load_config()
    validate_security(config)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    consumer = StreamConsumer(redis, GROUP_NAME, worker_id or f"correlate-{os.getpid()}", ["matches"])
    correlator = Correlator(sessions)

    async def process(data):
        event = prepare_event(CanonicalEvent.model_validate_json(data["event"]), trusted_collector=True)
        async with sessions() as session:
            row = await session.get(CatalogItemORM, data["catalog_item_id"])
            if row is None:
                raise ValueError("Missing catalog item")
            if row.status != "active":
                return  # An explicit administrator disable cancels queued detections.
            item = CatalogItemRead.model_validate(row)
        await correlator.upsert_detection(event, item, data["match_field"], float(data["match_confidence"]))

    try:
        await consumer.initialize()
        while True:
            try:
                for stream, messages in await consumer.read():
                    for message_id, data in messages:
                        await consumer.process(stream, message_id, data, process)
            except Exception as exc:
                logger.error("correlation_loop_failed", error_type=type(exc).__name__)
                await asyncio.sleep(2)
    finally:
        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_correlation_worker())
