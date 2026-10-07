"""Retryable correlation; acknowledge only after the detection transaction commits."""

import asyncio
import os
from contextlib import suppress

import redis.asyncio as aioredis
import structlog
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.config import load_config, validate_security
from shadai.engine.correlator import Correlator
from shadai.models.catalog import CatalogItemORM, CatalogItemRead
from shadai.utils.queueing import PermanentMessageError, prepare_queued_event
from shadai.workers.probe import ProcessProbe
from shadai.workers.streams import StreamConsumer

logger = structlog.get_logger()
GROUP_NAME = "correlate_group"


async def run_correlation_worker(worker_id=None):
    async with ProcessProbe("correlation") as probe:
        await _run_correlation_worker(worker_id, probe)


async def _run_correlation_worker(worker_id, probe):
    config = load_config()
    validate_security(config)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    consumer = StreamConsumer(redis, GROUP_NAME, worker_id or f"correlate-{os.getpid()}", ["matches"],
                              operational=True, probe=probe)
    heartbeat = None
    correlator = Correlator(sessions)

    async def process(data):
        event = prepare_queued_event(data, field="event")
        try:
            catalog_item_id = data["catalog_item_id"]
            if not isinstance(catalog_item_id, str) or not catalog_item_id:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise PermanentMessageError("Invalid catalog reference") from None
        async with sessions() as session:
            row = await session.get(CatalogItemORM, catalog_item_id)
            if row is None:
                raise PermanentMessageError("Missing catalog item")
            if row.status != "active":
                return  # An explicit administrator disable cancels queued detections.
            item = CatalogItemRead.model_validate(row)
        try:
            field, confidence = data["match_field"], float(data["match_confidence"])
        except (ValueError, KeyError, TypeError):
            raise PermanentMessageError("Invalid match metadata") from None
        await correlator.upsert_detection(event, item, field, confidence)

    try:
        await consumer.initialize()
        probe.mark_initialized()
        heartbeat = asyncio.create_task(consumer.operations.heartbeat())
        while True:
            try:
                for stream, messages in await consumer.read():
                    for message_id, data in messages:
                        await consumer.process(stream, message_id, data, process)
            except Exception as exc:
                logger.error("correlation_loop_failed", error_type=type(exc).__name__)
                await asyncio.sleep(2)
    finally:
        if heartbeat:
            heartbeat.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat
        await redis.aclose()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_correlation_worker())
