"""Retention maintenance. Pending Redis messages are never trimmed by this worker."""

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.config import load_config
from shadai.database import init_clickhouse
from shadai.models.audit import AuditLogORM
from shadai.models.detection import DetectionORM
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM

logger = structlog.get_logger()


async def purge_once(config, sessions, clickhouse):
    if not config.retention.purge_enabled:
        return
    now = datetime.now(UTC)
    # Integer bounds are validated by RetentionSettings before interpolating TTL DDL.
    await asyncio.to_thread(
        clickhouse.execute, f"ALTER TABLE events MODIFY TTL timestamp + INTERVAL {config.retention.events_days} DAY"
    )
    await asyncio.to_thread(
        clickhouse.execute,
        "ALTER TABLE events DELETE WHERE timestamp < %(cutoff)s",
        {"cutoff": now - timedelta(days=config.retention.events_days)},
    )
    async with sessions.begin() as session:
        await session.execute(
            update(DetectionORM)
            .where(
                DetectionORM.last_seen_at < now - timedelta(days=30),
                DetectionORM.shadow_ai_status.notin_(["archived", "false_positive"]),
            )
            .values(shadow_ai_status="stale")
        )
        await session.execute(
            update(DetectionORM)
            .where(
                DetectionORM.last_seen_at < now - timedelta(days=90),
                DetectionORM.shadow_ai_status == "stale",
            )
            .values(shadow_ai_status="archived")
        )
        await session.execute(
            delete(DetectionORM).where(
                DetectionORM.last_seen_at < now - timedelta(days=config.retention.detections_days)
            )
        )
        await session.execute(
            delete(AuditLogORM).where(AuditLogORM.timestamp < now - timedelta(days=config.retention.audit_logs_days))
        )
        for receipt in (IngestReceiptORM, CorrelationReceiptORM):
            await session.execute(
                delete(receipt).where(receipt.received_at < now - timedelta(days=config.retention.receipt_days))
            )


async def run_purge_worker():
    config = load_config()
    if not config.retention.purge_enabled:
        logger.info("purge_disabled")
        return
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    ch = init_clickhouse(config.database)
    try:
        while True:
            try:
                await purge_once(config, sessions, ch)
                logger.info("purge_cycle_complete")
            except Exception as exc:
                logger.error("purge_failed", error_type=type(exc).__name__)
            # Daily interval from process startup; cron expressions are not interpreted.
            await asyncio.sleep(86400)
    finally:
        ch.disconnect()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_purge_worker())
