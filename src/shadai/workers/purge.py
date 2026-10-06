"""Retention maintenance. Pending Redis messages are never trimmed by this worker."""

import argparse
import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

import structlog
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.config import load_config
from shadai.database import init_clickhouse
from shadai.models.audit import AuditLogORM
from shadai.models.detection import DetectionORM
from shadai.models.evidence_identity import EvidenceIdentityORM
from shadai.models.receipts import CorrelationReceiptORM, IngestReceiptORM
from shadai.utils.privacy import identity_cutoff, refresh_identity_counts, sanitize_evidence

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
    await maintain_personal_evidence(config, sessions, now=now)


async def maintain_personal_evidence(config, sessions, *, now: datetime, batch_size: int = 500):
    """Each detection lock precedes its membership locks, matching correlation."""
    cursor = None
    while True:
        async with sessions.begin() as session:
            query = select(DetectionORM).order_by(DetectionORM.detection_id).limit(batch_size).with_for_update()
            if cursor is not None:
                query = query.where(DetectionORM.detection_id > cursor)
            detections = list((await session.execute(query)).scalars())
            if not detections:
                return
            await session.execute(
                delete(EvidenceIdentityORM).where(
                    EvidenceIdentityORM.detection_id.in_([d.detection_id for d in detections]),
                    EvidenceIdentityORM.last_seen_at < identity_cutoff(now, config=config),
                )
            )
            projected = await refresh_identity_counts(session, detections, now=now, recalculate_risk=True)
            for detection, current in zip(detections, projected, strict=True):
                detection.impacted_users_count = current.impacted_users_count
                detection.impacted_devices_count = current.impacted_devices_count
                detection.evidence_bundle = current.evidence_bundle
                detection.primary_evidence = current.primary_evidence
                detection.risk_score = current.risk_score
                detection.reasoning_summary = current.reasoning_summary
            cursor = detections[-1].detection_id


PERSONAL_EVENT_COLUMNS = (
    "user_id",
    "username",
    "device_id",
    "hostname",
    "identity_object_id",
    "identity_sid",
    "src_ip",
)


async def scrub_personal_history(
    config, sessions, clickhouse, *, batch_size=500, max_batches=100, after_detection_id=None
):
    """Explicit bounded cleanup; preserves console identities, audit and receipts.

    Quiesce collectors/workers and drain their spools before changing privacy mode
    or key. Failure is resumable: ClickHouse batches are synchronously verified,
    PostgreSQL commits each page, and identifiers are cleared rather than relabeled.
    """
    if not 1 <= batch_size <= 500 or not 1 <= max_batches <= 1000:
        raise ValueError("Cleanup batch limits are outside supported bounds")
    predicate = " OR ".join(f"{name} != ''" for name in PERSONAL_EVENT_COLUMNS)
    ch_complete, event_batches = False, 0
    for _ in range(max_batches):
        rows = await asyncio.to_thread(
            clickhouse.execute,
            f"SELECT DISTINCT event_id FROM events WHERE tenant_id = %(tenant)s AND ({predicate}) LIMIT %(limit)s",
            {"tenant": config.tenant_id, "limit": batch_size},
        )
        if not rows:
            ch_complete = True
            break
        ids = tuple(str(row[0]) for row in rows)
        await asyncio.to_thread(
            clickhouse.execute,
            "ALTER TABLE events UPDATE "
            + ", ".join(f"{name} = ''" for name in PERSONAL_EVENT_COLUMNS)
            + " WHERE tenant_id = %(tenant)s AND event_id IN %(ids)s",
            {"tenant": config.tenant_id, "ids": ids},
            settings={"mutations_sync": 2},
        )
        remaining = await asyncio.to_thread(
            clickhouse.execute,
            "SELECT count() FROM events WHERE tenant_id = %(tenant)s AND event_id IN %(ids)s " + f"AND ({predicate})",
            {"tenant": config.tenant_id, "ids": ids},
        )
        if remaining[0][0] != 0:
            raise RuntimeError("ClickHouse personal-history mutation is not complete")
        event_batches += 1
    if not ch_complete:
        remaining = await asyncio.to_thread(
            clickhouse.execute,
            f"SELECT count() FROM events WHERE tenant_id = %(tenant)s AND ({predicate})",
            {"tenant": config.tenant_id},
        )
        ch_complete = remaining[0][0] == 0
    now, cursor, detections_count, sql_complete = datetime.now(UTC), after_detection_id, 0, False
    for _ in range(max_batches):
        async with sessions.begin() as session:
            query = select(DetectionORM).order_by(DetectionORM.detection_id).limit(batch_size).with_for_update()
            if cursor is not None:
                query = query.where(DetectionORM.detection_id > cursor)
            detections = list((await session.execute(query)).scalars())
            if not detections:
                sql_complete = True
                break
            await session.execute(
                delete(EvidenceIdentityORM).where(
                    EvidenceIdentityORM.detection_id.in_([d.detection_id for d in detections])
                )
            )
            for detection in detections:
                bundle = sanitize_evidence(detection.evidence_bundle, now=now, config=config)
                for section in bundle.values():
                    if not isinstance(section, dict):
                        continue
                    if "sample_values" in section or "sample_observations" in section:
                        section["sample_values"], section["sample_observations"] = [], []
                    for observation in section.get("network_observations", []):
                        observation["src_ip"] = ""
                bundle["_risk_score_stale"] = True
                detection.evidence_bundle = bundle
                detection.impacted_users_count = detection.impacted_devices_count = 0
                detection.primary_evidence = None
                detection.reasoning_summary = (
                    "Personal history cleared; fresh evidence is required to rebuild identity counts."
                )
                detections_count += 1
            await session.flush()
            projected = await refresh_identity_counts(session, detections, now=now, recalculate_risk=True)
            for detection, current in zip(detections, projected, strict=True):
                detection.risk_score = current.risk_score
                detection.evidence_bundle = {**current.evidence_bundle, "_personal_history_scrubbed": True}
            cursor = detections[-1].detection_id
    if not sql_complete:
        async with sessions() as session:
            query = select(DetectionORM.detection_id).where(DetectionORM.detection_id > cursor).limit(1)
            sql_complete = await session.scalar(query) is None
    if sql_complete:
        # Resume cursors cannot manufacture a full-cleanup claim. Correlation
        # strips this maintenance marker, detecting resumed writers as well.
        async with sessions() as session:
            unclean = await session.scalar(
                select(func.count())
                .select_from(DetectionORM)
                .where(
                    func.coalesce(DetectionORM.evidence_bundle["_personal_history_scrubbed"].as_boolean(), False).is_(
                        False
                    )
                )
            )
            remaining_members = await session.scalar(select(func.count()).select_from(EvidenceIdentityORM))
            sql_complete = unclean == 0 and remaining_members == 0
            if not sql_complete:
                cursor = None
    return {
        "complete": ch_complete and sql_complete,
        "clickhouse_complete": ch_complete,
        "sql_complete": sql_complete,
        "event_batches": event_batches,
        "detections_scrubbed": detections_count,
        "next_detection_id": None if sql_complete or cursor is None else str(cursor),
    }


async def run_personal_scrub(args):
    config = load_config()
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True)
    sessions, ch = async_sessionmaker(engine, expire_on_commit=False), init_clickhouse(config.database)
    try:
        result = await scrub_personal_history(
            config,
            sessions,
            ch,
            batch_size=args.batch_size,
            max_batches=args.max_batches,
            after_detection_id=args.after_detection_id,
        )
        import json

        print(json.dumps(result))
        return 0 if result["complete"] else 1
    finally:
        ch.disconnect()
        await engine.dispose()


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
    parser = argparse.ArgumentParser(description="Retention worker or explicit personal-history cleanup")
    parser.add_argument("--scrub-personal-history", action="store_true")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--max-batches", type=int, default=100)
    parser.add_argument("--after-detection-id", type=UUID)
    arguments = parser.parse_args()
    if arguments.scrub_personal_history:
        raise SystemExit(asyncio.run(run_personal_scrub(arguments)))
    asyncio.run(run_purge_worker())
