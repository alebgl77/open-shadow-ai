"""Real lab fixtures and exact source/restore inventories, executed inside the lab."""

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid5

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.api.collectors import issue_credential
from shadai.config import load_config
from shadai.database import init_clickhouse
from shadai.models.collector import CollectorORM
from shadai.qualification.journal import atomic_json
from shadai.qualification.schemas import QualificationError
from shadai.utils.operations import STAGES, pipeline_snapshot


def expected_load_ids(load, *, pending=None):
    identifiers = load["accepted_scoped_ids"]
    if pending is not None:
        if (
            type(load["accepted"]) is not int
            or load["accepted"] != 10
            or len(identifiers) != 10
            or len(set(identifiers)) != 10
            or pending in identifiers
        ):
            raise QualificationError("Restore requires ten distinct newly accepted events plus pending work")
    expected = set(identifiers)
    if pending is not None:
        expected.add(pending)
    return expected


async def fixture(action, directory, run_id, *, case="baseline"):
    directory = Path(directory)
    config = load_config()
    if config.security.allow_legacy_agent_key or not config.tenant_id.startswith("q-"):
        raise QualificationError("Fixture requires the disposable scoped lab installation")
    engine = create_async_engine(config.database.postgres_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    redis = aioredis.from_url(config.database.redis_url, decode_responses=True)
    ch = init_clickhouse(config.database)
    collector_id = "qualification-" + UUID(run_id).hex
    try:
        if action == "initialize":
            from shadai.workers.redis_lifecycle import reconcile
            from shadai.workers.streams import StreamConsumer

            for group, streams in STAGES.values():
                await StreamConsumer(
                    redis, group, "qualification-initializer", streams, settings=config.redis_queue
                ).initialize()
            result = await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=config.redis_queue)
            return {"initialized": True, "retention": result}
        if action == "pipeline":
            return {"pipeline": await pipeline_snapshot(redis)}
        if action == "redis_persistence":
            from shadai.qualification.redis_persistence import redis_persistence

            return await redis_persistence(redis)
        if action == "enroll":
            async with sessions.begin() as session:
                if await session.get(CollectorORM, collector_id):
                    raise QualificationError("Fixture collector already exists; preserve its recorded credential")
                collector = CollectorORM(
                    collector_id=collector_id,
                    tenant_id=config.tenant_id,
                    display_name="SYNTHETIC qualification",
                    allowed_source_types=["dns"],
                    credential_generation=1,
                )
                session.add(collector)
                await session.flush()
                credential, token = issue_credential(collector, 1)
                session.add(credential)
            path = directory / "collector-key"
            with path.open("x") as file:
                file.write(token)
            path.chmod(0o600)
            return {"collector_id": collector_id, "enrolled": True, "legacy_disabled": True}
        if action == "seed_pending":
            # Workers are stopped by the host before this call. Witness a real
            # PEL with XREADGROUP; retain poison source, DLQ pointer and replay ref.
            from shadai.models.event import CanonicalEvent
            from shadai.utils.queue_admission import admit_records
            from shadai.utils.queueing import PermanentMessageError, queue_fields
            from shadai.workers.redis_lifecycle import reconcile, refs_key
            from shadai.workers.replay import replay_deadletters
            from shadai.workers.streams import StreamConsumer

            await reconcile(redis, execute=True, legacy_writers_stopped=True, settings=config.redis_queue)
            clock = await redis.time()
            accepted_at = datetime.fromtimestamp(clock[0], UTC)
            for group, streams in STAGES.values():
                for stream in streams:
                    try:
                        await redis.xgroup_create(stream, group, id="0", mkstream=True)
                    except Exception as exc:
                        if "BUSYGROUP" not in str(exc):
                            raise
            event = CanonicalEvent(
                event_id=uuid5(UUID(run_id), "restore-undelivered"),
                tenant_id=config.tenant_id,
                collector_id=collector_id,
                timestamp=accepted_at,
                source_type="dns",
                domain="api.openai.com",
            )
            fields = queue_fields(event.model_dump_json(), accepted_at=accepted_at)
            await admit_records(redis, [{"stream": "events:dns", "fields": fields}], settings=config.redis_queue)
            pending = await redis.xreadgroup("ingest_group", "qualification-crashed", {"events:dns": ">"}, count=1)
            poison_fields = {"data": "synthetic-invalid", "accepted_at": accepted_at.isoformat()}
            [poison] = await admit_records(
                redis, [{"stream": "events:dns", "fields": poison_fields}], settings=config.redis_queue
            )
            await redis.xreadgroup("ingest_group", "qualification-poison", {"events:dns": ">"}, count=1)
            consumer = StreamConsumer(
                redis,
                "ingest_group",
                "qualification-poison",
                ["events:dns"],
                max_attempts=1,
                settings=config.redis_queue,
            )

            async def reject(data):
                raise PermanentMessageError("SYNTHETIC poison")

            await consumer.process("events:dns", poison, poison_fields, reject)
            replayed = await replay_deadletters(redis, "ingest_group", execute=True, settings=config.redis_queue)
            if len(replayed) != 1 or replayed[0]["status"] != "replayed":
                raise QualificationError("Actual DLQ/replay fixture did not complete")
            marker = "replayed:ingest_group:" + replayed[0]["pointer_id"]
            refs = refs_key("events:dns")
            if not pending or int(await redis.hget(refs, poison) or 0) < 1:
                raise QualificationError("Poison source reference or pending fixture is absent")
            return {
                "pel_witnessed": bool((await redis.xpending("events:dns", "ingest_group"))["pending"]),
                "poison_source": poison,
                "replay_marker": marker,
                "refs": refs,
                "pending_event_id": str(event.event_id),
            }
        if action in {"inventory", "verify_load"}:
            async with sessions() as session:
                tables = {}
                for table, columns in {
                    "ingest_receipts": "event_id",
                    "correlation_receipts": "event_id,catalog_item_id",
                    "detections": "detection_id,catalog_item_id,total_events_count",
                    "collectors": "collector_id,tenant_id,allowed_source_types,credential_generation",
                    "collector_credentials": "credential_id,collector_id,secret_digest,generation",
                    "detection_identity_members": "detection_id,kind,identity_digest",
                }.items():
                    # Fixed identifiers only; no input can become SQL syntax.
                    exists = await session.scalar(text("SELECT to_regclass(:table)"), {"table": table})
                    if exists:
                        rows = await session.execute(text("SELECT " + columns + " FROM " + table + " ORDER BY 1"))
                        tables[table] = [list(row) for row in rows]
                receipt_times = dict(
                    (await session.execute(text("SELECT event_id,received_at FROM ingest_receipts"))).all()
                )
            events = await asyncio.to_thread(
                ch.execute, "SELECT event_id,tenant_id,collector_id,catalog_match_id FROM events ORDER BY event_id"
            )
            stores = {"postgres": tables, "clickhouse_events": [list(row) for row in events], "redis": {}}
            async for key in redis.scan_iter(count=100):
                # Operational heartbeats legitimately change; queues, PEL, refs,
                # retries, replay and their exact binary dump do not while quiesced.
                if key.startswith("operations:"):
                    continue
                kind = await redis.type(key)
                if kind == "stream":
                    groups = await redis.xinfo_groups(key)
                    stores["redis"][key] = {
                        "type": kind,
                        "entries": await redis.xrange(key),
                        "groups": groups,
                        "pending": {
                            group["name"]: [
                                {field: value for field, value in item.items() if field != "time_since_delivered"}
                                for item in await redis.xpending_range(key, group["name"], "-", "+", 10000)
                            ]
                            for group in groups
                        },
                    }
                elif kind == "hash":
                    stores["redis"][key] = {"type": kind, "value": await redis.hgetall(key)}
                elif kind == "string":
                    stores["redis"][key] = {"type": kind, "value": await redis.get(key)}
                elif kind == "zset":
                    stores["redis"][key] = {"type": kind, "value": await redis.zrange(key, 0, -1, withscores=True)}
                else:
                    raise QualificationError("Unexpected Redis type in fixed lab inventory")
            # PostgreSQL timestamps/UUIDs are canonical strings; no events/users
            # enter the public report. The full inventory stays private run evidence.
            encoded = json.loads(json.dumps(stores, default=str, sort_keys=True))
            if action == "inventory":
                atomic_json(directory / (case + "-inventory.json"), encoded)
                return {
                    "inventory_file": case + "-inventory.json",
                    "logical_events": len({row[0] for row in encoded["clickhouse_events"]}),
                    "pipeline": await pipeline_snapshot(redis),
                }
            load = json.loads((directory / (case + "-load.json")).read_text())
            pending_fixture = None
            if case == "restored-fresh":
                pending_fixture = json.loads((directory / "cold-manifest.json").read_text())["pending_fixture"][
                    "pending_event_id"
                ]
            expected = expected_load_ids(load, pending=pending_fixture)
            persisted = {str(row[0]) for row in events}
            receipts = {row[0] for row in encoded["postgres"]["ingest_receipts"]}
            correlations = {row[0] for row in encoded["postgres"]["correlation_receipts"]}
            result = {
                "expected_logical_events": len(expected),
                "persisted": len(expected & persisted),
                "receipts": len(expected & receipts),
                "correlation_receipts": len(expected & correlations),
                "missing": sorted(expected - persisted),
                "missing_receipts": sorted(expected - receipts),
                "missing_correlations": sorted(expected - correlations),
                "restored_pending_fixture_persisted": pending_fixture in persisted if pending_fixture else None,
                "unique_physical_ids": len(persisted),
                "physical_rows": len(events),
                "pipeline": await pipeline_snapshot(redis),
            }
            from uuid import NAMESPACE_URL

            from shadai.qualification.load import percentile

            latencies = []
            for name in json.loads((directory / (case + "-load-manifest.json")).read_text())["batches"]:
                for event in json.loads((directory / name).read_text())["events"]:
                    scoped = uuid5(
                        NAMESPACE_URL,
                        json.dumps([config.tenant_id, collector_id, event["event_id"]], separators=(",", ":")),
                    )
                    received = receipt_times.get(scoped)
                    if received:
                        seconds = (received - datetime.fromisoformat(event["timestamp"])).total_seconds()
                        if seconds < 0:
                            raise QualificationError("Clock ordering does not support end-to-end latency evidence")
                        latencies.append(seconds)
            result["end_to_end_latency_p95_seconds"] = percentile(latencies, 0.95)
            result["end_to_end_latency_provenance"] = "lab shared-host clock event scheduled emission to PG receipt"
            atomic_json(directory / (case + "-verification.json"), result)
            return result
        if action == "physical":
            memory = await redis.info("memory")
            filesystem = os.statvfs("/qualification")
            return {
                "redis_used_memory_bytes": memory["used_memory"],
                "redis_used_memory_rss_bytes": memory["used_memory_rss"],
                "redis_maxmemory_bytes": memory["maxmemory"],
                "run_filesystem_total_bytes": filesystem.f_blocks * filesystem.f_frsize,
                "run_filesystem_available_bytes": filesystem.f_bavail * filesystem.f_frsize,
                "provenance": {"redis": "INFO memory", "run_filesystem": "statvfs /qualification"},
            }
        raise QualificationError("Unknown fixture action")
    finally:
        ch.disconnect()
        await redis.aclose()
        await engine.dispose()
