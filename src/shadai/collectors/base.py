"""Base collector interface for all data sources."""

from __future__ import annotations

import asyncio
import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import redis.asyncio as aioredis
import structlog

from shadai.engine.catalog_loader import CatalogIndex
from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser
from shadai.utils.metrics import EVENTS_INGESTED, EVENTS_REJECTED
from shadai.utils.queueing import queue_fields

logger = structlog.get_logger()


class BaseCollector(ABC):
    """Abstract base for all collectors (syslog, file, API, agent)."""

    collector_id: str
    source_type: str

    def __init__(
        self,
        collector_id: str,
        parser: BaseParser,
        redis_client: aioredis.Redis,
        catalog_loader: Callable[[], Awaitable[CatalogIndex]] | None = None,
        spool=None,
    ):
        self.collector_id = collector_id
        self.parser = parser
        self.redis = redis_client
        self.source_type = parser.source_type
        # Lets URL paths and user agents be matched here, before they are discarded.
        self.catalog_loader = catalog_loader
        self.spool = spool
        self.counters = {"delivery_failures": 0, "retention_failures": 0, "delivered_events": 0}

    async def push_events(self, events: list[CanonicalEvent]) -> int:
        """Push canonical events to Redis Stream. Returns count pushed."""
        if not events:
            return 0

        from shadai.api.ingestion import boundary_catalog, has_transient_signals, prepare_event

        matcher = None
        if self.catalog_loader is not None and any(has_transient_signals(event) for event in events):
            matcher = await boundary_catalog.get(self.catalog_loader)
        accepted_at = datetime.now(UTC)
        queued = []
        accepted = 0
        for event in events:
            try:
                event = prepare_event(event, trusted_collector=True, matcher=matcher)
            except ValueError as exc:
                # One out-of-window event must not drop its neighbours or the TCP connection.
                EVENTS_REJECTED.labels(source_type=self.source_type).inc()
                logger.warning("event_rejected", collector=self.collector_id, reason=str(exc))
                continue
            event.collector_id = self.collector_id
            stream_key = f"events:{event.source_type}"
            queued.append({"stream": stream_key,
                           "fields": queue_fields(event.model_dump_json(), accepted_at=accepted_at)})
            accepted += 1

        if not accepted:
            return 0
        if self.spool is not None:
            try:
                await asyncio.to_thread(self.spool.enqueue,
                                        json.dumps(queued, separators=(",", ":")).encode("utf-8"),
                                        event_count=accepted)
            except Exception:
                self.counters["retention_failures"] += 1
                raise
            # Successful retention is counted separately from actual Redis delivery.
            await self.flush_spool()
            return accepted
        pipe = self.redis.pipeline(transaction=True)
        for record in queued:
            pipe.xadd(record["stream"], record["fields"])
        await pipe.execute()
        EVENTS_INGESTED.labels(source_type=self.source_type).inc(accepted)
        logger.debug("events_pushed", collector=self.collector_id, count=accepted)
        return accepted

    async def flush_spool(self, *, limit: int = 50) -> int:
        if self.spool is None:
            return 0
        delivered = 0
        for _ in range(limit):
            batches = await asyncio.to_thread(self.spool.claim, limit=1)
            if not batches:
                break
            [batch] = batches
            records = json.loads(batch.payload)
            pipe = self.redis.pipeline(transaction=True)
            for record in records:
                pipe.xadd(record["stream"], record["fields"])
            try:
                await pipe.execute()
            except Exception as exc:
                self.counters["delivery_failures"] += 1
                await asyncio.to_thread(self.spool.retry, batch)
                logger.warning("collector_delivery_failed", collector=self.collector_id,
                               error_type=type(exc).__name__)
            else:
                await asyncio.to_thread(self.spool.ack, batch)
                delivered += len(records)
        if delivered:
            self.counters["delivered_events"] += delivered
            EVENTS_INGESTED.labels(source_type=self.source_type).inc(delivered)
        return delivered

    async def delivery_stats(self) -> dict:
        stats = dict(self.counters)
        if self.spool is not None:
            stats["spool"] = await asyncio.to_thread(self.spool.stats)
        return stats

    @abstractmethod
    async def run(self) -> None:
        """Start collecting. Runs indefinitely."""
        ...
