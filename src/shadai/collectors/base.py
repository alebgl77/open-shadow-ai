"""Base collector interface for all data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

import redis.asyncio as aioredis
import structlog

from shadai.engine.catalog_loader import CatalogIndex
from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser
from shadai.utils.metrics import EVENTS_INGESTED, EVENTS_REJECTED

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
    ):
        self.collector_id = collector_id
        self.parser = parser
        self.redis = redis_client
        self.source_type = parser.source_type
        # Lets URL paths and user agents be matched here, before they are discarded.
        self.catalog_loader = catalog_loader

    async def push_events(self, events: list[CanonicalEvent]) -> int:
        """Push canonical events to Redis Stream. Returns count pushed."""
        if not events:
            return 0

        from shadai.api.ingestion import boundary_catalog, has_transient_signals, prepare_event

        matcher = None
        if self.catalog_loader is not None and any(has_transient_signals(event) for event in events):
            matcher = await boundary_catalog.get(self.catalog_loader)
        pipe = self.redis.pipeline()
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
            pipe.xadd(stream_key, {"data": event.model_dump_json()})
            accepted += 1

        if not accepted:
            return 0
        await pipe.execute()
        EVENTS_INGESTED.labels(source_type=self.source_type).inc(accepted)
        logger.debug("events_pushed", collector=self.collector_id, count=accepted)
        return accepted

    @abstractmethod
    async def run(self) -> None:
        """Start collecting. Runs indefinitely."""
        ...
