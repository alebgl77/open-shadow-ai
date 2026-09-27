"""Base collector interface for all data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

import redis.asyncio as aioredis
import structlog

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser
from shadai.utils.metrics import EVENTS_INGESTED, EVENTS_REJECTED

logger = structlog.get_logger()


class BaseCollector(ABC):
    """Abstract base for all collectors (syslog, file, API, agent)."""

    collector_id: str
    source_type: str

    def __init__(self, collector_id: str, parser: BaseParser, redis_client: aioredis.Redis):
        self.collector_id = collector_id
        self.parser = parser
        self.redis = redis_client
        self.source_type = parser.source_type

    async def push_events(self, events: list[CanonicalEvent]) -> int:
        """Push canonical events to Redis Stream. Returns count pushed."""
        if not events:
            return 0

        from shadai.api.ingestion import prepare_event

        pipe = self.redis.pipeline()
        accepted = 0
        for event in events:
            try:
                event = prepare_event(event, trusted_collector=True)
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
