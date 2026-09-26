"""Base collector interface for all data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod

import redis.asyncio as aioredis
import structlog

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser
from shadai.utils.metrics import EVENTS_INGESTED

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

        pipe = self.redis.pipeline()
        for event in events:
            from shadai.api.ingestion import prepare_event

            event = prepare_event(event, trusted_collector=True)
            event.collector_id = self.collector_id
            stream_key = f"events:{event.source_type}"
            pipe.xadd(stream_key, {"data": event.model_dump_json()})

        await pipe.execute()
        EVENTS_INGESTED.labels(source_type=self.source_type).inc(len(events))
        logger.debug("events_pushed", collector=self.collector_id, count=len(events))
        return len(events)

    @abstractmethod
    async def run(self) -> None:
        """Start collecting. Runs indefinitely."""
        ...
