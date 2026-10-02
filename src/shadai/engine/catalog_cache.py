"""Active catalog for ingestion boundaries, which evaluate signals they must not retain."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

import structlog

from shadai.config import get_config
from shadai.engine.catalog_loader import CatalogIndex
from shadai.engine.matcher import CatalogMatcher

logger = structlog.get_logger()


class CatalogCache:
    """Matcher reloaded at the catalog interval; a failed reload keeps the previous one."""

    def __init__(self) -> None:
        self._matcher: CatalogMatcher | None = None
        self._expires = float("-inf")
        self._lock = asyncio.Lock()

    async def get(self, load: Callable[[], Awaitable[CatalogIndex]]) -> CatalogMatcher | None:
        if time.monotonic() < self._expires:
            return self._matcher
        async with self._lock:
            if time.monotonic() >= self._expires:
                try:
                    index = await load()
                    self._matcher = CatalogMatcher(index) if index.items else None
                except Exception as exc:
                    # Ingestion continues; the worker still matches the retained fields.
                    logger.warning("boundary_catalog_unavailable", error_type=type(exc).__name__)
                self._expires = time.monotonic() + get_config().catalog.reload_interval_seconds
        return self._matcher
