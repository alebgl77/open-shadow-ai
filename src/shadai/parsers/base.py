"""Base parser interface for all log format parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import structlog

from shadai.models.event import CanonicalEvent
from shadai.utils.metrics import EVENTS_PARSED, PARSE_ERRORS

logger = structlog.get_logger()

# Parser registry for dynamic lookup
PARSER_REGISTRY: dict[str, type[BaseParser]] = {}


def register_parser(name: str):
    """Class decorator to register a parser by name."""

    def decorator(cls):
        PARSER_REGISTRY[name] = cls
        return cls

    return decorator


def get_parser(name: str, timezone: str = "UTC") -> BaseParser:
    """Instantiate a parser by its registered name."""
    if name not in PARSER_REGISTRY:
        raise ValueError(f"Unknown parser: {name}. Available: {list(PARSER_REGISTRY.keys())}")
    return PARSER_REGISTRY[name](timezone=timezone)


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    source_type: str = ""
    parser_version: str = "1.0.0"

    def __init__(self, timezone: str = "UTC"):
        try:
            self.timezone = UTC if timezone == "UTC" else ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"Unknown source timezone: {timezone!r}") from exc

    def localize(self, value: datetime) -> datetime:
        """Read a device-local timestamp without offset in the source's configured timezone."""
        if value.tzinfo is None:
            value = value.replace(tzinfo=self.timezone)
        return value.astimezone(UTC)

    @abstractmethod
    def parse(self, raw_line: str) -> CanonicalEvent | None:
        """Parse a single raw log line into a canonical event.

        Returns None if the line cannot be parsed (comments, headers, etc.).
        """
        ...

    def parse_batch(self, lines: list[str]) -> list[CanonicalEvent]:
        """Parse multiple lines, skipping unparseable ones."""
        results = []
        for line in lines:
            try:
                event = self.parse(line)
                if event:
                    results.append(event)
                    EVENTS_PARSED.labels(parser=self.__class__.__name__).inc()
            except Exception as e:
                logger.warning("parse_error", parser=self.__class__.__name__, error=str(e), line=line[:200])
                PARSE_ERRORS.labels(parser=self.__class__.__name__).inc()
        return results
