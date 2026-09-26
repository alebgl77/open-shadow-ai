"""Event deduplication to prevent noise from repetitive signals.

v2 fixes:
- Uses regular dict (safe in single-threaded async) instead of threading.Lock
- Adds proxy dedup (same src_ip + domain within window)
- Cleanup actually called from ingest worker
"""

from __future__ import annotations

from datetime import UTC, datetime

from shadai.models.event import CanonicalEvent


class Deduplicator:
    """In-memory deduplication with configurable window."""

    def __init__(self, window_seconds: int = 300):
        self._window = window_seconds
        self._seen: dict[str, datetime] = {}

    def is_duplicate(self, event: CanonicalEvent) -> bool:
        """Check if this event is a duplicate within the dedup window.

        Dedup rules:
        - DNS: same (src_ip, domain) within window — prefetch noise suppression
        - Proxy: same (src_ip, domain) within window — reduces page-load noise
        - Endpoint: same (device_id, process_name, local_port) within window — snapshot dedup
        - Browser: same (device_id, extension_id) within window
        - OAuth: no dedup (each consent event is significant)
        """
        key = self._dedup_key(event)
        if key is None:
            return False

        now = datetime.now(UTC)
        last_seen = self._seen.get(key)
        if last_seen and (now - last_seen).total_seconds() < self._window:
            return True

        self._seen[key] = now
        return False

    def cleanup(self) -> None:
        """Remove entries older than the dedup window."""
        now = datetime.now(UTC)
        expired = [k for k, v in self._seen.items() if (now - v).total_seconds() >= self._window]
        for k in expired:
            del self._seen[k]

    def _dedup_key(self, event: CanonicalEvent) -> str | None:
        """Build dedup key based on source type. Returns None if no dedup."""
        if event.source_type == "dns":
            if event.src_ip and event.domain:
                return f"dns:{event.src_ip}:{event.domain}"
        elif event.source_type == "proxy":
            if event.src_ip and event.domain:
                return f"proxy:{event.src_ip}:{event.domain}"
        elif event.source_type == "endpoint":
            if event.device_id and event.process_name:
                return f"ep:{event.device_id}:{event.process_name}:{event.local_port}"
        elif event.source_type == "browser":
            if event.device_id and event.extension_id:
                return f"br:{event.device_id}:{event.extension_id}"
        return None
