"""BIND named query log parser."""

from __future__ import annotations

import re
from datetime import datetime

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# BIND query log format (named.conf: querylog yes):
# 27-Mar-2026 14:23:45.123 queries: info: client @0x... 192.168.1.100#12345 (chat.openai.com): query:
# chat.openai.com IN A +E(0)K (10.0.0.1)
_BIND_RE = re.compile(
    r"(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"queries:\s+info:\s+client\s+(?:@\S+\s+)?(\S+)#(\d+)\s+"
    r"\(([^)]*)\):\s+query:\s+(\S+)\s+IN\s+(\S+)"
)

# Simpler format: just timestamp + client IP + query domain
_BIND_SIMPLE_RE = re.compile(
    r"(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+.*?"
    r"client\s+(?:@\S+\s+)?(\S+)#\d+.*?query:\s+(\S+)\s+IN"
)


@register_parser("bind_query_log")
class BindQueryLogParser(BaseParser):
    source_type = "dns"
    parser_version = "1.0.0"

    def parse(self, raw_line: str) -> CanonicalEvent | None:
        line = sanitize_log_input(raw_line.strip())
        if not line or line.startswith("#") or "query:" not in line:
            return None

        match = _BIND_RE.search(line)
        if not match:
            match = _BIND_SIMPLE_RE.search(line)
            if not match:
                return None
            ts_str, client_ip, domain = match.group(1), match.group(2), match.group(3)
        else:
            ts_str, client_ip = match.group(1), match.group(2)
            domain = match.group(5)

        # Parse timestamp
        try:
            timestamp = datetime.strptime(ts_str.split(".")[0], "%d-%b-%Y %H:%M:%S")
            timestamp = self.localize(timestamp)
        except ValueError:
            return None

        # Strip trailing dot from FQDN
        domain = domain.rstrip(".")

        return CanonicalEvent(
            source_type=self.source_type,
            timestamp=timestamp,
            domain=domain,
            src_ip=client_ip,
            parser_version=self.parser_version,
        )
