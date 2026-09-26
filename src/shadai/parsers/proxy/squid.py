"""Squid access.log parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# Squid access.log format:
# 1711545825.123    234 192.168.1.100 TCP_MISS/200 12345 GET https://chat.openai.com/backend-api/conversation -
# DIRECT/104.18.2.1 application/json
_SQUID_RE = re.compile(
    r"(\d+\.\d+)\s+"  # timestamp (UNIX epoch)
    r"(\d+)\s+"  # elapsed ms
    r"(\S+)\s+"  # client IP
    r"(\S+)/(\d+)\s+"  # result_code/status
    r"(\d+)\s+"  # bytes
    r"(\S+)\s+"  # method
    r"(\S+)\s+"  # URL
    r"(\S+)\s+"  # ident
    r"(\S+)/(\S+)\s*"  # hierarchy/server
)


@register_parser("squid_access_log")
class SquidAccessLogParser(BaseParser):
    source_type = "proxy"
    parser_version = "1.0.0"

    def parse(self, raw_line: str) -> CanonicalEvent | None:
        line = sanitize_log_input(raw_line.strip())
        if not line or line.startswith("#"):
            return None

        match = _SQUID_RE.match(line)
        if not match:
            return None

        ts_epoch = float(match.group(1))
        client_ip = match.group(3)
        response_bytes = int(match.group(6))
        method = match.group(7).upper()
        url_raw = match.group(8)

        timestamp = datetime.fromtimestamp(ts_epoch, tz=UTC)

        # Parse URL
        if method == "CONNECT":
            # CONNECT host:port — HTTPS tunnel
            host_port = url_raw.split(":")
            domain = host_port[0]
            url_host = domain
            url_path = ""
            dst_port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            parsed = urlparse(url_raw)
            domain = parsed.hostname or ""
            url_host = domain
            url_path = parsed.path or ""
            dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        return CanonicalEvent(
            source_type=self.source_type,
            timestamp=timestamp,
            src_ip=client_ip,
            domain=domain,
            url_host=url_host,
            url_path=url_path,
            http_method=method,
            dst_port=dst_port,
            bytes_in=response_bytes,
            parser_version=self.parser_version,
        )
