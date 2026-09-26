"""FortiGate web filter log parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# FortiGate web filter log (key=value format):
# date=2026-03-27 time=14:23:45 devname="FG-200F" logid="0316013056" type="utm" subtype="webfilter"
# ... srcip=192.168.1.100 dstip=104.18.2.1 hostname="chat.openai.com" url="/backend-api/conversation"
# sentbyte=4500 rcvdbyte=12000 ...

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


@register_parser("fortigate_webfilter")
class FortiGateWebFilterParser(BaseParser):
    source_type = "proxy"
    parser_version = "1.0.0"

    def parse(self, raw_line: str) -> CanonicalEvent | None:
        line = sanitize_log_input(raw_line.strip())
        if not line:
            return None

        fields = {}
        for match in _KV_RE.finditer(line):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            fields[key] = value

        if not fields:
            return None

        # Need at least hostname or url to be useful
        hostname = fields.get("hostname", "")
        url = fields.get("url", "")
        if not hostname and not url:
            return None

        # Parse timestamp
        date_str = fields.get("date", "")
        time_str = fields.get("time", "")
        timestamp = self._parse_timestamp(date_str, time_str)

        domain = hostname or url.split("/")[0]
        url_path = url if url.startswith("/") else ""

        return CanonicalEvent(
            source_type=self.source_type,
            timestamp=timestamp,
            src_ip=fields.get("srcip", ""),
            dst_ip=fields.get("dstip", ""),
            dst_port=int(fields.get("dstport", "0") or 0),
            domain=domain,
            url_host=domain,
            url_path=url_path,
            http_method=fields.get("method", "").upper() or "",
            bytes_in=int(fields.get("rcvdbyte", "0") or 0),
            bytes_out=int(fields.get("sentbyte", "0") or 0),
            username=fields.get("user", fields.get("srcname", "")),
            protocol=fields.get("proto", fields.get("service", "")),
            parser_version=self.parser_version,
        )

    def _parse_timestamp(self, date_str: str, time_str: str) -> datetime:
        if date_str and time_str:
            try:
                return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            except ValueError:
                pass
        return datetime.now(UTC)
