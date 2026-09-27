"""FortiGate web filter log parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# FortiGate web filter log (key=value format):
# date=2026-03-27 time=14:23:45 devname="FG-200F" logid="0316013056" type="utm" subtype="webfilter"
# ... srcip=192.168.1.100 dstip=104.18.2.1 hostname="chat.openai.com" url="/backend-api/conversation"
# sentbyte=4500 rcvdbyte=12000 eventtime=1774617825123456789 tz="+0100" ...
#
# date/time are the device's local wall clock. FortiOS 6.2+ adds eventtime (epoch; the unit
# varies by release) and tz (UTC offset). Both are preferred over the source's configured zone.

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
_TZ_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
# Epoch digit count -> divisor: nanoseconds, microseconds, milliseconds, seconds.
_EPOCH_UNITS = ((18, 1_000_000_000), (15, 1_000_000), (12, 1_000), (1, 1))


@register_parser("fortigate_webfilter")
class FortiGateWebFilterParser(BaseParser):
    source_type = "proxy"
    parser_version = "1.1.0"

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

        timestamp = self._parse_timestamp(fields)

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

    def _parse_timestamp(self, fields: dict[str, str]) -> datetime:
        eventtime = fields.get("eventtime", "")
        if eventtime.isdigit():
            divisor = next(divisor for digits, divisor in _EPOCH_UNITS if len(eventtime) >= digits)
            try:
                return datetime.fromtimestamp(int(eventtime) / divisor, tz=UTC)
            except (OverflowError, OSError, ValueError):
                pass
        date_str, time_str = fields.get("date", ""), fields.get("time", "")
        if date_str and time_str:
            try:
                local = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return datetime.now(UTC)
            offset = _TZ_RE.match(fields.get("tz", "").strip())
            if offset:
                sign = -1 if offset[1] == "-" else 1
                delta = timedelta(hours=int(offset[2]), minutes=int(offset[3]))
                if delta < timedelta(hours=24):
                    return local.replace(tzinfo=timezone(sign * delta)).astimezone(UTC)
            return self.localize(local)
        return datetime.now(UTC)
