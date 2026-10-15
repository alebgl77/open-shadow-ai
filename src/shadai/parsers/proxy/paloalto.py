"""Palo Alto Networks PAN-OS URL filtering log parser."""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, datetime, timedelta

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# PAN-OS URL log (syslog CSV):
# Fields vary by PAN-OS version but key positions are relatively stable.
# We parse key=value syslog format which is more common.

# Key-value syslog format:
# <14>1 2026-03-27T14:23:45.000Z PA-5220 - - - - src=192.168.1.100 dst=104.18.2.1 ... url=chat.openai.com/backend-
# api sport=12345 dport=443 ...
_RFC5424_TIMESTAMP = re.compile(r"^<\d{1,3}>1 (?P<timestamp>\S+)(?: |$)")
_ISO_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_LOCAL_TIMESTAMP = re.compile(r"[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}")
_BSD_TIMESTAMP = re.compile(r"[A-Z][a-z]{2} {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}")


@register_parser("paloalto_url_log")
class PaloAltoURLLogParser(BaseParser):
    source_type = "proxy"
    parser_version = "1.1.0"

    def parse(self, raw_line: str) -> CanonicalEvent | None:
        line = sanitize_log_input(raw_line.strip())
        if not line:
            return None

        # Try key=value parsing (most common PAN-OS syslog format)
        fields = self._parse_kv(line)
        if not fields:
            # Fallback: try CSV
            fields = self._parse_csv(line)

        if not fields or "url" not in fields:
            return None

        # Parse timestamp
        ts_str = next((fields[key] for key in ("receive_time", "time_generated", "timestamp") if key in fields), None)
        header_time = ts_str is None
        if header_time:
            header = _RFC5424_TIMESTAMP.match(line)
            ts_str = header.group("timestamp") if header else ""
        timestamp = self._parse_timestamp(ts_str, rfc5424=header_time)

        url_raw = fields.get("url", "")
        domain = fields.get("hostname", "") or url_raw.split("/")[0]
        url_path = "/" + "/".join(url_raw.split("/")[1:]) if "/" in url_raw else ""

        return CanonicalEvent(
            source_type=self.source_type,
            timestamp=timestamp,
            src_ip=fields.get("src", fields.get("srcip", "")),
            dst_ip=fields.get("dst", fields.get("dstip", "")),
            dst_port=int(fields.get("dport", fields.get("dstport", "0")) or 0),
            domain=domain,
            url_host=domain,
            url_path=url_path,
            http_method=fields.get("method", "").upper() or "",
            bytes_in=int(fields.get("bytes_received", fields.get("rcvdbyte", "0")) or 0),
            bytes_out=int(fields.get("bytes_sent", fields.get("sentbyte", "0")) or 0),
            username=fields.get("srcuser", fields.get("user", "")),
            parser_version=self.parser_version,
        )

    def _parse_kv(self, line: str) -> dict[str, str] | None:
        """Parse key=value or key="value" format."""
        fields = {}
        # Simple KV parser handling quoted and unquoted values
        i = 0
        while i < len(line):
            # Find key
            eq_pos = line.find("=", i)
            if eq_pos == -1:
                break
            # Walk back to find key start (space or line start)
            key_start = line.rfind(" ", i, eq_pos)
            key_start = key_start + 1 if key_start != -1 else i
            key = line[key_start:eq_pos].strip()

            # Find value
            val_start = eq_pos + 1
            if val_start < len(line) and line[val_start] == '"':
                # Quoted value
                val_end = line.find('"', val_start + 1)
                if val_end == -1:
                    val_end = len(line)
                fields[key] = line[val_start + 1 : val_end]
                i = val_end + 1
            else:
                # Unquoted value — ends at next space
                val_end = line.find(" ", val_start)
                if val_end == -1:
                    val_end = len(line)
                fields[key] = line[val_start:val_end]
                i = val_end

        return fields if fields else None

    def _parse_csv(self, line: str) -> dict[str, str] | None:
        """Fallback CSV parsing for comma-delimited PAN-OS logs."""
        try:
            reader = csv.reader(io.StringIO(line))
            parts = next(reader)
            if len(parts) < 30:
                return None
            return {
                "receive_time": parts[1] if len(parts) > 1 else "",
                "srcip": parts[7] if len(parts) > 7 else "",
                "dstip": parts[8] if len(parts) > 8 else "",
                "srcport": parts[24] if len(parts) > 24 else "",
                "dstport": parts[25] if len(parts) > 25 else "",
                "url": parts[31] if len(parts) > 31 else "",
                "user": parts[12] if len(parts) > 12 else "",
            }
        except Exception:
            return None

    def _parse_timestamp(self, ts_str: str, *, rfc5424: bool = False) -> datetime:
        try:
            if _ISO_TIMESTAMP.fullmatch(ts_str):
                # fromisoformat alone normalizes invalid offsets and accepts unsupported ISO forms.
                value = datetime.fromisoformat(ts_str)
            elif not rfc5424 and _LOCAL_TIMESTAMP.fullmatch(ts_str):
                # receive_time/time_generated use the firewall's local clock.
                value = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
            elif not rfc5424 and _BSD_TIMESTAMP.fullmatch(ts_str):
                # BSD syslog omits the year: retain the existing most-recent-date convention.
                now = datetime.now(UTC)
                value = datetime.strptime(f"{now.astimezone(self.timezone).year} {ts_str}", "%Y %b %d %H:%M:%S")
                if self.localize(value) > now + timedelta(days=1):
                    value = value.replace(year=value.year - 1)
            else:
                raise ValueError("Unsupported timestamp format")
            return self.localize(value)
        except (ValueError, OverflowError):
            raise ValueError("Invalid or missing Palo Alto event timestamp") from None
