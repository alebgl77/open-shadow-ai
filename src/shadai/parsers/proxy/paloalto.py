"""Palo Alto Networks PAN-OS URL filtering log parser."""

from __future__ import annotations

import csv
import io
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
        ts_str = fields.get("receive_time") or fields.get("time_generated") or fields.get("timestamp", "")
        timestamp = self._parse_timestamp(ts_str)

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

    def _parse_timestamp(self, ts_str: str) -> datetime:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(ts_str, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        try:
            # receive_time/time_generated use the firewall's local clock.
            return self.localize(datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            pass
        now = datetime.now(UTC)
        try:
            # BSD syslog timestamps omit the year: take the most recent one not in the future.
            local = datetime.strptime(f"{now.astimezone(self.timezone).year} {ts_str}", "%Y %b %d %H:%M:%S")
            if self.localize(local) > now + timedelta(days=1):
                local = local.replace(year=local.year - 1)
        except ValueError:
            return now
        return self.localize(local)
