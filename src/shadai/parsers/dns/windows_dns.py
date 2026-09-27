"""Windows DNS Server debug log parser."""

from __future__ import annotations

import re
from datetime import datetime

from shadai.models.event import CanonicalEvent
from shadai.parsers.base import BaseParser, register_parser
from shadai.utils.validators import sanitize_log_input

# Windows DNS debug log format:
# 3/27/2026 2:23:45 PM 0BE0 PACKET  00000012345ABCDE UDP Rcv 192.168.1.100  0001   Q [0001   D   NOERROR] A
# (4)chat(6)openai(3)com(0)
_WIN_DNS_RE = re.compile(
    r"(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+"
    r"\S+\s+PACKET\s+\S+\s+(?:UDP|TCP)\s+(?:Rcv|Snd)\s+"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r".*?\s+Q\s+.*?\]\s+\S+\s+(.*?)$"
)

# Pattern to decode Windows DNS wire-format domain: (4)chat(6)openai(3)com(0)
_WIRE_LABEL_RE = re.compile(r"\((\d+)\)([^(]*)")


def _decode_wire_domain(wire: str) -> str:
    """Decode Windows DNS wire-format domain name."""
    parts = []
    for match in _WIRE_LABEL_RE.finditer(wire):
        length, label = int(match.group(1)), match.group(2)
        if length == 0:
            break
        parts.append(label[:length])
    return ".".join(parts) if parts else wire.strip()


@register_parser("windows_dns_debug")
class WindowsDNSDebugParser(BaseParser):
    source_type = "dns"
    parser_version = "1.0.0"

    def parse(self, raw_line: str) -> CanonicalEvent | None:
        line = sanitize_log_input(raw_line.strip())
        if not line or "PACKET" not in line or " Q " not in line:
            return None

        match = _WIN_DNS_RE.search(line)
        if not match:
            return None

        ts_str, client_ip, wire_domain = match.group(1), match.group(2), match.group(3)

        try:
            timestamp = datetime.strptime(ts_str, "%m/%d/%Y %I:%M:%S %p")
            timestamp = self.localize(timestamp)
        except ValueError:
            return None

        domain = _decode_wire_domain(wire_domain)
        if not domain:
            return None

        return CanonicalEvent(
            source_type=self.source_type,
            timestamp=timestamp,
            domain=domain,
            src_ip=client_ip,
            parser_version=self.parser_version,
        )
