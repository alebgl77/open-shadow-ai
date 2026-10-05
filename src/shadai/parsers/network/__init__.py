"""Passive network metadata adapters (never derive identity from IP addresses)."""

from shadai.parsers.network.common import NetworkParser
from shadai.parsers.network.suricata import SuricataParser
from shadai.parsers.network.tshark import TSharkParser
from shadai.parsers.network.zeek import ZeekParser

FORMATS = ("zeek-dns", "zeek-tls", "zeek-http", "zeek-quic", "suricata", "tshark")


def network_parser(format_name: str, sensor_id: str, tenant_id: str = "", site_id: str = "default") -> NetworkParser:
    options = {"tenant_id": tenant_id, "site_id": site_id}
    if format_name.startswith("zeek-") and format_name in FORMATS:
        return ZeekParser(sensor_id, format_name.removeprefix("zeek-").upper(), **options)
    if format_name == "suricata":
        return SuricataParser(sensor_id, **options)
    if format_name == "tshark":
        return TSharkParser(sensor_id, **options)
    raise ValueError("Unknown network metadata format")
