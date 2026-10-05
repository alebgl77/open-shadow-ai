"""Bounded, metadata-only primitives shared by passive network adapters."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation

from shadai.models.event import CanonicalEvent

MAX_LINE_BYTES = 256 * 1024
MAX_HOSTS = 64
EVENT_FIELDS = (
    "event_id", "timestamp", "source_type", "collector_id", "tenant_id", "site_id",
    "src_ip", "dst_ip", "dst_port", "protocol", "domain", "sni", "url_host",
    "http_method", "parser_version", "evidence_type",
)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SENSOR = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")


class RecordRejected(ValueError):  # noqa: N818
    """Deliberately generic: source records must never appear in errors or logs."""

    def __init__(self):
        super().__init__("invalid_metadata_record")


@dataclass
class NetworkStats:
    parsed: int = 0
    emitted: int = 0
    rejected: int = 0
    no_hostname: int = 0
    dns_response_filtered: int = 0
    ech_offered: int = 0


def normalize_host(value: object, *, http: bool = False) -> str:
    if value in (None, "", "-"):
        return ""
    if not isinstance(value, str) or len(value) > 1024:
        raise RecordRejected()
    if any(char.isspace() or ord(char) < 32 or char in "/?#@\\" for char in value):
        raise RecordRejected()
    if http and value.startswith("["):
        address, close, port = value[1:].partition("]")
        if not close or (port and (not port.startswith(":") or not port[1:].isdecimal()
                                   or not 1 <= int(port[1:]) <= 65535)):
            raise RecordRejected()
        normalize_ip(address)
        return ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return ""
    if http and ":" in value:
        # Hostnames only; IP literals cannot identify a service.
        value, separator, port = value.rpartition(":")
        if not separator or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise RecordRejected()
    value = value.removesuffix(".").lower()
    try:
        host = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise RecordRejected() from None
    if not host or len(host) > 253 or any(not _LABEL.fullmatch(label) for label in host.split(".")):
        raise RecordRejected()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return ""


def normalize_ip(value: object) -> str:
    if not isinstance(value, str) or "%" in value:
        raise RecordRejected()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise RecordRejected() from None


def port_number(value: object) -> int:
    if isinstance(value, bool):
        raise RecordRejected()
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        raise RecordRejected() from None
    if str(port) != str(value) or not 0 <= port <= 65535:
        raise RecordRejected()
    return port


def observation_time(value: object, *, epoch: bool = False) -> datetime:
    try:
        if epoch:
            seconds = Decimal(str(value))
            if not seconds.is_finite() or not 0 <= seconds <= Decimal("253402300799"):
                raise RecordRejected()
            # Decimal preserves decimal epochs; float conversion loses microseconds.
            micros = int(seconds * 1_000_000)
            return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=micros)
        if not isinstance(value, str):
            raise RecordRejected()
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise RecordRejected()
        return parsed.astimezone(UTC)
    except (ValueError, TypeError, OverflowError, InvalidOperation):
        raise RecordRejected() from None


def json_record(line: str) -> dict:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise RecordRejected()
    try:
        record = json.loads(line, parse_float=Decimal)
    except (ValueError, RecursionError):
        raise RecordRejected() from None
    if not isinstance(record, dict):
        raise RecordRejected()
    return record


def unique_hosts(values: object, *, http: bool = False) -> list[str]:
    if not isinstance(values, list):
        values = [values]
    if len(values) > MAX_HOSTS:
        raise RecordRejected()
    return sorted({host for value in values if (host := normalize_host(value, http=http))})


def event_metadata(event: CanonicalEvent) -> dict:
    """Whitelist metadata at the serialization boundary; never emit other defaults."""
    return event.model_dump(mode="json", include=set(EVENT_FIELDS))


class NetworkParser:
    parser_version = "1.0.0"

    def __init__(self, sensor_id: str, tenant_id: str = "", site_id: str = "default"):
        if not _SENSOR.fullmatch(sensor_id):
            raise ValueError("sensor_id must contain 1-200 ASCII letters, numbers, _, ., :, or -")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{0,100}", tenant_id) or not _SENSOR.fullmatch(site_id):
            raise ValueError("Invalid tenant/site identifier")
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id
        self.site_id = site_id
        self.stats = NetworkStats()

    def make_events(
        self, *, format_name: str, timestamp: object, epoch: bool, identity: object,
        src_ip: object, dst_ip: object, dst_port: object, protocol: str, hosts: list[str],
        http_method: object = "",
    ) -> list[CanonicalEvent]:
        at = observation_time(timestamp, epoch=epoch)
        source, destination = normalize_ip(src_ip), normalize_ip(dst_ip)
        port = port_number(dst_port)
        if not isinstance(http_method, str) or (http_method and not re.fullmatch(r"[A-Z]{1,20}", http_method)):
            raise RecordRejected()
        if not hosts:
            self.stats.no_hostname += 1
            if protocol not in {"TLS", "QUIC"}:
                return []
            hosts = [""]
        events = []
        for host in hosts:
            # File path, import time, normalized_at, and secrets are intentionally absent.
            key = json.dumps(
                [self.sensor_id, self.tenant_id, self.site_id, format_name, str(timestamp),
                 identity, source, destination, port, protocol, host, http_method],
                ensure_ascii=True, separators=(",", ":"), default=str,
            )
            events.append(CanonicalEvent(
                event_id=uuid.uuid5(uuid.NAMESPACE_URL, "shadai:passive-network:" + key),
                timestamp=at, normalized_at=at, source_type="network", evidence_type="observation",
                collector_id=self.sensor_id, tenant_id=self.tenant_id, site_id=self.site_id,
                src_ip=source, dst_ip=destination, dst_port=port, protocol=protocol, domain=host,
                sni=host if protocol in {"TLS", "QUIC"} else "",
                url_host=host if protocol == "HTTP" else "", http_method=http_method,
                parser_version=self.parser_version,
            ))
        return events

    def parse_record(self, line: str) -> list[CanonicalEvent]:
        if not line.strip() or line.startswith("#"):
            return []
        try:
            events = self._parse(line)
        except (ValueError, KeyError, TypeError, OverflowError, AttributeError, RecursionError):
            self.stats.rejected += 1
            raise RecordRejected() from None
        self.stats.parsed += 1
        self.stats.emitted += len(events)
        return events

    def _parse(self, line: str) -> list[CanonicalEvent]:
        raise NotImplementedError
