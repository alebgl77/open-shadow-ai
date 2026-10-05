"""Read TShark header-bearing CSV/TSV exports, retaining every bounded host occurrence."""

import csv

from shadai.parsers.network.common import MAX_HOSTS, MAX_LINE_BYTES, NetworkParser, RecordRejected, unique_hosts

TSHARK_FIELDS = (
    "frame.time_epoch", "frame.number", "frame.protocols", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.dstport", "udp.dstport", "dns.flags.response", "dns.qry.name", "tls.handshake.type",
    "tls.handshake.extensions_server_name", "http.host", "http.request.method",
)
ECH_FIELD = "tls.handshake.extension.type"


def occurrences(value: str) -> list[str]:
    values = value.split(",") if value else []
    if len(values) > MAX_HOSTS:
        raise RecordRejected()
    return values


def single(values: list[str]) -> str:
    if len(values) != 1:
        raise RecordRejected()
    return values[0]


class TSharkParser(NetworkParser):
    def __init__(self, sensor_id: str, **kwargs):
        super().__init__(sensor_id, **kwargs)
        self.header = None
        self.delimiter = "\t"

    def _parse(self, line):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise RecordRejected()
        if self.header is None:
            self.delimiter = "\t" if "\t" in line else ","
        try:
            row = next(csv.reader([line], delimiter=self.delimiter, strict=True))
        except csv.Error:
            raise RecordRejected() from None
        if self.header is None:
            if len(row) != len(set(row)) or not {"frame.time_epoch", "frame.number", "frame.protocols"} <= set(row):
                raise RecordRejected()
            self.header = row
            return []
        if len(row) != len(self.header):
            raise RecordRejected()
        record = dict(zip(self.header, row, strict=True))
        protocols = set(record["frame.protocols"].split(":"))
        if "dns" in protocols:
            response = occurrences(record.get("dns.flags.response", ""))
            if not response or any(flag not in {"0", "1", "True", "False"} for flag in response):
                raise RecordRejected()
            if any(flag in {"1", "True"} for flag in response):
                self.stats.dns_response_filtered += 1
                return []
            protocol = "DNS"
            hosts = unique_hosts(occurrences(record.get("dns.qry.name", "")))
            method = ""
        elif "http" in protocols and record.get("http.request.method"):
            protocol = "HTTP"
            hosts = unique_hosts(occurrences(record.get("http.host", "")), http=True)
            methods = occurrences(record.get("http.request.method", ""))
            # Multiplexed requests cannot safely associate different methods with hosts.
            method = single(list(set(methods)))
        elif {"tls", "quic"} & protocols:
            hello = occurrences(record.get("tls.handshake.type", ""))
            if hello and "1" not in hello:
                return []
            protocol = "QUIC" if "quic" in protocols else "TLS"
            method = ""
            hosts = unique_hosts(occurrences(record.get("tls.handshake.extensions_server_name", "")))
            extensions = occurrences(record.get(ECH_FIELD, ""))
            try:
                ech = any(int(value, 16 if value.lower().startswith("0x") else 10) == 0xFE0D for value in extensions)
            except ValueError:
                raise RecordRejected() from None
            if ech:
                self.stats.ech_offered += 1
                hosts = []
        else:
            return []
        source = occurrences(record.get("ip.src", "")) + occurrences(record.get("ipv6.src", ""))
        destination = occurrences(record.get("ip.dst", "")) + occurrences(record.get("ipv6.dst", ""))
        ports = occurrences(record.get("tcp.dstport", "")) + occurrences(record.get("udp.dstport", ""))
        frame = single(occurrences(record["frame.number"]))
        if not frame.isascii() or not frame.isdecimal():
            raise RecordRejected()
        return self.make_events(
            format_name="tshark", timestamp=record["frame.time_epoch"], epoch=True,
            identity=frame, src_ip=single(source), dst_ip=single(destination), dst_port=single(ports),
            protocol=protocol, hosts=hosts, http_method=method,
        )
