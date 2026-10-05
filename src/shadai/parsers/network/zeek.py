"""Adapters for Zeek's dns, ssl, http and current quic JSON logs."""

from shadai.parsers.network.common import NetworkParser, RecordRejected, json_record, unique_hosts


class ZeekParser(NetworkParser):
    def __init__(self, sensor_id: str, protocol: str, **kwargs):
        super().__init__(sensor_id, **kwargs)
        if protocol not in {"DNS", "TLS", "HTTP", "QUIC"}:
            raise ValueError("Unknown Zeek protocol")
        self.protocol = protocol

    def _parse(self, line):
        record = json_record(line)
        uid = record.get("uid")
        if not isinstance(uid, str) or not 1 <= len(uid) <= 200:
            raise RecordRejected()
        field = {"DNS": "query", "TLS": "server_name", "QUIC": "server_name", "HTTP": "host"}[self.protocol]
        hosts = unique_hosts(record.get(field), http=self.protocol == "HTTP")
        return self.make_events(
            format_name="zeek-" + self.protocol.lower(), timestamp=record["ts"], epoch=True,
            identity=[uid, record.get("trans_id"), record.get("trans_depth"), record.get("id.orig_p")],
            src_ip=record["id.orig_h"], dst_ip=record["id.resp_h"], dst_port=record["id.resp_p"],
            protocol=self.protocol, hosts=hosts,
            http_method=record.get("method", "") if self.protocol == "HTTP" else "",
        )
