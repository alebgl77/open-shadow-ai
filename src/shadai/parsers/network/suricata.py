"""Suricata EVE metadata adapters; DNS replies never become client observations."""

from shadai.parsers.network.common import MAX_HOSTS, NetworkParser, RecordRejected, json_record, unique_hosts


class SuricataParser(NetworkParser):
    def _parse(self, line):
        record = json_record(line)
        kind = record.get("event_type")
        if kind not in {"dns", "tls", "http", "quic"}:
            return []
        details = record.get(kind)
        if not isinstance(details, dict):
            raise RecordRejected()
        if kind == "dns":
            if details.get("type") in {"answer", "response"} or details.get("qr") is True:
                self.stats.dns_response_filtered += 1
                return []
            if details.get("type") not in {"query", "request"}:
                raise RecordRejected()
            if "queries" in details:
                questions = details["queries"]
                if not isinstance(questions, list) or len(questions) > MAX_HOSTS:
                    raise RecordRejected()
                hosts = unique_hosts([question["rrname"] for question in questions])
            else:
                hosts = unique_hosts(details.get("rrname"))
        else:
            hosts = unique_hosts(details.get("hostname" if kind == "http" else "sni"), http=kind == "http")
            # Current QUIC EVE documents extension type IDs. An offered ECH extension
            # may be GREASE; do not promote the outer SNI to a destination claim.
            if kind == "quic" and any(
                extension.get("type") == 0xFE0D for extension in details.get("extensions", [])
            ):
                self.stats.ech_offered += 1
                hosts = []
        flow = record.get("flow_id")
        if isinstance(flow, bool) or not isinstance(flow, (int, str)) or not 1 <= len(str(flow)) <= 200:
            raise RecordRejected()
        return self.make_events(
            format_name="suricata", timestamp=record["timestamp"], epoch=False,
            identity=[flow, record.get("tx_id"), record.get("pcap_cnt"), record.get("src_port")],
            src_ip=record["src_ip"], dst_ip=record["dest_ip"], dst_port=record["dest_port"],
            protocol=kind.upper(), hosts=hosts,
            http_method=details.get("http_method", "") if kind == "http" else "",
        )
