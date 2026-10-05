"""Synthetic metadata only: parser attribution and replay/privacy boundaries."""

import csv
import io
import json
from datetime import UTC

import pytest

from shadai.parsers.network import network_parser
from shadai.parsers.network.common import MAX_HOSTS, MAX_LINE_BYTES, RecordRejected, event_metadata
from shadai.parsers.network.tshark import ECH_FIELD, TSHARK_FIELDS


def zeek(**updates):
    record = {"ts": "1780000000.123456789", "uid": "synthetic-flow-1", "id.orig_h": "192.0.2.10",
              "id.resp_h": "198.51.100.20", "id.orig_p": 50100, "id.resp_p": 443,
              "query": "API.OpenAI.com.", "server_name": "API.OpenAI.com.", "host": "API.OpenAI.com.:80",
              "method": "POST", "uri": "/secret-prompt?token=secret", "user_agent": "secret-browser",
              "username": "never-retained"}
    return record | updates


def eve(kind="tls", **updates):
    record = {"timestamp": "2026-05-28T21:20:00.123456+0000", "flow_id": 100, "tx_id": 1,
              "src_ip": "2001:db8::10", "dest_ip": "2001:db8::20", "dest_port": 443,
              "src_port": 50100, "event_type": kind, "proto": "UDP" if kind == "quic" else "TCP",
              kind: {"sni": "Claude.AI.", "hostname": "Claude.AI.:443", "http_method": "GET"}}
    return record | updates


def tshark_rows(**updates):
    record = dict.fromkeys((*TSHARK_FIELDS, ECH_FIELD), "")
    record.update({"frame.time_epoch": "1780000000.123456789", "frame.number": "1",
                   "frame.protocols": "eth:ip:tcp:tls", "ip.src": "192.0.2.10",
                   "ip.dst": "198.51.100.20", "tcp.dstport": "443", "tls.handshake.type": "1",
                   "tls.handshake.extensions_server_name": "API.OpenAI.com."})
    record.update(updates)
    out = io.StringIO()
    writer = csv.writer(out, delimiter="\t")
    writer.writerow(record)
    writer.writerow(record.values())
    return out.getvalue().splitlines()


def parse_tshark(**updates):
    parser = network_parser("tshark", "test-sensor")
    header, row = tshark_rows(**updates)
    assert parser.parse_record(header) == []
    return parser, parser.parse_record(row)


@pytest.mark.parametrize("format_name,protocol", [
    ("zeek-dns", "DNS"), ("zeek-tls", "TLS"), ("zeek-http", "HTTP"), ("zeek-quic", "QUIC"),
])
def test_zeek_metadata_only(format_name, protocol):
    parser = network_parser(format_name, "office-sensor")
    event, = parser.parse_record(json.dumps(zeek()))
    assert event.protocol == protocol
    assert event.domain == "api.openai.com"
    assert event.source_type == "network" and event.evidence_type == "observation"
    assert event.timestamp.tzinfo is UTC and event.timestamp.microsecond == 123456
    assert event.normalized_at == event.timestamp
    assert event.collector_id == "office-sensor" and event.tenant_id == ""
    assert not any((event.user_id, event.username, event.device_id, event.hostname, event.model, event.provider))
    assert event.input_tokens is event.output_tokens is event.cost_usd is None
    output = json.dumps(event_metadata(event))
    assert all(secret not in output for secret in ("secret", "never-retained", "normalized_at", "uri", "user_agent"))
    assert event.sni == (event.domain if protocol in {"TLS", "QUIC"} else "")
    assert event.url_host == (event.domain if protocol == "HTTP" else "")


@pytest.mark.parametrize("kind", ["tls", "http", "quic"])
def test_suricata_ipv6(kind):
    event, = network_parser("suricata", "test-sensor").parse_record(json.dumps(eve(kind)))
    assert event.domain == "claude.ai" and event.protocol == kind.upper()
    assert event.src_ip == "2001:db8::10" and event.dst_ip == "2001:db8::20"


@pytest.mark.parametrize("details", [
    {"version": 2, "type": "query", "rrname": "api.openai.com"},
    {"version": 3, "type": "request", "queries": [{"rrname": "api.openai.com"}, {"rrname": "Claude.AI."}]},
])
def test_suricata_dns_query_versions(details):
    events = network_parser("suricata", "test-sensor").parse_record(json.dumps(eve("dns", dns=details)))
    assert {event.domain for event in events} == ({"api.openai.com"} if details["version"] == 2
                                                else {"api.openai.com", "claude.ai"})


def test_dns_responses_filtered_without_reverse_address_attribution():
    parser = network_parser("suricata", "test-sensor")
    record = eve("dns", src_ip="198.51.100.53", dest_ip="192.0.2.10",
                 dns={"type": "answer", "qr": True, "queries": [{"rrname": "api.openai.com"}]})
    assert parser.parse_record(json.dumps(record)) == []
    assert parser.stats.dns_response_filtered == 1
    parser, events = parse_tshark(**{"frame.protocols": "eth:ip:udp:dns", "dns.flags.response": "1",
                                    "dns.qry.name": "api.openai.com"})
    assert events == [] and parser.stats.dns_response_filtered == 1


def test_tshark_multiple_hosts_csv_and_exact_epoch():
    parser, events = parse_tshark(**{"tls.handshake.extensions_server_name": "Claude.AI.,API.OpenAI.com.,claude.ai"})
    assert [event.domain for event in events] == ["api.openai.com", "claude.ai"]
    assert len({event.event_id for event in events}) == 2
    assert events[0].timestamp.microsecond == 123456 and parser.stats.emitted == 2
    header, row = tshark_rows()
    source = [next(csv.reader([line], delimiter="\t")) for line in (header, row)]
    out = io.StringIO()
    csv.writer(out).writerows(source)
    parser = network_parser("tshark", "test-sensor")
    events = [event for line in out.getvalue().splitlines() for event in parser.parse_record(line)]
    assert events[0].domain == "api.openai.com"


def test_tshark_ipv6_dns_and_http():
    _, dns = parse_tshark(**{"frame.protocols": "eth:ipv6:udp:dns", "ip.src": "", "ip.dst": "",
                            "ipv6.src": "2001:db8::10", "ipv6.dst": "2001:db8::20", "tcp.dstport": "",
                            "udp.dstport": "53", "dns.flags.response": "0",
                            "dns.qry.name": "API.OpenAI.com.,Claude.AI."})
    assert len(dns) == 2 and all(event.protocol == "DNS" for event in dns)
    _, http = parse_tshark(**{"frame.protocols": "eth:ip:tcp:http", "http.host": "API.OpenAI.com.:80,Claude.AI:80",
                             "http.request.method": "GET,GET"})
    assert {event.domain for event in http} == {"api.openai.com", "claude.ai"}
    assert all(event.http_method == "GET" and event.protocol == "HTTP" for event in http)


def test_quic_requires_dissector_and_nameless_observations():
    _, events = parse_tshark(**{"frame.protocols": "eth:ip:udp", "tcp.dstport": "", "udp.dstport": "443"})
    assert events == []
    parser, events = parse_tshark(**{"frame.protocols": "eth:ip:udp:quic:tls", "tcp.dstport": "", "udp.dstport": "443",
                                    "tls.handshake.extensions_server_name": ""})
    assert events[0].protocol == "QUIC" and not events[0].domain and parser.stats.no_hostname == 1
    events = network_parser("zeek-quic", "test-sensor").parse_record(json.dumps(zeek(server_name=None)))
    assert len(events) == 1 and events[0].domain == ""


@pytest.mark.parametrize("extension", ["0xfe0d", "65037", "0,65037,10"])
def test_ech_offer_is_not_acceptance_and_suppresses_outer_sni(extension):
    parser, events = parse_tshark(**{ECH_FIELD: extension})
    assert parser.stats.ech_offered == 1 and parser.stats.no_hostname == 1
    assert events[0].domain == events[0].sni == ""
    parser = network_parser("suricata", "test-sensor")
    event, = parser.parse_record(json.dumps(eve("quic", quic={"sni": "api.openai.com",
                                                             "extensions": [{"type": 65037}]})))
    assert not event.domain and parser.stats.ech_offered == 1


@pytest.mark.parametrize("value", ["api.openai.com.evil.test", "арi.openai.com"])
def test_suffix_and_homoglyph_not_normalized_into_catalog_domain(value):
    event, = network_parser("zeek-tls", "test-sensor").parse_record(json.dumps(zeek(server_name=value)))
    assert event.domain != "api.openai.com" and not event.domain.endswith(".api.openai.com")


@pytest.mark.parametrize("value", ["https://api.openai.com/prompt", "user@api.openai.com", "api.openai.com?secret",
                                   "api.openai.com/secret", "api.openai.com..", "bad_name.test", "api.openai.com\n"])
def test_invalid_host_never_logged(value, caplog):
    with pytest.raises(RecordRejected, match="^invalid_metadata_record$"):
        network_parser("zeek-tls", "test-sensor").parse_record(json.dumps(zeek(server_name=value)))
    assert value not in caplog.text


@pytest.mark.parametrize("format_name,field,value", [("zeek-tls", "server_name", "198.51.100.20"),
                                                    ("zeek-http", "host", "[2001:db8::20]:443")])
def test_ip_host_has_no_service_attribution(format_name, field, value):
    parser = network_parser(format_name, "test-sensor")
    events = parser.parse_record(json.dumps(zeek(**{field: value})))
    assert all(not event.domain for event in events) and parser.stats.no_hostname == 1


@pytest.mark.parametrize("updates", [{"ip.src": "192.0.2.10,192.0.2.20"}, {"ipv6.src": "2001:db8::10"},
                                    {"ip.dst": "invalid"}, {"udp.dstport": "443"},
                                    {"http.request.method": "GET,POST", "frame.protocols": "eth:ip:tcp:http"}])
def test_multilayer_or_invalid_address_and_method_rejected(updates):
    with pytest.raises(RecordRejected):
        parse_tshark(**updates)


def test_replay_stable_ids_and_distinct_observation_identity():
    record = zeek()
    def parse(record, sensor="test-sensor"):
        return network_parser("zeek-tls", sensor).parse_record(json.dumps(record))[0]
    first = parse(record)
    assert first.event_id == parse(record).event_id
    for updates in ({"uid": "other-flow"}, {"ts": "1780000000.123456790"}, {"id.orig_h": "192.0.2.11"}):
        assert first.event_id != parse(record | updates).event_id
    assert first.event_id != parse(record, "other-sensor").event_id


@pytest.mark.parametrize("raw", ["{secret", "[1,2]", "{" * 2000, "x" * (MAX_LINE_BYTES + 1)],
                         ids=["invalid-json", "non-object", "deep-json", "oversize"])
def test_malformed_or_oversize_bounded_generic_rejection(raw, caplog):
    parser = network_parser("suricata", "test-sensor")
    with pytest.raises(RecordRejected, match="^invalid_metadata_record$"):
        parser.parse_record(raw)
    assert parser.stats.rejected == 1 and caplog.text == ""


def test_too_many_hosts_and_unknown_types():
    with pytest.raises(RecordRejected):
        parse_tshark(**{"tls.handshake.extensions_server_name": ",".join(["api.openai.com"] * (MAX_HOSTS + 1))})
    parser = network_parser("suricata", "test-sensor")
    assert parser.parse_record(json.dumps(eve("flow"))) == []
    assert parser.parse_record("# comment") == []


@pytest.mark.parametrize("sensor", ["", "bad sensor", "=formula", "x" * 201, "é"])
def test_sensor_identifier_bounded(sensor):
    with pytest.raises(ValueError):
        network_parser("zeek-dns", sensor)
