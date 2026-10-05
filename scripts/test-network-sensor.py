"""Offline-only real TShark smoke using deterministic, entirely synthetic packets.

No capture interface, capture permissions, external server, or packet payload retention.
The fixture uses documentation IP ranges and harmless example hostnames. QUIC Initial
protection follows RFC 9001; its decryption tests the real UDP/QUIC/TLS dissectors.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from shadai.collectors.network import tshark_command, tshark_has_ech_field
from shadai.parsers.network import network_parser


def checksum(value: bytes) -> int:
    value += b"\0" * (len(value) % 2)
    total = sum(struct.unpack("!" + "H" * (len(value) // 2), value))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(payload: bytes, destination_port: int, *, udp: bool = False, ipv6: bool = False,
           source_port: int = 50100) -> bytes:
    source = ipaddress.ip_address("2001:db8::10" if ipv6 else "192.0.2.10").packed
    destination = ipaddress.ip_address("2001:db8::20" if ipv6 else "198.51.100.20").packed
    protocol = 17 if udp else 6
    if udp:
        segment = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
        checksum_offset = 6
    else:
        segment = struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
        checksum_offset = 16
    pseudo = source + destination + (struct.pack("!I3xB", len(segment), protocol) if ipv6
                                     else struct.pack("!BBH", 0, protocol, len(segment)))
    check = checksum(pseudo + segment) or 0xFFFF
    segment = segment[:checksum_offset] + struct.pack("!H", check) + segment[checksum_offset + 2:]
    if ipv6:
        return struct.pack("!IHBB", 0x60000000, len(segment), protocol, 64) + source + destination + segment
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, protocol, 0) + source + destination
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + segment


def dns_query(host: str) -> bytes:
    name = b"".join(bytes([len(label)]) + label.encode() for label in host.split(".")) + b"\0"
    return struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def client_hello(host: str, *, quic: bool = False, ech: bool = False) -> bytes:
    name = host.encode()
    sni_name = b"\0" + struct.pack("!H", len(name)) + name
    sni = struct.pack("!H", len(sni_name)) + sni_name
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    extensions += struct.pack("!HH", 43, 3) + b"\2\3\4"
    if quic:
        extensions += struct.pack("!HH", 16, 5) + b"\0\3\2h3"
        extensions += struct.pack("!HH", 57, 0)
    if ech:
        # An offered, GREASE-like ECH outer extension: no acceptance is claimed.
        grease = b"\0\0\1\0\1\0\0\0\0\1\0"
        extensions += struct.pack("!HH", 0xFE0D, len(grease)) + grease
    body = b"\3\3" + bytes(range(32)) + b"\0\0\2\x13\1\1\0" + struct.pack("!H", len(extensions)) + extensions
    return b"\1" + len(body).to_bytes(3, "big") + body


def expand(secret: bytes, label: bytes, length: int) -> bytes:
    label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(label)]) + label + b"\0"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def varint(value: int) -> bytes:
    return bytes([value]) if value < 64 else struct.pack("!H", value | 0x4000)


def quic_initial(host: str) -> bytes:
    dcid = bytes.fromhex("8394c8f03e515708")
    extract = hmac.HMAC(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), hashes.SHA256())
    extract.update(dcid)
    secret = expand(extract.finalize(), b"client in", 32)
    key, iv, hp = expand(secret, b"quic key", 16), expand(secret, b"quic iv", 12), expand(secret, b"quic hp", 16)
    hello = client_hello(host, quic=True)
    crypto = b"\6\0" + varint(len(hello)) + hello
    prefix = b"\xc3\0\0\0\1" + bytes([len(dcid)]) + dcid + b"\10" + bytes(range(8)) + b"\0"
    pn = b"\0\0\0\1"
    plaintext_length = 1200 - (len(prefix) + 2 + len(pn)) - 16
    header = prefix + varint(len(pn) + plaintext_length + 16) + pn
    plaintext = crypto + b"\0" * (plaintext_length - len(crypto))
    nonce = bytes(a ^ b for a, b in zip(iv, b"\0" * 8 + pn, strict=True))
    encrypted = AESGCM(key).encrypt(nonce, plaintext, header)
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(encrypted[:16]) + encryptor.finalize()
    protected = bytes([header[0] ^ (mask[0] & 0x0F)]) + header[1:-4]
    protected += bytes(a ^ b for a, b in zip(pn, mask[1:5], strict=True))
    return protected + encrypted


def write_fixture(path: Path) -> None:
    tls = client_hello("tls.example.test")
    ech = client_hello("outer.example.test", ech=True)
    packets = [
        packet(dns_query("dns.example.test"), 53, udp=True),
        packet(dns_query("ipv6.example.test"), 53, udp=True, ipv6=True),
        packet(b"GET / HTTP/1.1\r\nHost: HTTP.Example.Test:80\r\n\r\n", 80),
        packet(b"\x16\3\1" + struct.pack("!H", len(tls)) + tls, 443),
        packet(quic_initial("quic.example.test"), 443, udp=True),
        packet(b"\x16\3\1" + struct.pack("!H", len(ech)) + ech, 443, source_port=50101),
    ]
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for index, value in enumerate(packets):
            output.write(struct.pack("<IIII", 1780000000 + index, 123456, len(value), len(value)))
            output.write(value)


def main(argv=None) -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--tshark-binary", default="tshark")
    args.add_argument("--write-fixture", type=Path, help="Only create the benign fixture; never invoke capture")
    options = args.parse_args(argv)
    if options.write_fixture:
        write_fixture(options.write_fixture)
        return 0
    stage = "capability_probe"
    diagnostics = {}
    try:
        ech = tshark_has_ech_field(options.tshark_binary)
        diagnostics["ech_field"] = ech
        with tempfile.TemporaryDirectory(prefix="shadai-offline-network-") as directory:
            stage = "fixture_generation"
            pcap = Path(directory) / "synthetic.pcap"
            write_fixture(pcap)
            command = tshark_command(options.tshark_binary, pcap=str(pcap), ech_field=ech)
            stage = "offline_dissection"
            result = subprocess.run(command, capture_output=True, timeout=30, check=True)
            stage = "metadata_parse"
            parser = network_parser("tshark", "ci-offline-synthetic")
            events = []
            for index, line in enumerate(result.stdout.decode().splitlines()):
                diagnostics["export_row"] = index
                events.extend(parser.parse_record(line))
            diagnostics["observations"] = len(events)
            diagnostics["protocol_counts"] = dict(Counter(event.protocol for event in events))
            diagnostics["parser_stats"] = asdict(parser.stats)
            expected = {("DNS", "dns.example.test"), ("DNS", "ipv6.example.test"),
                        ("HTTP", "http.example.test"), ("TLS", "tls.example.test"),
                        ("QUIC", "quic.example.test")}
            actual = {(event.protocol, event.domain) for event in events}
            diagnostics["missing_expected"] = sorted(expected - actual)
            stage = "protocol_assertions"
            assert expected <= actual, "Real TShark dissectors did not expose all synthetic protocols"
            stage = "ipv6_assertion"
            assert any(event.protocol == "DNS" and ":" in event.src_ip for event in events)
            stage = "privacy_assertion"
            assert all(not event.username and not event.model and event.cost_usd is None for event in events)
            if ech:
                stage = "ech_assertion"
                assert parser.stats.ech_offered == 1 and ("TLS", "outer.example.test") not in actual
            print(json.dumps({"offline_tshark_smoke": "passed", "observations": len(events), "ech_field": ech}))
        return 0
    except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
        failure = {"offline_tshark_smoke": "failed", "stage": stage, "error_type": type(error).__name__,
                   **diagnostics}
        # Only fixed, production-safe probe messages are surfaced. The fixture's
        # counts and missing expected names are synthetic; stderr/commands/packets
        # and arbitrary exception text are never dumped.
        safe_reasons = {
            "TShark capability probe failed", "TShark capability probe exceeded metadata bounds",
            "TShark capability probe timed out", "invalid_metadata_record",
        }
        if str(error) in safe_reasons:
            failure["reason"] = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            failure["return_code"] = error.returncode
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
