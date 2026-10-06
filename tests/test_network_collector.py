"""Collector transport, bounded delivery, CLI privacy, and explicit capture contract."""

import json
import ssl
import subprocess

import httpx
import pytest

from shadai.collectors import network
from shadai.parsers.network import network_parser


def event():
    record = {"ts": "1780000000.123456", "uid": "synthetic-flow", "id.orig_h": "192.0.2.10",
              "id.resp_h": "198.51.100.20", "id.resp_p": 443, "server_name": "api.openai.com"}
    return network_parser("zeek-tls", "test-sensor").parse_record(json.dumps(record))[0]


@pytest.mark.parametrize("url", ["https://api.example.test", "https://api.example.test/",
                                "https://api.example.test/api/v1/ingest/events"])
def test_endpoint_origin_or_exact_path(url):
    assert network.ingest_endpoint(url) == "https://api.example.test/api/v1/ingest/events"


@pytest.mark.parametrize("url", ["http://api.example.test", "http://127.0.0.1", "https://user:key@api.example.test",
                                "https://api.example.test?key=secret", "https://api.example.test/#secret",
                                "https://api.example.test/other", "https://api.example.test\\evil",
                                "https://api.example.test:invalid", "https://api.example.test\n"])
def test_endpoint_rejects_ambiguity_and_insecure_defaults(url):
    with pytest.raises(ValueError):
        network.ingest_endpoint(url)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]"])
def test_http_loopback_requires_explicit_flag(host):
    assert network.ingest_endpoint("http://" + host, True).startswith("http://")
    with pytest.raises(ValueError):
        network.ingest_endpoint("http://192.0.2.1", True)


@pytest.mark.parametrize("first", [408, 429, 500, 503, "network"])
def test_retries_same_uuid_timestamp_and_exact_bytes(first):
    requests = []
    def handle(request):
        requests.append((request.read(), dict(request.headers), str(request.url)))
        if len(requests) == 1:
            if first == "network":
                raise httpx.ReadError("never-report-secret", request=request)
            return httpx.Response(first)
        return httpx.Response(202)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        delivery = network.EventTransport("https://api.example.test", "a" * 32, client=client, sleep=lambda _: None)
        batch = network.EventBatcher(delivery)
        batch.add(event())
        batch.flush()
    assert len(requests) == 2 and requests[0][0] == requests[1][0]
    assert requests[0][1]["x-api-key"] == "a" * 32
    sent = json.loads(requests[0][0])["events"][0]
    assert sent["event_id"] == str(event().event_id) and "normalized_at" not in sent


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 403, 413, 422])
def test_redirects_and_client_errors_terminal(status):
    requests = []
    def handle(request):
        requests.append(request)
        return httpx.Response(status, headers={"Location": "http://evil.example.test/secret"})
    with httpx.Client(transport=httpx.MockTransport(handle), follow_redirects=True) as client:
        delivery = network.EventTransport("https://api.example.test", "a" * 32, client=client, sleep=lambda _: None)
        with pytest.raises(network.DeliveryError, match="delivery_http_" + str(status)):
            delivery.send(b'{"events":[]}')
    assert len(requests) == 1


def test_retry_exhaustion_bounded_and_secret_free():
    calls = []
    def handle(request):
        calls.append(request)
        raise httpx.ConnectError("secret=" + "a" * 32, request=request)
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        delivery = network.EventTransport("https://api.example.test", "a" * 32, client=client, sleep=lambda _: None)
        with pytest.raises(network.DeliveryError, match="^delivery_retries_exhausted$"):
            delivery.send(b'{"events":[]}')
    assert len(calls) == 4


def test_tls_and_ca_always_verified(monkeypatch):
    seen = []
    actual_context = ssl.create_default_context()
    monkeypatch.setattr(network.ssl, "create_default_context", lambda **kwargs: seen.append(kwargs) or actual_context)
    monkeypatch.setattr(network.httpx, "Client", lambda **kwargs: seen.append(kwargs) or object())
    network.EventTransport("https://api.example.test", "a" * 32, ca_file="private-ca.pem")
    assert seen[0] == {"cafile": "private-ca.pem"}
    assert seen[1]["verify"].check_hostname and seen[1]["verify"].verify_mode == ssl.CERT_REQUIRED
    assert seen[1]["follow_redirects"] is False and seen[1]["trust_env"] is False


def test_batch_size_utf8_event_count_and_sparse_flush(monkeypatch):
    sent = []
    clock = [0.0]
    class Transport:
        def send(self, body):
            sent.append(body)
    monkeypatch.setattr(network, "MAX_BATCH_BYTES", 2048)
    batch = network.EventBatcher(Transport(), clock=lambda: clock[0])
    for _ in range(20):
        batch.add(event())
    batch.flush()
    assert len(sent) > 1 and all(len(body) <= 2048 for body in sent)
    assert sum(len(json.loads(body)["events"]) for body in sent) == 20
    sent.clear()
    batch.add(event())
    clock[0] = 1.99
    batch.flush_due()
    assert sent == []
    clock[0] = 2.0
    batch.flush_due()
    assert len(sent) == 1
    monkeypatch.setattr(network, "MAX_BATCH_BYTES", 900 * 1024)
    sent.clear()
    for _ in range(501):
        batch.add(event())
    batch.flush()
    assert [len(json.loads(body)["events"]) for body in sent] == [500, 1]


def test_tshark_capture_argv_no_shell_or_raw_capture():
    command = network.tshark_command("path with spaces/tshark", interface="Ethernet; evil", ech_field=False)
    assert command[0] == "path with spaces/tshark" and command[command.index("-i") + 1] == "Ethernet; evil"
    assert "tcp or udp" in command and "duration:600" in command
    assert "-w" not in command and network.ECH_FIELD not in command
    offline = network.tshark_command("tshark", pcap="synthetic.pcap")
    assert "-r" in offline and "-i" not in offline and "-a" not in offline
    assert network.ECH_FIELD in offline
    for duration in (0, 3601):
        with pytest.raises(ValueError):
            network.tshark_command("tshark", interface="eth0", duration=duration)


@pytest.mark.parametrize("available", [True, False])
def test_optional_ech_capability_probe(monkeypatch, available):
    import io

    class Process:
        def __init__(self, command, **kwargs):
            assert command == ["tshark", "-G", "fields"] and kwargs["shell"] is False
            field = network.ECH_FIELD.encode() if available else b"unsupported"
            self.stdout = io.BytesIO(b"F\tExtension\t" + field + b"\tFT_UINT16\n")
        def wait(self, **kwargs):
            return 0
        def poll(self):
            return 0
    monkeypatch.setattr(network.subprocess, "Popen", Process)
    assert network.tshark_has_ech_field("tshark") is available


def test_ech_probe_ignores_non_field_exact_abbreviation(monkeypatch):
    import io

    class Process:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b"P\tExtension\t" + network.ECH_FIELD.encode() + b"\n")
        def wait(self, **kwargs):
            return 0
        def poll(self):
            return 0
    monkeypatch.setattr(network.subprocess, "Popen", Process)
    assert network.tshark_has_ech_field("tshark") is False


def test_filter_exact_label_boundaries_and_no_parent_domain():
    filter_text = network.display_filter(["api.openai.com", "*.claude.ai", "api.openai.com"])
    assert "dns.flags.response == 0" in filter_text and "(?i)^" in filter_text
    assert "http.host matches" in filter_text and "tls.handshake.extensions_server_name matches" in filter_text
    assert "google.com" not in filter_text and "github.com" not in filter_text
    assert "api\\\\.openai\\\\.com" in filter_text and "claude\\\\.ai" in filter_text


def test_print_filter_real_catalog_stdout_only_expression(capsys):
    # Exercise the actual catalog loader/logger, including reuse in the same process.
    for _ in range(2):
        assert network.main(["--sensor-id", "test-sensor", "--print-filter"]) == 0
        output = capsys.readouterr()
        assert len(output.out.splitlines()) == 1
        assert output.out.startswith("(dns.flags.response == 0")
        assert "catalog_loaded" not in output.out and "network_stats" not in output.out


def test_capability_probe_output_limit(monkeypatch):
    import io

    class Process:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b"x" * (network.MAX_LINE_BYTES + 1) + b"\n")
        def poll(self):
            return 0
    monkeypatch.setattr(network.subprocess, "Popen", Process)
    with pytest.raises(ValueError, match="exceeded metadata bounds"):
        network.tshark_has_ech_field("tshark")


def test_ech_probe_cumulative_limit_precedes_positive_field_and_cleans_up(monkeypatch):
    import io

    processes = []
    class Process:
        def __init__(self, *args, **kwargs):
            record = b"x" * (network.MAX_LINE_BYTES - 1) + b"\n"
            declaration = b"F\tExtension\t" + network.ECH_FIELD.encode() + b"\tFT_UINT16\n"
            self.stdout = io.BytesIO(record * 64 + declaration)
            self.stopped = False
            self.reaped = False
            processes.append(self)
        def poll(self):
            return None if not self.stopped else 0
        def kill(self):
            self.stopped = True
        def wait(self, **kwargs):
            self.reaped = True
            return 0
    monkeypatch.setattr(network.subprocess, "Popen", Process)
    with pytest.raises(ValueError, match="exceeded metadata bounds"):
        network.tshark_has_ech_field("tshark")
    assert processes[0].stopped and processes[0].reaped and processes[0].stdout.closed


def test_positive_ech_probe_stops_before_large_remaining_registry(monkeypatch):
    import io

    processes = []
    class Process:
        def __init__(self, *args, **kwargs):
            declaration = b"F\tExtension\t" + network.ECH_FIELD.encode() + b"\tFT_UINT16\n"
            self.stdout = io.BytesIO(declaration + b"x" * (network.MAX_LINE_BYTES + 1) + b"\n")
            self.stopped = False
            processes.append(self)
        def poll(self):
            return None if not self.stopped else 0
        def kill(self):
            self.stopped = True
        def wait(self, **kwargs):
            return 0
    monkeypatch.setattr(network.subprocess, "Popen", Process)
    assert network.tshark_has_ech_field("tshark") is True
    assert processes[0].stopped and processes[0].stdout.closed


def test_smoke_failure_reports_synthetic_stage_without_arbitrary_exception_text(monkeypatch, capsys):
    import runpy
    from pathlib import Path

    script = runpy.run_path(str(Path("scripts/test-network-sensor.py")))
    def fail(_):
        raise ValueError("never-display-arbitrary-secret")
    monkeypatch.setitem(script["main"].__globals__, "tshark_has_ech_field", fail)
    assert script["main"]([]) == 1
    captured = capsys.readouterr()
    failure = json.loads(captured.err)
    assert failure["stage"] == "capability_probe" and failure["error_type"] == "ValueError"
    assert "never-display-arbitrary-secret" not in captured.out + captured.err


def test_smoke_missing_protocol_diagnostics_preserve_mandatory_assertions(monkeypatch, capsys):
    import runpy
    from pathlib import Path

    script = runpy.run_path(str(Path("scripts/test-network-sensor.py")))
    monkeypatch.setitem(script["main"].__globals__, "tshark_has_ech_field", lambda _: False)
    export_header = "\t".join(network.TSHARK_FIELDS).encode() + b"\n"
    monkeypatch.setattr(script["main"].__globals__["subprocess"], "run",
                        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=export_header))
    assert script["main"]([]) == 1
    failure = json.loads(capsys.readouterr().err)
    assert failure["stage"] == "protocol_assertions" and failure["observations"] == 0
    assert len(failure["missing_expected"]) == 5
    assert failure["protocol_counts"] == {}


def test_offline_fixture_is_deterministic_and_benign(tmp_path):
    import runpy
    import struct
    from pathlib import Path

    script = runpy.run_path(str(Path("scripts/test-network-sensor.py")))
    generated = tmp_path / "synthetic.pcap"
    script["write_fixture"](generated)
    contents = generated.read_bytes()
    assert contents == Path("tests/fixtures/network/synthetic.pcap").read_bytes()
    assert struct.unpack("<IHHIIII", contents[:24])[-1] == 101
    assert b"HTTP.Example.Test" in contents and b"tls.example.test" in contents
    assert b"secret" not in contents and len(contents) < 4096


def test_quic_synthetic_initial_packet_protection_round_trip():
    import runpy
    from pathlib import Path

    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    script = runpy.run_path(str(Path("scripts/test-network-sensor.py")))
    packet = script["quic_initial"]("quic.example.test")
    dcid = packet[6:14]
    extract = hmac.HMAC(bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), hashes.SHA256())
    extract.update(dcid)
    secret = script["expand"](extract.finalize(), b"client in", 32)
    key, iv = script["expand"](secret, b"quic key", 16), script["expand"](secret, b"quic iv", 12)
    hp = script["expand"](secret, b"quic hp", 16)
    # Fixture's length field starts at 24, packet-number at 26, cipher text at 30.
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(packet[30:46])
    header = bytes([packet[0] ^ (mask[0] & 0x0F)]) + packet[1:26]
    pn = bytes(a ^ b for a, b in zip(packet[26:30], mask[1:5], strict=True))
    header += pn
    nonce = bytes(a ^ b for a, b in zip(iv, b"\0" * 8 + pn, strict=True))
    plaintext = AESGCM(key).decrypt(nonce, packet[30:], header)
    assert len(packet) == 1200 and b"quic.example.test" in plaintext and pn == b"\0\0\0\1"


def test_cli_dry_run_csv_replay_and_no_sensitive_output(tmp_path, capsys):
    metadata = {"ts": "1780000000.123456", "uid": "synthetic-flow", "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20", "id.resp_p": 80, "host": "API.OpenAI.com.:80",
                "method": "GET", "uri": "/prompt?secret=hidden", "password": "never-show-this"}
    source = tmp_path / "metadata.jsonl"
    source.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
    csv_file = tmp_path / "metadata.csv"
    spool_path = tmp_path / "must-not-create-spool"
    args = ["--format", "zeek-http", "--input", str(source), "--sensor-id", "test-sensor", "--dry-run",
            "--spool-dir", str(spool_path)]
    assert network.main(args + ["--csv-output", str(csv_file)]) == 0
    assert not spool_path.exists()
    output = capsys.readouterr()
    first = json.loads(output.out)
    assert first["domain"] == "api.openai.com" and first["protocol"] == "HTTP"
    assert "network_stats" in output.err and "never-show-this" not in output.out + output.err
    assert "prompt" not in csv_file.read_text()
    renamed = source.rename(tmp_path / "renamed.jsonl")
    args[args.index("--input") + 1] = str(renamed)
    assert network.main(args) == 0
    assert json.loads(capsys.readouterr().out)["event_id"] == first["event_id"]


def test_cli_invalid_lines_and_delivery_failure_nonzero(tmp_path, capsys, monkeypatch):
    from shadai.utils import delivery_spool

    # SQLite semantics fixture only: the sandbox workspace ancestors are unsafe.
    monkeypatch.setattr(delivery_spool, "_private_ancestors", lambda path: None)
    source = tmp_path / "bad.jsonl"
    source.write_bytes(b'{"secret":"never-show-this"\n' + b"x" * (network.MAX_LINE_BYTES + 2) + b"\n")
    args = ["--format", "zeek-tls", "--input", str(source), "--sensor-id", "test-sensor"]
    assert network.main(args + ["--dry-run"]) == 2
    output = capsys.readouterr()
    assert '"rejected":2' in output.err and "never-show-this" not in output.out + output.err
    source.write_text(json.dumps({"ts": "1780000000", "uid": "flow", "id.orig_h": "192.0.2.10",
                                "id.resp_h": "198.51.100.20", "id.resp_p": 443, "server_name": "api.openai.com"}))
    class Failing:
        def __init__(self, *args, **kwargs):
            pass
        def send(self, body):
            raise network.DeliveryError("delivery_http_401")
        def close(self):
            pass
    monkeypatch.setattr(network, "EventTransport", Failing)
    assert network.main(args + ["--spool-dir", str(tmp_path / "private-spool")]) == 1
    assert "delivery_http_401" in capsys.readouterr().err


def test_csv_cannot_truncate_input(tmp_path, capsys):
    source = tmp_path / "source.jsonl"
    source.write_text("original")
    assert network.main(["--format", "zeek-dns", "--input", str(source), "--sensor-id", "sensor",
                         "--dry-run", "--csv-output", str(source)]) == 1
    assert source.read_text() == "original"
    capsys.readouterr()


def test_api_key_not_cli_argument_and_file_overrides_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_API_KEY", "e" * 32)
    assert network.read_api_key() == "e" * 32
    path = tmp_path / "key.txt"
    path.write_text("f" * 32 + "\n")
    path.chmod(0o600)
    monkeypatch.setattr(network, "_private_windows_key", lambda _: True)
    assert network.read_api_key(str(path)) == "f" * 32
    assert "--api-key" not in network.argument_parser().format_help().split()


def test_windows_key_permission_failure_is_closed(tmp_path, monkeypatch):
    import os

    if os.name != "nt":
        pytest.skip("Windows-specific file ACL guard")
    path = tmp_path / "key.txt"
    path.write_text("f" * 32)
    monkeypatch.setattr(network, "_private_windows_key", lambda _: False)
    with pytest.raises(ValueError, match="private Windows ACL"):
        network.read_api_key(str(path))


def test_windows_acl_probe_never_interpolates_path_or_prints_key(tmp_path, monkeypatch):
    import os

    path = tmp_path / "key;bad.txt"
    inherited_modules = r"C:\Program Files\PowerShell\7\Modules"
    monkeypatch.setenv("PSModulePath", inherited_modules)
    seen = []
    def run(command, **kwargs):
        seen.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1)
    monkeypatch.setattr(network.subprocess, "run", run)
    assert network._private_windows_key(path) is False
    command, kwargs = seen[0]
    assert str(path) not in command[-1]
    assert kwargs["env"]["SHADAI_NETWORK_PRIVATE_KEY_PATH"] == str(path.resolve())
    from pathlib import Path

    assert kwargs["env"]["PSModulePath"] == str(Path(command[0]).parent / "Modules")
    assert os.environ["PSModulePath"] == inherited_modules
    assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
