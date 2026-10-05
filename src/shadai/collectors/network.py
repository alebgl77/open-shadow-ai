"""Import passive network metadata or explicitly invoke a bounded TShark sensor.

Persisted Zeek/Suricata metadata logs can be replayed with stable observation IDs.
Live packet capture has no crash durability guarantee. No raw packet files are written.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import os
import queue
import re
import signal
import ssl
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from shadai.parsers.network import FORMATS, network_parser
from shadai.parsers.network.common import MAX_LINE_BYTES, RecordRejected, event_metadata, normalize_host
from shadai.parsers.network.tshark import ECH_FIELD, TSHARK_FIELDS

MAX_BATCH_EVENTS = 500
MAX_BATCH_BYTES = 900 * 1024
CSV_FIELDS = (
    "event_id", "timestamp", "collector_id", "site_id", "protocol", "src_ip", "dst_ip", "dst_port",
    "domain", "sni", "url_host", "http_method", "evidence_type",
)
_OVERSIZE = object()


class DeliveryError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)


def ingest_endpoint(value: str, allow_http_loopback: bool = False) -> str:
    if not value or any(char.isspace() or ord(char) < 32 for char in value) or "\\" in value:
        raise ValueError("Invalid collector API endpoint")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("Collector endpoint cannot contain credentials, query, or fragment")
    if not parsed.hostname or parsed.path not in {"", "/", "/api/v1/ingest/events"}:
        raise ValueError("Use an API origin or the exact ingestion endpoint")
    if parsed.scheme != "https" and not (
        allow_http_loopback and parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("HTTPS required; explicit HTTP development is limited to loopback")
    _ = parsed.port
    return value.rstrip("/") if parsed.path == "/api/v1/ingest/events" else value.rstrip("/") + "/api/v1/ingest/events"


def read_api_key(path: str | None = None) -> str:
    path = path or os.environ.get("AGENT_API_KEY_FILE")
    if path:
        key_path = Path(path)
        metadata = key_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError("API key file must be a private regular file")
        if metadata.st_size > 4096:
            raise ValueError("Invalid API key file")
        if os.name == "nt" and not _private_windows_key(key_path):
            raise ValueError("API key file must have a private Windows ACL")
        descriptor = os.open(key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino) or not stat.S_ISREG(opened.st_mode):
                raise ValueError("API key file changed while being opened")
            if os.name != "nt" and stat.S_IMODE(opened.st_mode) & 0o077:
                raise ValueError("API key file must be a private regular file")
            key = source.read(4097).strip()
    else:
        key = os.environ.get("AGENT_API_KEY", "")
    if not 32 <= len(key.encode()) <= 4096 or any(ord(char) < 32 for char in key):
        raise ValueError("Set AGENT_API_KEY or a private AGENT_API_KEY_FILE")
    return key


def _private_windows_key(path: Path) -> bool:
    """Inspect permissions without putting either file contents or paths in a command."""
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = """
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $env:SHADAI_NETWORK_PRIVATE_KEY_PATH -Force
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }
$acl = Get-Acl -LiteralPath $item.FullName
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544')
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { exit 1 }
foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) { exit 1 }
}
exit 0
"""
    environment = os.environ.copy()
    # A PS7 caller may supply modules that cannot load in native Windows PS5.
    # The security cmdlets must come from the child runtime's own module directory.
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    environment["SHADAI_NETWORK_PRIVATE_KEY_PATH"] = str(path.resolve())
    try:
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
                                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class EventTransport:
    """No redirects, verified TLS, bounded retries, identical request bytes."""

    def __init__(self, api_url: str, key: str, *, ca_file: str | None = None,
                 allow_http_loopback: bool = False, client=None, sleep=time.sleep, retries: int = 3):
        self.endpoint = ingest_endpoint(api_url, allow_http_loopback)
        self.key = key
        self.sleep = sleep
        self.retries = retries
        context = ssl.create_default_context(cafile=ca_file)
        self.client = client or httpx.Client(verify=context, follow_redirects=False, timeout=15, trust_env=False)
        self.owns_client = client is None

    def send(self, body: bytes) -> None:
        if len(body) > MAX_BATCH_BYTES:
            raise DeliveryError("batch_size_exceeded")
        for attempt in range(self.retries + 1):
            try:
                with self.client.stream(
                    "POST", self.endpoint, content=body,
                    headers={"X-API-Key": self.key, "Content-Type": "application/json"},
                    follow_redirects=False,
                ) as response:
                    status = response.status_code
                if status == 202:
                    return
                if status not in {408, 429} and not 500 <= status <= 599:
                    raise DeliveryError("delivery_http_" + str(status))
            except httpx.TransportError:
                pass
            if attempt == self.retries:
                raise DeliveryError("delivery_retries_exhausted")
            self.sleep(min(2**attempt, 8))

    def close(self):
        if self.owns_client:
            self.client.close()


class EventBatcher:
    def __init__(self, transport, *, flush_seconds: float = 2.0, clock=time.monotonic):
        self.transport = transport
        self.flush_seconds = flush_seconds
        self.clock = clock
        self.events = []
        self.bytes = len(b'{"events":[]}')
        self.started = None

    def add(self, event):
        encoded = json.dumps(event_metadata(event), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        added = len(encoded) + bool(self.events)
        if self.events and (len(self.events) >= MAX_BATCH_EVENTS or self.bytes + added > MAX_BATCH_BYTES):
            self.flush()
            added = len(encoded)
        if self.bytes + added > MAX_BATCH_BYTES:
            raise DeliveryError("event_size_exceeded")
        if not self.events:
            self.started = self.clock()
        self.events.append(encoded)
        self.bytes += added
        if len(self.events) >= MAX_BATCH_EVENTS:
            self.flush()

    def flush_due(self):
        if self.events and self.clock() - self.started >= self.flush_seconds:
            self.flush()

    def flush(self):
        if self.events:
            body = b'{"events":[' + b",".join(self.events) + b"]}"
            self.transport.send(body)
            self.events.clear()
            self.bytes = len(b'{"events":[]}')
            self.started = None


def tshark_has_ech_field(binary: str) -> bool:
    """Probe an optional field without letting unsupported fields break capture."""
    process = None
    stop = threading.Event()
    try:
        process = subprocess.Popen([binary, "-G", "fields"], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False)
        records = queue.Queue(maxsize=8)
        threading.Thread(target=_read_lines, args=(process.stdout, records, stop), daemon=True).start()
        deadline, total, supported = time.monotonic() + 30, 0, False
        while time.monotonic() < deadline:
            try:
                line = records.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                if process.wait(timeout=2):
                    raise ValueError("TShark capability probe failed")
                return supported
            if line is _OVERSIZE:
                raise ValueError("TShark capability probe exceeded metadata bounds")
            total += len(line)
            if total > 16 * 1024 * 1024:
                raise ValueError("TShark capability probe exceeded metadata bounds")
            parts = line.split(b"\t")
            supported |= len(parts) > 2 and parts[2] == ECH_FIELD.encode()
        raise ValueError("TShark capability probe timed out")
    except (OSError, subprocess.SubprocessError):
        raise ValueError("TShark capability probe failed") from None
    finally:
        stop.set()
        if process:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()


def tshark_command(binary: str, *, pcap: str | None = None, interface: str | None = None,
                   duration: int = 600, ech_field: bool = True) -> list[str]:
    if bool(pcap) == bool(interface) or not 1 <= duration <= 3600:
        raise ValueError("Choose one capture input and duration 1-3600 seconds")
    command = [binary, "-n", "-l"]
    if pcap:
        command += ["-r", str(Path(pcap).resolve())]
    else:
        if not interface or len(interface) > 200 or any(ord(char) < 32 for char in interface):
            raise ValueError("Invalid capture interface")
        command += ["-i", interface, "-a", "duration:" + str(duration), "-f", "tcp or udp"]
    command += ["-Y", "dns or tls or quic or http", "-T", "fields", "-E", "header=y",
                "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in (*TSHARK_FIELDS, *((ECH_FIELD,) if ech_field else ())):
        command += ["-e", field]
    return command


def display_filter(domains: list[str]) -> str:
    normalized = sorted({host for domain in domains if (host := normalize_host(domain.removeprefix("*.")))})
    if not normalized:
        raise ValueError("Configured catalog has no usable domains")
    # Labels and final anchors prevent suffix attacks; no shared parent domains are added.
    pattern = "(?i)^(?:[a-z0-9-]+\\.)*(?:" + "|".join(re.escape(domain) for domain in normalized) + ")\\.?$"
    http_pattern = pattern.removesuffix("$") + "(?::[0-9]{1,5})?$"
    quote = lambda value: json.dumps(value, ensure_ascii=True)  # noqa: E731
    return ("(dns.flags.response == 0 && dns.qry.name matches " + quote(pattern) + ") || "
            "(tls.handshake.extensions_server_name matches " + quote(pattern) + ") || "
            "(http.host matches " + quote(http_pattern) + ")")


def _read_lines(stream, output, stop):
    def put(value):
        while not stop.is_set():
            try:
                output.put(value, timeout=0.1)
                return
            except queue.Full:
                pass

    try:
        while not stop.is_set():
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                while line and not line.endswith(b"\n") and not stop.is_set():
                    line = stream.readline(MAX_LINE_BYTES + 1)
                put(_OVERSIZE)
            else:
                put(line)
    except (OSError, ValueError):
        put(_OVERSIZE)
    finally:
        put(None)


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--format", choices=FORMATS)
    parser.add_argument("--sensor-id", required=True)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--input", help="Metadata file or '-' for stdin")
    inputs.add_argument("--pcap", help="Offline PCAP dissected by TShark; no live capture")
    inputs.add_argument("--interface", help="Explicitly capture this interface with TShark")
    parser.add_argument("--duration", type=int, default=600, help="Live capture duration (1-3600 seconds)")
    parser.add_argument("--tshark-binary", default="tshark")
    parser.add_argument("--tenant-id", default="")
    parser.add_argument("--site-id", default="default")
    parser.add_argument("--dry-run", action="store_true", help="Write canonical metadata JSONL, without delivery")
    parser.add_argument("--csv-output")
    parser.add_argument("--api-url", default=os.environ.get("SHADAI_API_URL", "https://localhost:8443"))
    parser.add_argument("--api-key-file", help="Private key file; alternatively AGENT_API_KEY[_FILE]")
    parser.add_argument("--ca-file", help="PEM CA bundle; certificate/hostname checks always remain enabled")
    parser.add_argument("--allow-http-loopback", action="store_true")
    parser.add_argument("--print-filter", action="store_true",
                        help="Print a display filter from configured YAML catalog")
    parser.add_argument("--catalog-builtin", default="catalog/builtin")
    parser.add_argument("--catalog-local", default="catalog/local")
    return parser


def main(argv=None) -> int:
    args = argument_parser().parse_args(argv)
    process = stream = csv_file = transport = parser = None
    stop = threading.Event()
    previous_signals = {}
    exit_code = 0
    try:
        if args.print_filter:
            from shadai.engine.catalog_loader import load_catalog_from_yaml

            with contextlib.redirect_stdout(sys.stderr):
                items = load_catalog_from_yaml(args.catalog_builtin, args.catalog_local)
            print(display_filter([domain for item in items if item.status == "active" for domain in item.domains]))
            return 0
        if not any((args.input, args.pcap, args.interface)):
            raise ValueError("Choose --input, --pcap, or --interface")
        if (args.pcap or args.interface) and args.format not in {None, "tshark"}:
            raise ValueError("PCAP/interface inputs use the tshark format")
        if args.input and not args.format:
            raise ValueError("Metadata input requires --format")
        if not 1 <= args.duration <= 3600:
            raise ValueError("Duration must be 1-3600 seconds")
        parser = network_parser(args.format or "tshark", args.sensor_id, args.tenant_id, args.site_id)
        if not args.dry_run:
            transport = EventTransport(args.api_url, read_api_key(args.api_key_file), ca_file=args.ca_file,
                                       allow_http_loopback=args.allow_http_loopback)
        batch = EventBatcher(transport) if transport else None
        if args.csv_output:
            source_path = args.input if args.input != "-" else None
            if any(Path(args.csv_output).resolve() == Path(value).resolve()
                   or (Path(args.csv_output).exists() and Path(value).exists()
                       and Path(args.csv_output).samefile(value)) for value in (source_path, args.pcap) if value):
                raise ValueError("CSV output cannot overwrite the input")
            csv_file = Path(args.csv_output).open("w", encoding="utf-8", newline="")
            csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS, extrasaction="ignore")
            csv_writer.writeheader()
        if args.pcap or args.interface:
            has_ech = tshark_has_ech_field(args.tshark_binary)
            if not has_ech:
                print("ECH field unavailable; ECH offer detection is incomplete", file=sys.stderr)
            command = tshark_command(args.tshark_binary, pcap=args.pcap, interface=args.interface,
                                     duration=args.duration, ech_field=has_ech)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
            stream = process.stdout
        else:
            stream = sys.stdin.buffer if args.input == "-" else Path(args.input).open("rb")
        # A bounded queue supplies backpressure and lets sparse live streams flush on time.
        records = queue.Queue(maxsize=8)
        reader = threading.Thread(target=_read_lines, args=(stream, records, stop), daemon=True)
        reader.start()
        for name in (signal.SIGINT, signal.SIGTERM):
            previous_signals[name] = signal.getsignal(name)
            signal.signal(name, lambda *_: stop.set())
        while not stop.is_set():
            try:
                raw = records.get(timeout=0.1)
            except queue.Empty:
                if batch:
                    batch.flush_due()
                continue
            if raw is None:
                break
            if raw is _OVERSIZE:
                parser.stats.rejected += 1
                continue
            try:
                events = parser.parse_record(raw.decode("utf-8"))
            except UnicodeError:
                parser.stats.rejected += 1
                continue
            except RecordRejected:
                continue
            for event in events:
                metadata = event_metadata(event)
                if args.dry_run:
                    print(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")))
                if csv_file:
                    csv_writer.writerow(metadata)
                if batch:
                    batch.add(event)
            if batch:
                batch.flush_due()
        if batch:
            batch.flush()
        if process and not stop.is_set() and process.wait(timeout=5):
            raise ValueError("TShark metadata extraction failed")
        exit_code = 2 if parser.stats.rejected else 0
    except DeliveryError as exc:
        print(str(exc) + "; replay persisted metadata with the same sensor ID", file=sys.stderr)
        exit_code = 1
    except (ValueError, OSError, subprocess.SubprocessError):
        print("network_collector_failed: check input, configuration, or TShark availability", file=sys.stderr)
        exit_code = 1
    finally:
        stop.set()
        for name, handler in previous_signals.items():
            signal.signal(name, handler)
        if process:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if stream and stream is not getattr(sys.stdin, "buffer", None):
            stream.close()
        if csv_file:
            csv_file.close()
        if transport:
            transport.close()
        if parser:
            stats = asdict(parser.stats)
            if stats["ech_offered"]:
                print("ECH offered; acceptance unknown; GREASE possible", file=sys.stderr)
            print(json.dumps({"network_stats": stats}, separators=(",", ":")), file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
