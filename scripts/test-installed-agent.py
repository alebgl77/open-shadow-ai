"""Prove the exact offline agent wheel in isolated Python 3.10 processes.

All HTTP uses an owned loopback server and synthetic settings. SQLite, native
privacy guards, timestamps and delivery are real; no memory spool substitutes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import threading
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
HEADER = {"hostname": "synthetic-installed-agent", "agent_version": "legacy-snapshot",
          "timestamp": "2026-10-06T12:34:56.123456+00:00"}
SCENARIOS = ("http503", "partial_ack", "lost_reply")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wheel_inventory(wheelhouse: Path, checkout: Path = ROOT) -> tuple[Path, dict[str, str]]:
    manifest = json.loads((wheelhouse / "SHA256SUMS.json").read_text(encoding="utf8"))
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("wheelhouse_manifest_invalid")
    for name, expected in manifest.items():
        if (Path(name).name != name or not re.fullmatch(r"[a-f0-9]{64}", expected)
                or digest(wheelhouse / name) != expected):
            raise ValueError("wheelhouse_hash_mismatch")
    if {path.name for path in wheelhouse.iterdir() if path.is_file()} != {*manifest, "SHA256SUMS.json"}:
        raise ValueError("wheelhouse_unlisted_file")
    lock_manifest = json.loads((checkout / "requirements/manifest.json").read_text(encoding="utf8"))
    for name in ("agent.txt", "build.txt"):
        expected = lock_manifest["locks"][name]
        if digest(wheelhouse / name) != expected or digest(checkout / "requirements" / name) != expected:
            raise ValueError("dependency_lock_drift")
    wheel, = wheelhouse.glob("shadai_agent-*.whl")
    if wheel.name not in manifest:
        raise ValueError("agent_wheel_unlisted")
    with zipfile.ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist()
                 if name.startswith("shadai_agent/") and name.endswith(".py")}
    source = {path.relative_to(checkout / "agent").as_posix(): path
              for path in (checkout / "agent/shadai_agent").rglob("*.py")}
    if set(files) != set(source) or any(files[name] != source[name].read_bytes() for name in files):
        raise ValueError("agent_wheel_source_mismatch")
    return wheel, {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}


def verify_module_origin(module, purelib: Path, expected: str) -> None:
    path = Path(module.__file__).resolve()
    if not path.is_relative_to(purelib.resolve()):
        raise ValueError("agent_module_outside_installed_site_packages")
    if digest(path) != expected:
        raise ValueError("installed_agent_module_hash_mismatch")


def verify_qa_root(root: Path, parent: Path) -> None:
    if (root.parent != parent or not parent.is_absolute() or root.resolve() != root
            or not re.fullmatch(r"installed-agent-[a-f0-9]{32}", root.name)):
        raise ValueError("unsafe_installed_agent_qa_path")


def installed_modules(environment: Path, expected: dict[str, str]):
    if sys.version_info[:2] != (3, 10) or Path(sys.prefix).resolve() != environment.resolve():
        raise ValueError("isolated_python310_environment_required")
    purelib = Path(sysconfig.get_path("purelib")).resolve()
    if not purelib.is_relative_to(environment.resolve()):
        raise ValueError("installed_site_packages_outside_environment")
    for name, checksum in expected.items():
        module_name = name.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        verify_module_origin(importlib.import_module(module_name), purelib, checksum)
    agent = importlib.import_module("shadai_agent.main")
    spool = importlib.import_module("shadai_agent.delivery_spool")
    agent.logger.disabled = True
    return agent, spool


def private_directory(path: Path) -> None:
    """Create only a new QA leaf, using the delivered protected-at-creation recipe."""
    if path.exists() or path.is_symlink():
        raise ValueError("qa_directory_must_be_new")
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = """
$ErrorActionPreference = 'Stop'
$path = [IO.Path]::GetFullPath($env:SHADAI_INSTALLED_AGENT_PRIVATE_PATH)
if (Test-Path -LiteralPath $path) { exit 10 }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($sid)
$security.SetAccessRuleProtection($true, $false)
foreach ($identity in $allowed) {
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]$identity, 'FullControl',
        'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
[IO.Directory]::CreateDirectory($path, $security) | Out-Null
$acl = Get-Acl -LiteralPath $path
$unexpected = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
    Where-Object { $_.IdentityReference.Value -notin $allowed })
if (-not $acl.AreAccessRulesProtected -or
    $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
    $unexpected.Count -or (Get-ChildItem -LiteralPath $path -Force | Select-Object -First 1)) { exit 11 }
"""
    environment = {key: value for key, value in clean_environment().items() if key.upper() != "PSMODULEPATH"}
    environment["PSMODULEPATH"] = str(powershell.parent / "Modules")
    environment["SHADAI_INSTALLED_AGENT_PRIVATE_PATH"] = str(path)
    subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script], env=environment,
                   capture_output=True, timeout=15, check=True,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def clean_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(("PIP_", "UV_", "PYTHON", "AGENT_", "SHADAI_"))
                   and key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}}
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["NO_PROXY"] = "127.0.0.1"
    return environment


@contextmanager
def local_receiver(agent, scenario: str, *, fail: bool = False):
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/api/v1/agent/config":
                self.send_error(404)
                return
            self.respond(200, {"legacy": True})

        def respond(self, status, body):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            self.connection.settimeout(5)
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/api/v1/agent/telemetry" or not 0 < size <= agent.MAX_BODY_BYTES:
                self.send_error(400)
                return
            payload = self.rfile.read(size)
            if len(payload) != size:
                self.send_error(400)
                return
            seen.append(payload)
            body = json.loads(payload)
            received = sum(len(body.get(section, [])) for section in agent.SECTIONS)
            if fail and len(seen) == 2:
                if scenario == "lost_reply":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    self.close_connection = True
                    return
                self.respond(503 if scenario == "http503" else 200,
                             {"received": received - 1})
                return
            self.respond(200, {"received": received})
            if scenario == "utc":
                agent._running = False

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 5
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("qa_http_server_did_not_stop")


def shapes(agent) -> dict:
    small = {**HEADER, "processes": [{"name": str(i)} for i in range(250)],
             "extensions": [{"id": str(i)} for i in range(250)]}
    saved = json.dumps(small, indent=3).encode()
    assert agent.delivery_payloads(saved) == [saved], "small_parent_bytes_changed"
    with local_receiver(agent, "small") as (url, seen):
        assert agent.send_once(url + "/api/v1/agent/telemetry", saved, {}, True) == 500
    assert seen == [saved], "small_wire_bytes_changed"
    original = {**HEADER, "processes": [{"name": str(i), "extra": "retained"} for i in range(500)],
                "extensions": [{"id": str(i)} for i in range(500)], "model_files": [{"name": "legacy"}]}
    parent = json.dumps(original, indent=2).encode()
    children = agent.delivery_payloads(parent)
    assert children == agent.delivery_payloads(parent) and len(children) == 3, "legacy_children_not_deterministic"
    rows = [json.loads(child) for child in children]
    assert [sum(len(row[section]) for section in agent.LEGACY_SECTIONS) for row in rows] == [500, 500, 1]
    assert all(len(child) <= agent.MAX_BODY_BYTES for child in children)
    assert all({key: row[key] for key in HEADER} == HEADER for row in rows)
    for section in agent.LEGACY_SECTIONS:
        assert [record for row in rows for record in row[section]] == original.get(section, [])
    assert json.loads(parent) == original
    fresh = agent.split_batches(HEADER, {section: original.get(section, []) for section in agent.SECTIONS})
    assert all(sum(len(row[section]) for section in agent.SECTIONS) <= 500 for row in fresh)
    return {"small_exact_bytes": True, "legacy_total": 1001, "child_counts": [500, 500, 1]}


def utc_loop(agent, path: Path) -> dict:
    private_directory(path)
    with local_receiver(agent, "utc") as (url, seen):
        settings = SimpleNamespace(server_url=url, api_key="synthetic-installed-agent-key-0000", ca_bundle=None,
            hostname="synthetic", spool_dir=str(path), spool_max_bytes=1024 * 1024, spool_max_batches=10,
            spool_ttl_seconds=3600, poll_interval_seconds=0, collect_processes=False, collect_containers=False,
            collect_local_ai=False, collect_extensions=False, collector_id="")
        handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
        started = datetime.now(timezone.utc)  # noqa: UP017 - Python 3.10
        agent._running = True
        try:
            # Controlled collection/settings only; the clock, HTTP and DurableSpool stay real.
            with patch.object(agent, "load_agent_config", return_value=settings):
                agent.main()
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
        finished = datetime.now(timezone.utc)  # noqa: UP017 - Python 3.10
    assert len(seen) == 1, "utc_loop_did_not_publish_once"
    stamp = json.loads(seen[0])["timestamp"]
    value = datetime.fromisoformat(stamp)
    assert stamp.endswith("+00:00") and value.utcoffset() == timedelta(0) and started <= value <= finished
    return {"utc_wire_aware": True}


def recovery(agent, spool_module, path: Path, scenario: str, stage: str) -> dict:
    original = {**HEADER, "processes": [{"name": str(i)} for i in range(500)],
                "extensions": [{"id": str(i)} for i in range(500)]}
    saved = json.dumps(original, indent=2).encode()
    children = agent.delivery_payloads(saved)
    parent_id = hashlib.sha256(saved).hexdigest()
    if stage == "seed":
        private_directory(path)
    with local_receiver(agent, scenario, fail=stage == "seed") as (url, seen):
        settings = SimpleNamespace(server_url=url, api_key="synthetic-installed-agent-key-0000", ca_bundle=None)
        with spool_module.DurableSpool(path, clock=lambda: 1000 if stage == "seed" else 1301) as spool:
            assert spool.db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            assert spool.db.execute("PRAGMA synchronous").fetchone()[0] == 2
            if stage == "seed":
                assert spool.enqueue(saved, event_count=1000) == parent_id
                assert agent.drain_spool(spool, settings, limit=1) == 0
                assert spool.db.execute("SELECT id,payload FROM batches").fetchone() == (parent_id, saved)
                assert spool.stats().get("delivered_events", 0) == 0 and spool.stats()["retried"] == 1
            else:
                [retained] = spool.claim(limit=1)
                assert retained.batch_id == parent_id and retained.payload == saved and retained.attempts == 1
                assert spool.retry(retained, delay=0)
                assert agent.drain_spool(spool, settings, limit=1) == 1000
                assert spool.stats()["batches"] == 0 and spool.stats()["delivered_events"] == 1000
                assert spool.stats()["delivered"] == 1
    assert seen == children, "retried_child_wire_bytes_changed"
    return {"scenario": scenario, "stage": stage, "parent_sha256": parent_id,
            "child_sha256": [hashlib.sha256(child).hexdigest() for child in seen],
            "native_sqlite": True, "parent_retained": stage == "seed", "acked_all": stage == "retry"}


def worker(arguments) -> dict:
    fixture_root = arguments.environment.resolve().parent
    verify_qa_root(fixture_root, fixture_root.parent)
    if (arguments.expected.resolve().parent != fixture_root or arguments.spool.parent != fixture_root
            or not re.fullmatch(r"spool-(none|utc|http503|partial_ack|lost_reply)", arguments.spool.name)):
        raise ValueError("installed_worker_path_outside_qa_root")
    expected = json.loads(arguments.expected.read_text(encoding="utf8"))
    agent, spool = installed_modules(arguments.environment, expected["modules"])
    report = {"phase": arguments.worker, "python": sys.version.split()[0], "module_file": agent.__file__,
              "main_sha256": digest(Path(agent.__file__)), "installed_wheel_sha256": expected["wheel_sha256"]}
    if arguments.worker == "shapes":
        report.update(shapes(agent))
    elif arguments.worker == "utc":
        report.update(utc_loop(agent, arguments.spool))
    else:
        report.update(recovery(agent, spool, arguments.spool, arguments.scenario, arguments.worker))
    return report


def run_installed(arguments) -> None:
    if sys.version_info[:2] != (3, 10):
        raise ValueError("python310_required")
    wheelhouse = arguments.wheelhouse.resolve()
    wheel, modules = wheel_inventory(wheelhouse)
    parent = arguments.temporary_parent or (Path(os.environ["USERPROFILE"]) if os.name == "nt" else ROOT / "tmp")
    if arguments.temporary_parent is None and os.name != "nt":
        parent.mkdir(mode=0o700, exist_ok=True)
    parent = parent.resolve(strict=True)
    root = parent / ("installed-agent-" + uuid4().hex)
    verify_qa_root(root, parent)
    report = {"wheel_sha256": digest(wheel), "checkout_module_sha256": modules, "workers": [],
              "offline_require_hashes": True, "native_guards_mocked": False, "passed": False}
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    active_wait = None

    def execute(argv, *, phase, cwd=None):
        nonlocal active_wait
        environment = clean_environment()
        environment.update(TMP=str(root), TEMP=str(root), TMPDIR=str(root))
        active_wait = (phase, 120)
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, text=True, timeout=120)
        active_wait = None
        if result.returncode:
            report["failed_command"] = {"argv": argv, "returncode": result.returncode,
                                        "stdout": result.stdout[-2048:], "stderr": result.stderr[-2048:]}
            raise RuntimeError("installed_agent_child_failed")
        return result.stdout

    try:
        active_wait = ("private_directory", 15) if os.name == "nt" else None
        private_directory(root)
        active_wait = None
        environment = root / "environment"
        execute([sys.executable, "-I", "-m", "venv", str(environment)], phase="venv")
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        requirement = root / "exact-agent.txt"
        requirement.write_text(f"shadai-agent @ {wheel.as_uri()} --hash=sha256:{digest(wheel)}\n", encoding="utf8")
        execute([str(python), "-I", "-m", "pip", "--cache-dir", str(root / "pip-cache"),
                 "install", "--no-index", "--find-links", str(wheelhouse),
                 "--only-binary=:all:", "--require-hashes", "-r", str(wheelhouse / "build.txt"),
                 "-r", str(wheelhouse / "agent.txt"), "-r", str(requirement)], phase="offline_install")
        execute([str(python), "-I", "-m", "pip", "check"], phase="dependency_check")
        expected = root / "expected.json"
        expected.write_text(json.dumps({"modules": modules, "wheel_sha256": digest(wheel)}), encoding="utf8")

        def stage(phase, scenario="none"):
            spool = root / ("spool-" + ("utc" if phase == "utc" else scenario))
            argv = [str(python), "-I", str(Path(__file__).resolve()), "--worker", phase,
                    "--environment", str(environment), "--expected", str(expected), "--spool", str(spool),
                    "--scenario", scenario]
            result = json.loads(execute(argv, phase="worker", cwd=environment))
            report["workers"].append(result)
            return result

        stage("shapes")
        stage("utc")
        for scenario in SCENARIOS:
            seed = stage("seed", scenario)
            retry = stage("retry", scenario)
            assert seed["parent_sha256"] == retry["parent_sha256"]
            assert seed["child_sha256"] == retry["child_sha256"]
        report["passed"] = True
    except Exception as error:
        report["failure_type"] = type(error).__name__
        if (type(error) is subprocess.TimeoutExpired and type(active_wait) is tuple and len(active_wait) == 2
                and type(active_wait[0]) is str and type(active_wait[1]) is int
                and active_wait in (("private_directory", 15), ("venv", 120), ("offline_install", 120),
                                    ("dependency_check", 120), ("worker", 120))):
            report["timeout_phase"], report["timeout_seconds"] = active_wait
        raise
    finally:
        arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf8")
        # Only the exclusively created, verified absolute QA root is removed.
        if root.exists():
            verify_qa_root(root, parent)
            shutil.rmtree(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--temporary-parent", type=Path, help="Existing trusted parent; Windows CI uses USERPROFILE")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/installed-agent-proof.json")
    parser.add_argument("--worker", choices=("shapes", "utc", "seed", "retry"), help=argparse.SUPPRESS)
    parser.add_argument("--environment", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--expected", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--spool", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--scenario", choices=("none", *SCENARIOS), default="none", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.worker and not all((arguments.environment, arguments.expected, arguments.spool)):
        parser.error("Internal installed worker requires environment, expected hashes and private spool")
    if not arguments.worker and not arguments.wheelhouse:
        parser.error("--wheelhouse is required")
    try:
        if arguments.worker:
            print(json.dumps(worker(arguments), sort_keys=True))
        else:
            run_installed(arguments)
            print("PASS: exact installed Python3.10 wheel; UTC, total batching and native HTTP/SQLite restart recovery")
        return 0
    except Exception as error:
        # Do not disclose HTTP headers, configuration, payloads or credentials.
        print(json.dumps({"passed": False, "failure_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
