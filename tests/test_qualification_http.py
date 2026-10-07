"""Real loopback witnesses for total HTTP deadlines and child ownership."""

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import pytest

from shadai.qualification.http_transport import HttpTransport
from shadai.qualification.lab import Laboratory
from shadai.qualification.load import LoadSender
from shadai.qualification.schemas import QualificationError, load_profile
from shadai.qualification.target import bounded_get


@pytest.fixture
def server():
    state = {"mode": "ok", "requests": [], "redirects": 0, "stop": threading.Event()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.respond(b"")

        def do_POST(self):
            self.respond(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

        def respond(self, payload):
            state["requests"].append(payload)
            try:
                mode = state["mode"]
                if self.path == "/redirected":
                    state["redirects"] += 1
                if mode == "headers":
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                    while not state["stop"].wait(0.04):
                        self.connection.sendall(b"a")
                    return
                if mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "/redirected")
                    self.end_headers()
                    return
                status = 503 if mode == "retry" and len(state["requests"]) == 1 else 202 if payload else 200
                self.send_response(status)
                body = (
                    b"a" * 65537
                    if mode == "large"
                    else b'{"received":true}'
                    if mode == "boolean"
                    else json.dumps({"received": len(json.loads(payload)["events"])}).encode()
                    if payload
                    else b'{"status":"ready"}'
                )
                self.send_header("Content-Length", str(100 if mode in {"body", "short"} else len(body)))
                self.end_headers()
                if mode == "body":
                    while not state["stop"].wait(0.04):
                        self.wfile.write(b"a")
                        self.wfile.flush()
                elif mode == "short":
                    self.wfile.write(b"{")
                    self.wfile.flush()
                    state["stop"].wait(5)
                else:
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    http.daemon_threads = True
    http.block_on_close = False
    thread = threading.Thread(target=http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(http.server_port), state
    state["stop"].set()
    http.shutdown()
    http.server_close()
    thread.join(timeout=1)


@pytest.fixture
def children(monkeypatch):
    original = subprocess.Popen
    observed = []

    def spawn(command, **kwargs):
        child = original(command, **kwargs)
        observed.append((command, kwargs, child))
        return child

    monkeypatch.setattr("shadai.qualification.http_transport.subprocess.Popen", spawn)
    return observed


def reaped(children, transport=None):
    assert children and all(child.poll() is not None for _, _, child in children)
    assert all(child.stdout.closed and child.stdin.closed for _, _, child in children)
    assert all(command[:2] == [sys.executable, "-I"] and len(command) == 3 for command, _, _ in children)
    assert all(
        Path(command[2]).is_absolute() and options["stderr"] == subprocess.DEVNULL for command, options, _ in children
    )
    if transport:
        assert not transport.children


@pytest.mark.parametrize("mode", ["headers", "body", "short"])
def test_real_drips_and_short_body_respect_total_deadline(server, children, mode):
    url, state = server
    state["mode"] = mode
    transport = HttpTransport()
    before = time.monotonic()
    status, _, error = transport.request(url, deadline=before + 0.7, timeout=4)
    assert status == 0 and error == "unconfirmed"
    assert time.monotonic() - before < 1.8
    reaped(children, transport)


def test_real_cancel_reaps_blocked_child_and_never_submits_again(server, children):
    url, state = server
    state["mode"] = "short"
    stopped = threading.Event()
    transport = HttpTransport(stopped)
    timer = threading.Timer(0.4, stopped.set)
    timer.start()
    before = time.monotonic()
    try:
        assert transport.request(url, deadline=before + 10, timeout=10)[0] == 0
        assert time.monotonic() - before < 1.8
        count = len(children)
        assert transport.request(url, deadline=before + 10, timeout=10)[0] == 0
        assert len(children) == count
        reaped(children, transport)
    finally:
        timer.cancel()


def test_simulated_blocked_dns_uses_actual_killed_subprocess(tmp_path, monkeypatch):
    worker = Path(__file__).resolve().parents[1] / "src/shadai/qualification/http_worker.py"
    wrapper = tmp_path / "dns-block.py"
    wrapper.write_text(
        "import runpy,socket,time\n"
        "socket.getaddrinfo=lambda *a,**k: time.sleep(10)\n"
        f"runpy.run_path({str(worker)!r},run_name='__main__')\n"
    )
    original = subprocess.Popen
    observed = []

    def spawn(command, **kwargs):
        observed.append(original([*command[:2], str(wrapper)], **kwargs))
        return observed[-1]

    monkeypatch.setattr("shadai.qualification.http_transport.subprocess.Popen", spawn)
    transport = HttpTransport()
    before = time.monotonic()
    assert transport.request("http://127.0.0.1:9", deadline=before + 0.6, timeout=4)[0] == 0
    assert time.monotonic() - before < 1.8
    assert len(observed) == 1 and observed[0].poll() is not None and not transport.children


def test_redirect_refused_proxy_environment_ignored_and_secret_absent(server, children, monkeypatch, capsys):
    url, state = server
    state["mode"] = "redirect"
    marker = "synthetic-private-key-never-in-command"
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    transport = HttpTransport()
    status, _, _ = transport.request(
        url, method="POST", body=b"{}", credential=marker, deadline=time.monotonic() + 3, timeout=3
    )
    assert status == 302 and state["redirects"] == 0 and len(state["requests"]) == 1
    assert marker not in repr([command for command, _, _ in children])
    assert marker not in str(capsys.readouterr())
    reaped(children, transport)


def small_profile():
    profile = load_profile(Path(__file__).resolve().parents[1] / "deploy/qualification/profiles/lab-smoke.json")
    profile["load"].update(total_events=10, batch_size=10, events_per_second=100, request_timeout_seconds=0.5)
    profile["limits"].update(max_wall_seconds=1.4, max_requests=3)
    return profile


def test_real_load_retry_preserves_bytes_and_scoped_acceptance(tmp_path, server, children):
    url, state = server
    state["mode"] = "retry"
    profile = small_profile()
    profile["load"]["request_timeout_seconds"] = 3
    profile["limits"]["max_wall_seconds"] = 6
    sender = LoadSender(profile, str(uuid4()), "retry", tmp_path, "scoped")
    result = sender.run(url, "synthetic")
    assert result["accepted"] == result["attempted"] == 10 and result["requests"] == 2
    assert len(set(result["accepted_scoped_ids"])) == 10
    assert state["requests"][0] == state["requests"][1]
    reaped(children, sender.transport)


def test_real_load_total_budget_reaps_all_and_leaves_acceptance_unconfirmed(tmp_path, server, children):
    url, state = server
    state["mode"] = "body"
    sender = LoadSender(small_profile(), str(uuid4()), "slow", tmp_path, "scoped")
    before = time.monotonic()
    result = sender.run(url, "synthetic")
    assert result["accepted"] == 0 and result["requests"] <= 3
    assert time.monotonic() - before < 2.5
    reaped(children, sender.transport)


def test_boolean_ack_is_rejected_even_when_equal_to_one(tmp_path, server, children):
    url, state = server
    state["mode"] = "boolean"
    profile = small_profile()
    profile["load"].update(total_events=1, batch_size=1, request_timeout_seconds=3)
    sender = LoadSender(profile, str(uuid4()), "boolean", tmp_path, "scoped")
    with pytest.raises(QualificationError, match="acknowledgement"):
        sender.run(url, "synthetic")
    reaped(children, sender.transport)


def test_preparation_consumes_wall_budget_before_any_http(tmp_path, children):
    times = iter([0, 0, 2])
    sender = LoadSender(small_profile(), str(uuid4()), "preparation", tmp_path, "scoped", clock=lambda: next(times))
    with pytest.raises(QualificationError, match="preparation"):
        sender.run("http://127.0.0.1:9", "synthetic")
    assert not children


def test_target_get_clips_global_deadline(server, children):
    url, state = server
    state["mode"] = "short"
    before = time.monotonic()
    with pytest.raises(QualificationError, match="deadline"):
        bounded_get(url, 10, deadline=before + 0.6)
    assert time.monotonic() - before < 1.8
    reaped(children)


def test_lab_readiness_uses_same_bounded_child_and_global_deadline(tmp_path, server, children, monkeypatch):
    url, state = server
    state["mode"] = "headers"
    root = Path(__file__).resolve().parents[1]
    profile = load_profile(root / "deploy/qualification/profiles/lab-smoke.json")
    lab = Laboratory(root, tmp_path, profile, "exact-context")
    monkeypatch.setattr(lab, "compose", lambda *a, **k: url.removeprefix("http://"))
    before = time.monotonic()
    lab.deadline = before + 0.6
    with pytest.raises(QualificationError, match="wall budget"):
        lab.wait_ready()
    assert time.monotonic() - before < 1.8
    reaped(children)


def test_response_byte_cap_rejects_before_acceptance(server, children):
    url, state = server
    state["mode"] = "large"
    transport = HttpTransport()
    with pytest.raises(QualificationError, match="proof boundary"):
        transport.request(url, deadline=time.monotonic() + 3, timeout=3)
    reaped(children, transport)


def test_two_concurrent_batches_never_exceed_child_concurrency(tmp_path, server, monkeypatch):
    url, state = server
    state["mode"] = "body"
    profile = small_profile()
    profile["load"]["total_events"] = 20
    original, children, counts, lock = subprocess.Popen, [], [], threading.Lock()

    def spawn(command, **kwargs):
        child = original(command, **kwargs)
        with lock:
            children.append(child)
            counts.append(sum(item.poll() is None for item in children))
        return child

    monkeypatch.setattr("shadai.qualification.http_transport.subprocess.Popen", spawn)
    sender = LoadSender(profile, str(uuid4()), "concurrent", tmp_path, "scoped")
    result = sender.run(url, "synthetic")
    assert result["accepted"] == 0 and max(counts) == profile["load"]["concurrency"] == 2
    assert all(item.poll() is not None for item in children) and not sender.transport.children
