"""Worker diagnostics retain bounded allowlisted state and preserve the failed CI gate."""

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compose_worker_diagnostic", ROOT / "scripts/diagnose-compose-workers.py")
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)
PROJECT = "open-shadow-ai"
IDS = {"ingest-worker": "a" * 64, "correlation-worker": "b" * 64}
SECRET = "synthetic-secret-never-retained"
RECORD = {
    "record_valid": True, "initialized": True, "phase": "idle",
    "heartbeat_age": 1.25, "poll_age": 2, "cycle_age": None,
}


def state(service):
    return {
        "Id": IDS[service], "Name": f"/{PROJECT}-{service}-1", "Created": "2026-10-06T00:00:00Z",
        "Image": "sha256:" + "c" * 64, "Project": PROJECT, "Service": service,
        "State": {"Status": "running", "Running": True, "ExitCode": 0, "OOMKilled": False},
        "RestartCount": 2, "Health": {"Status": "unhealthy", "FailingStreak": 12},
    }


class FakeClient:
    def __init__(self, *, ids=None, change=None, exec_results=None, record=None):
        self.ids = ids or {name: (value + "\n").encode() for name, value in IDS.items()}
        self.change = change
        self.exec_results = exec_results or {}
        self.record = json.dumps(RECORD).encode() if record is None else record
        self.commands = []
        self.executions = {name: 0 for name in IDS}

    def run(self, command, *, capture=True):
        self.commands.append((command, capture))
        if command[1] == "compose":
            return {"exit_code": 0, "stdout": self.ids[command[-1]]}
        service = next(name for name, container in IDS.items() if container == command[-1] or container == command[2])
        if command[1] == "inspect":
            value = state(service)
            if self.change:
                self.change(value, self.executions[service])
            return {"exit_code": 0, "stdout": json.dumps(value).encode()}
        self.executions[service] += 1
        mode = "record" if command[4] == "-c" else command[-3]
        return copy.deepcopy(self.exec_results.get(mode, {
            "exit_code": 0, **({"stdout": self.record} if capture else {}),
        }))


def test_exact_fixed_commands_reinspect_every_exec_and_export_only_allowlisted_state():
    client = FakeClient()
    report = DIAGNOSTIC.diagnose(PROJECT, client=client)
    assert set(report["workers"]) == set(IDS)
    for service, stage in DIAGNOSTIC.SERVICES.items():
        worker = report["workers"][service]
        assert worker["state"] == state(service)["State"]
        assert worker["health"] == state(service)["Health"] and worker["restart_count"] == 2
        assert worker["record"] == {**RECORD, "heartbeat_age": 1.2, "poll_age": 2.0}
        commands = [command for command, _ in client.commands if command[1] == "exec" and command[2] == IDS[service]]
        assert commands == [
            ["docker", "exec", IDS[service], "python", "-m", "shadai.workers.probe", mode, "--stage", stage]
            for mode in ("startup", "liveness")
        ] + [
            ["docker", "exec", IDS[service], "python", "/app/entrypoint.py", "python", "-m",
             "shadai.workers.probe", "readiness", "--stage", stage],
            ["docker", "exec", IDS[service], "python", "-c", DIAGNOSTIC.RECORD_COMMAND, stage],
        ]
    for index, (command, capture) in enumerate(client.commands):
        if command[1] == "exec":
            assert client.commands[index + 1][0] == [
                "docker", "inspect", "--format", DIAGNOSTIC.INSPECT_FORMAT, command[2],
            ]
            assert capture is (command[4] == "-c")
    raw = DIAGNOSTIC.report_bytes(report)
    assert len(raw) <= 8192
    assert not any(field.encode() in raw for field in ("Created", "Image", "Name", "Project", "Service"))
    assert not any(field in DIAGNOSTIC.INSPECT_FORMAT for field in (".Env", ".Cmd", ".Mounts", ".Health.Log"))


@pytest.mark.parametrize("raw,error", [
    (b"", "missing_container"), (b"a" * 63, "invalid_identity"), (b"g" * 64, "invalid_identity"),
    (b"a" * 64 + b"\n" + b"a" * 64, "invalid_identity"), (SECRET.encode(), "invalid_identity"),
])
def test_missing_malformed_and_duplicate_container_ids_never_exec(raw, error):
    client = FakeClient(ids={name: raw for name in IDS})
    assert all(worker == {"error": error} for worker in DIAGNOSTIC.diagnose(PROJECT, client=client)["workers"].values())
    assert not any(command[1] in {"inspect", "exec"} for command, _ in client.commands)


@pytest.mark.parametrize("field,value", [
    ("Project", "foreign"), ("Service", "foreign"), ("Name", "/foreign-ingest-worker-1"),
    ("Id", "d" * 64), ("Image", "mutable:latest"), ("Image", "sha256:" + "g" * 64),
    ("Created", ""), ("Env", [SECRET]), ("RestartCount", True),
    ("State", {"Status": SECRET, "Running": True, "ExitCode": 0, "OOMKilled": False}),
    ("Health", {"Status": SECRET, "FailingStreak": 1}),
])
def test_foreign_or_invalid_inspection_identity_never_exec_or_export(field, value):
    client = FakeClient(change=lambda record, count: record.update({field: value}))
    report = DIAGNOSTIC.diagnose(PROJECT, client=client)
    assert all(worker == {"error": "invalid_identity"} for worker in report["workers"].values())
    assert not any(command[1] == "exec" for command, _ in client.commands)
    assert SECRET.encode() not in DIAGNOSTIC.report_bytes(report)


@pytest.mark.parametrize("mode", ["startup", "liveness", "readiness", "record"])
@pytest.mark.parametrize("field,value", [("Created", "new-container"), ("Image", "sha256:" + "d" * 64),
                                         ("Project", "foreign"), ("Name", "/foreign")])
def test_identity_drift_after_each_exec_stops_that_worker(mode, field, value):
    stop = ("startup", "liveness", "readiness", "record").index(mode) + 1
    client = FakeClient(change=lambda record, count: record.update({field: value}) if count >= stop else None)
    report = DIAGNOSTIC.diagnose(PROJECT, client=client)
    for service, worker in report["workers"].items():
        assert worker["error"] == "identity_changed"
        assert client.executions[service] == stop
        assert mode not in worker["checks"] and "record" not in worker


@pytest.mark.parametrize("result", [{"exit_code": 37, "error": "nonzero"}, {"error": "timeout"}])
def test_failed_or_timed_out_exec_still_reinspects_and_retains_exact_exit(result):
    client = FakeClient(exec_results={"startup": result})
    report = DIAGNOSTIC.diagnose(PROJECT, client=client)
    assert all(worker["checks"]["startup"] == result for worker in report["workers"].values())
    assert all(count == 4 for count in client.executions.values())
    assert sum(command[1] == "inspect" for command, _ in client.commands) == 10


@pytest.mark.parametrize("raw", [
    SECRET.encode(), b'{"error":"invalid_record"}', b'{"record_valid":true,"record_valid":false}',
    json.dumps({**RECORD, "pid": SECRET}).encode(), json.dumps({**RECORD, "phase": SECRET}).encode(),
    json.dumps({**RECORD, "heartbeat_age": -1}).encode(), json.dumps({**RECORD, "poll_age": 97201}).encode(),
    json.dumps({**RECORD, "cycle_age": float("nan")}).encode(),
    json.dumps({**RECORD, "initialized": 1}).encode(),
])
def test_invalid_or_secret_record_output_becomes_constant_error(raw):
    report = DIAGNOSTIC.diagnose(PROJECT, client=FakeClient(record=raw))
    assert all(worker["record"] == {"record_valid": False, "error": "invalid_record"}
               for worker in report["workers"].values())
    assert SECRET.encode() not in DIAGNOSTIC.report_bytes(report)


@pytest.mark.parametrize("changed", [{}, {"boot_id": "other"}, {"start_ticks": 124},
                                     {"heartbeat_monotonic": 100001}])
def test_record_command_calls_real_identity_and_monotonic_validation(changed, tmp_path, monkeypatch, capsys):
    from shadai.workers import probe

    proc = tmp_path / "proc"
    (proc / "77").mkdir(parents=True)
    (proc / "sys/kernel/random").mkdir(parents=True)
    boot = str(uuid4())
    (proc / "77/stat").write_text("77 (worker name) " + " ".join(["S", *(["0"] * 18), "123"]))
    (proc / "sys/kernel/random/boot_id").write_text(boot)
    record = {
        "schema": 1, "stage": "ingest", "pid": 77, "start_ticks": 123, "boot_id": boot,
        "instance_uuid": str(uuid4()), "initialized": True, "phase": "idle",
        "heartbeat_monotonic": 1, "last_poll_monotonic": 99999.25,
        "phase_started_monotonic": 99999, "last_successful_cycle_monotonic": None, **changed,
    }
    monkeypatch.setattr(probe, "read_probe", lambda stage: probe.validate_probe(record, stage, proc=proc, now=100000))
    alarms = []
    monkeypatch.setattr(DIAGNOSTIC.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(DIAGNOSTIC.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(DIAGNOSTIC.signal, "signal", lambda *args: None)
    monkeypatch.setattr(DIAGNOSTIC.signal, "setitimer", lambda *args: alarms.append(args), raising=False)
    monkeypatch.setattr(sys, "argv", ["-c", "ingest"])
    exec(DIAGNOSTIC.RECORD_COMMAND, {})
    raw = capsys.readouterr().out.encode()
    assert alarms == [(0, 4)]
    result = DIAGNOSTIC.record_summary(raw)
    if changed:
        assert result == {"record_valid": False, "error": "invalid_record"}
    else:
        assert result == {**RECORD, "heartbeat_age": 97200, "poll_age": 0.8}
    assert not any(str(record[field]).encode() in raw for field in ("pid", "instance_uuid", "boot_id"))


def native_client():
    processes = []

    def popen(command, **kwargs):
        assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["stderr"] is subprocess.DEVNULL
        process = subprocess.Popen(command, **kwargs)
        processes.append(process)
        return process

    return DIAGNOSTIC.Client(popen=popen), processes


def test_native_client_suppresses_secret_probe_stdout_and_stderr(capsys):
    client, processes = native_client()
    result = client.run([sys.executable, "-c", f"import sys; print({SECRET!r}); print({SECRET!r}, file=sys.stderr)"],
                        capture=False)
    assert result == {"exit_code": 0}
    assert capsys.readouterr() == ("", "")
    assert processes[0].poll() == 0


def test_native_client_kills_and_reaps_timeout_within_remaining_budget():
    client, processes = native_client()
    client.deadline = time.monotonic() + 0.5
    started = time.monotonic()
    result = client.run([sys.executable, "-c", "import time; time.sleep(10)"])
    assert result == {"error": "timeout"}
    assert time.monotonic() - started < 1
    assert processes[0].poll() is not None and processes[0].stdout.closed


def test_native_client_bounds_stdout_during_read_and_reaps_overflow():
    client, processes = native_client()
    result = client.run([sys.executable, "-c",
                         "import sys,time; sys.stdout.buffer.write(b'x' * 20000); sys.stdout.flush(); time.sleep(10)"])
    assert result == {"error": "output_budget"}
    assert processes[0].poll() is not None and processes[0].stdout.closed


def test_native_client_accepts_exact_stdout_boundary_and_retains_nonzero_exit():
    client, _ = native_client()
    result = client.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 16384)"])
    assert result == {"exit_code": 0, "stdout": b"x" * 16384}
    result = client.run([sys.executable, "-c", f"import sys; print({SECRET!r}); sys.exit(37)"])
    assert result == {"exit_code": 37, "error": "nonzero"}


def lifecycle_client(monkeypatch, *, primary=None, interrupt=None, failures=(), posix=False):
    calls = []
    secondary = RuntimeError(SECRET)

    class Pipe:
        def close(self):
            calls.append(("close",))
            if "close" in failures:
                raise secondary

    class Process:
        pid = 77
        returncode = None
        stdout = Pipe()
        killed = False
        waits = 0

        def wait(self, *, timeout):
            self.waits += 1
            calls.append(("wait", timeout))
            if self.waits == 1 and interrupt == "process_wait":
                raise primary
            if self.killed and "wait" in failures:
                raise secondary
            self.returncode = -9 if self.killed else 0

        def kill(self):
            calls.append(("kill", self.pid))
            self.killed = True
            if "kill" in failures:
                raise secondary

    class Event:
        def __init__(self):
            if interrupt == "event_create":
                raise primary

        def wait(self, timeout):
            calls.append(("ready", timeout))
            if interrupt == "ready_wait":
                raise primary
            return True

    class Reader:
        def __init__(self, **kwargs):
            if interrupt == "reader_create":
                raise primary

        def start(self):
            calls.append(("start",))
            if interrupt == "reader_start":
                raise primary

        def join(self, *, timeout):
            calls.append(("join", timeout))
            if "join" in failures:
                raise secondary

        def is_alive(self):
            if "is_alive" in failures:
                raise secondary
            return False

    process = Process()

    def killpg(pid, sig):
        calls.append(("killpg", pid, sig))
        process.killed = True
        if "killpg" in failures:
            raise OSError(SECRET)
        if "killpg_cancel" in failures:
            raise SystemExit(SECRET)

    def popen(command, **kwargs):
        assert kwargs["start_new_session"] is posix
        assert kwargs["stderr"] is subprocess.DEVNULL and kwargs["stdin"] is subprocess.DEVNULL
        return process

    monkeypatch.setattr(DIAGNOSTIC, "threading", SimpleNamespace(Event=Event, Thread=Reader))
    monkeypatch.setattr(DIAGNOSTIC, "os", SimpleNamespace(name="posix" if posix else "nt", killpg=killpg))
    if posix:
        monkeypatch.setattr(DIAGNOSTIC.signal, "SIGKILL", 9, raising=False)
    return DIAGNOSTIC.Client(popen=popen), process, calls


@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize("interrupt,capture", [
    ("event_create", True), ("reader_create", True), ("reader_start", True), ("ready_wait", True),
    ("process_wait", True), ("process_wait", False),
])
def test_any_post_spawn_interruption_cleans_owned_client_and_preserves_exact_primary(
    kind, interrupt, capture, monkeypatch, capsys,
):
    primary = kind(SECRET)
    client, process, calls = lifecycle_client(monkeypatch, primary=primary, interrupt=interrupt)
    with pytest.raises(kind) as caught:
        client.run(["docker", "fixed"], capture=capture)
    assert caught.value is primary
    assert process.killed and process.returncode == -9
    assert process.waits == (2 if interrupt == "process_wait" else 1)
    assert ("kill", 77) in calls and all(0 <= call[1] <= 5 for call in calls if call[0] in {"wait", "join"})
    if capture:
        assert ("close",) in calls
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failures", [("kill",), ("wait",), ("join",), ("close",),
                                      ("kill", "wait", "join", "close", "is_alive")])
def test_secondary_cleanup_failure_never_masks_primary_or_emits_private_error(failures, monkeypatch, capsys):
    primary = KeyboardInterrupt(SECRET)
    client, process, calls = lifecycle_client(
        monkeypatch, primary=primary, interrupt="ready_wait", failures=failures,
    )
    with pytest.raises(KeyboardInterrupt) as caught:
        client.run(["docker", "fixed"])
    assert caught.value is primary and process.killed
    assert any(call[0] == "wait" for call in calls) and any(call[0] == "join" for call in calls)
    assert ("close",) in calls and capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failure", ["join", "is_alive", "close"])
def test_successful_command_with_cleanup_failure_returns_only_constant_error(failure, monkeypatch, capsys):
    client, process, _ = lifecycle_client(monkeypatch, failures=(failure,))
    assert client.run(["docker", "fixed"]) == {"error": "nonzero"}
    assert process.returncode == 0 and capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failure", ["killpg", "killpg_cancel"])
def test_cancellation_kills_only_owned_posix_group_then_reaps_with_pid_fallback(failure, monkeypatch):
    primary = SystemExit(SECRET)
    client, process, calls = lifecycle_client(
        monkeypatch, primary=primary, interrupt="process_wait", failures=(failure,), posix=True,
    )
    with pytest.raises(SystemExit) as caught:
        client.run(["docker", "fixed"], capture=False)
    assert caught.value is primary and process.returncode == -9
    assert ("killpg", 77, DIAGNOSTIC.signal.SIGKILL) in calls and ("kill", 77) in calls
    assert process.waits == 2


def test_cancellation_cleanup_cannot_extend_global_remaining_deadline(monkeypatch):
    primary = KeyboardInterrupt(SECRET)
    client, process, calls = lifecycle_client(monkeypatch)
    clock = SimpleNamespace(now=29)
    client.deadline = 30
    client.clock = lambda: clock.now

    def wait(*, timeout):
        process.waits += 1
        calls.append(("wait", timeout))
        if process.waits == 1:
            clock.now += timeout
            raise primary
        assert timeout <= 30 - clock.now
        clock.now += timeout / 2
        process.returncode = -9

    process.wait = wait
    with pytest.raises(KeyboardInterrupt) as caught:
        client.run(["docker", "fixed"], capture=False)
    assert caught.value is primary and process.killed and clock.now <= 30
    assert process.waits == 2 and all(0 <= call[1] <= 1 for call in calls if call[0] == "wait")


@pytest.mark.parametrize("capture", [True, False])
@pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
def test_native_cancellation_kills_and_reaps_before_propagating_primary(capture, kind, monkeypatch):
    primary = kind(SECRET)
    processes = []

    class Ready:
        def wait(self, timeout):
            raise primary

        def set(self):
            pass

    def popen(command, **kwargs):
        process = subprocess.Popen(command, **kwargs)
        processes.append(process)
        original_wait = process.wait
        calls = 0

        def wait(*, timeout):
            nonlocal calls
            calls += 1
            if not capture and calls == 1:
                raise primary
            return original_wait(timeout=timeout)

        process.wait = wait
        return process

    monkeypatch.setattr(DIAGNOSTIC, "threading", SimpleNamespace(Event=Ready, Thread=DIAGNOSTIC.threading.Thread))
    client = DIAGNOSTIC.Client(popen=popen)
    with pytest.raises(kind) as caught:
        client.run([sys.executable, "-c", "import time; time.sleep(10)"], capture=capture)
    assert caught.value is primary and processes[0].poll() is not None
    if capture:
        assert processes[0].stdout.closed


def test_fake_monotonic_deadline_caps_every_command_and_never_starts_after_expiry(monkeypatch):
    clock = SimpleNamespace(now=0)
    starts, waits, kills = [], [], []

    class Process:
        pid = 77
        returncode = None

        def wait(self, *, timeout):
            waits.append(timeout)
            if not kills:
                clock.now += timeout
                raise subprocess.TimeoutExpired("redacted", timeout)
            self.returncode = -9

        def kill(self):
            kills.append(True)

    def popen(*args, **kwargs):
        starts.append(clock.now)
        return Process()

    monkeypatch.setattr(DIAGNOSTIC.os, "killpg", lambda *args: kills.append(True), raising=False)
    client = DIAGNOSTIC.Client(clock=lambda: clock.now, popen=popen)
    clock.now = 29
    assert client.run(["docker", "fixed"], capture=False) == {"error": "timeout"}
    assert all(0 <= wait <= 1 for wait in waits) and kills
    clock.now = 30
    assert client.run(["docker", "fixed"], capture=False) == {"error": "deadline"}
    assert starts == [29]


@pytest.mark.parametrize("capture", [False, True])
def test_clock_advance_between_budget_reads_cannot_extend_global_deadline(capture, monkeypatch):
    client, process, _ = lifecycle_client(monkeypatch)
    clock = SimpleNamespace(now=29, advance=True)
    grants = []

    def now():
        value = clock.now
        if clock.advance:
            clock.now = 29.8
            clock.advance = False
        return value

    def wait(*, timeout):
        grants.append(("wait", clock.now, timeout))
        clock.now += timeout
        process.waits += 1
        if not process.killed:
            raise subprocess.TimeoutExpired("redacted", timeout)
        process.returncode = -9

    class Ready:
        def wait(self, timeout):
            grants.append(("ready", clock.now, timeout))
            clock.now += timeout
            return False

    class Reader:
        def __init__(self, **kwargs):
            pass

        def start(self):
            pass

        def join(self, *, timeout):
            grants.append(("join", clock.now, timeout))
            clock.now += timeout

        def is_alive(self):
            return False

    process.wait = wait
    client.clock = now
    client.deadline = 30
    monkeypatch.setattr(DIAGNOSTIC, "threading", SimpleNamespace(Event=Ready, Thread=Reader))
    assert client.run(["docker", "fixed"], capture=capture) == {"error": "timeout"}
    assert process.killed and process.returncode == -9
    assert clock.now <= 30
    assert all(0 <= timeout <= 30 - started for _, started, timeout in grants)


def test_global_deadline_is_reported_for_both_workers_without_any_exec():
    client = DIAGNOSTIC.Client(clock=lambda: 0)
    client.clock = lambda: 30
    assert DIAGNOSTIC.diagnose(PROJECT, client=client) == {
        "schema": 1, "workers": {service: {"error": "deadline"} for service in IDS},
    }


def test_final_report_budget_and_required_explicit_cli_arguments(tmp_path, monkeypatch):
    assert len(DIAGNOSTIC.report_bytes({"data": "x" * 10000})) <= 8192
    assert json.loads(DIAGNOSTIC.report_bytes({"data": "x" * 10000}))["error"] == "output_budget"
    for arguments in ([], ["--output", "artifact.json"], ["--project", PROJECT],
                      ["--project", "foreign", "--output", "artifact.json"]):
        with pytest.raises(SystemExit) as error:
            DIAGNOSTIC.main(arguments)
        assert error.value.code == 2
    report = DIAGNOSTIC.diagnose(PROJECT, client=FakeClient())
    monkeypatch.setattr(DIAGNOSTIC, "diagnose", lambda project: report)
    output = tmp_path / "artifacts/diagnostic.json"
    assert DIAGNOSTIC.main(["--project", PROJECT, "--output", str(output)]) == 0
    assert json.loads(output.read_bytes()) == report


def workflow_steps():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"][
        "compose-integration"]["steps"]


@pytest.mark.parametrize("wait_exit,diagnostic_exit", [(0, 0), (37, 0), (37, 83), (1, 83)])
def test_ci_preserves_original_wait_failure_even_when_diagnostic_fails(wait_exit, diagnostic_exit, tmp_path):
    steps = workflow_steps()
    run = next(step["run"] for step in steps if step.get("name") ==
               "Initialize actual groups and indexed retention before readiness")
    assert "--wait --wait-timeout 180 api ingest-worker correlation-worker purge-worker frontend" in run
    assert run.index("redis_lifecycle reconcile") < run.index("if docker compose up -d --wait")
    wrapper = run[run.index("if docker compose up -d --wait"):]
    bash = str(Path("C:/Program Files/Git/bin/bash.exe")) if os.name == "nt" else shutil.which("bash")
    if not bash or not Path(bash).is_file():
        pytest.skip("Bash unavailable for actual CI shell exit handling")
    marker = tmp_path / "called.txt"
    script = f"""docker() {{ return {wait_exit}; }}
python() {{ printf 'diagnostic-called\\n' >> "$DIAGNOSTIC_MARKER"; return {diagnostic_exit}; }}
{wrapper}
"""
    result = subprocess.run([bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
                            capture_output=True, text=True, timeout=5,
                            env={**os.environ, "DIAGNOSTIC_MARKER": marker.as_posix()})
    assert result.returncode == wait_exit and result.stdout == "" and result.stderr == ""
    assert marker.is_file() is bool(wait_exit)
    assert "|| true" in wrapper and 'exit "$wait_status"' in wrapper
    assert "scripts/diagnose-compose-workers.py --project open-shadow-ai --output" in wrapper


def test_ci_diagnostic_artifact_is_always_uploaded_if_present_and_documented():
    steps = workflow_steps()
    upload = next(step for step in steps if step.get("name") ==
                  "Retain bounded worker diagnostic after readiness failure")
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "ignore"
    assert upload["with"]["path"] == "artifacts/compose-worker-diagnostic.json"
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert "continue-on-error" not in upload
    document = ROOT / "docs/worker-diagnostics.md"
    assert document.is_file()
    assert "[Compose worker diagnostics](worker-diagnostics.md)" in (
        ROOT / "docs/production-delivery.md").read_text(encoding="utf-8")
