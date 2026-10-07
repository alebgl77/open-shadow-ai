"""Collect bounded, allowlisted worker state after an explicit Compose wait failure."""

import argparse
import json
import math
import os
import re
import signal
import subprocess
import threading
import time
from contextlib import suppress
from pathlib import Path

SERVICES = {"ingest-worker": "ingest", "correlation-worker": "correlation"}
PHASES = {"starting", "idle", "poll", "handler", "blocked", "failed", "purge", "sleep"}
STATUSES = {"created", "restarting", "running", "removing", "paused", "exited", "dead"}
OUTPUT_LIMIT = 16 * 1024
REPORT_LIMIT = 8 * 1024
INSPECT_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Created":{{json .Created}},"Image":{{json .Image}},'
    '"Project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"Service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
    '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}}},'
    '"RestartCount":{{json .RestartCount}},"Health":{{if .State.Health}}'
    '{"Status":{{json .State.Health.Status}},"FailingStreak":{{json .State.Health.FailingStreak}}}'
    '{{else}}null{{end}}}'
)
RECORD_COMMAND = """import json, os, signal, sys
signal.signal(signal.SIGALRM, lambda *_: os._exit(1))
signal.setitimer(signal.ITIMER_REAL, 4)
try:
    from shadai.workers.probe import read_probe
    value, now = read_probe(sys.argv[1])
    def age(field):
        moment = value[field]
        return None if moment is None else round(min(97200, now - moment), 1)
    result = {
        "record_valid": True, "initialized": value["initialized"], "phase": value["phase"],
        "heartbeat_age": age("heartbeat_monotonic"), "poll_age": age("last_poll_monotonic"),
        "cycle_age": age("last_successful_cycle_monotonic"),
    }
except Exception:
    result = {"error": "invalid_record"}
print(json.dumps(result, separators=(",", ":"), allow_nan=False))
"""


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def bounded_integer(value, low=0):
    return type(value) is int and low <= value <= 2147483647


class Client:
    """Bound client time and pipe memory without retaining diagnostic stderr."""

    def __init__(self, *, clock=None, popen=None):
        self.clock = clock or time.monotonic
        self.popen = popen or subprocess.Popen
        self.deadline = self.clock() + 30

    def run(self, command, *, capture=True):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            return {"error": "deadline"}
        expires = min(self.deadline, self.clock() + 5)
        # Reserve part of this command's budget for killing and reaping the client.
        work_expires = max(self.clock(), expires - 0.2)
        process = None
        reader = None
        error = None
        primary = None
        cleanup_failed = False

        def cleanup(action):
            nonlocal cleanup_failed
            try:
                return action()
            except BaseException:
                cleanup_failed = True

        def kill():
            nonlocal cleanup_failed
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    return
                except OSError:
                    pass
                except BaseException:
                    cleanup_failed = True
            process.kill()

        try:
            try:
                process = self.popen(
                    command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=os.name == "posix",
                )
            except OSError:
                return {"error": "nonzero"}
            raw = bytearray()
            ready = threading.Event()
            failure = []

            def read():
                try:
                    while True:
                        chunk = os.read(process.stdout.fileno(), min(4096, OUTPUT_LIMIT + 1 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                        if len(raw) > OUTPUT_LIMIT:
                            failure.append("output_budget")
                            break
                except BaseException:
                    failure.append("nonzero")
                finally:
                    with suppress(BaseException):
                        ready.set()

            reader = threading.Thread(target=read, daemon=True) if capture else None
            if reader:
                reader.start()
            if reader and not ready.wait(max(0, work_expires - self.clock())):
                error = "timeout"
            elif failure:
                error = failure[0]
            else:
                process.wait(timeout=max(0, work_expires - self.clock()))
        except subprocess.TimeoutExpired:
            error = "timeout"
        except BaseException as exception:
            primary = exception
        finally:
            if process is not None and (error or primary is not None):
                cleanup(kill)
                cleanup(lambda: process.wait(timeout=max(0, expires - self.clock())))
            if reader:
                cleanup(lambda: reader.join(timeout=max(0, expires - self.clock())))
                if cleanup(reader.is_alive) is not False:
                    cleanup_failed = True
            if capture and process is not None:
                cleanup(process.stdout.close)
        if primary is not None:
            raise primary
        if cleanup_failed:
            return {"error": "nonzero"}
        if error:
            return {"error": error}
        if not bounded_integer(process.returncode, -2147483648):
            return {"error": "nonzero"}
        result = {"exit_code": process.returncode}
        if process.returncode:
            result["error"] = "nonzero"
        if capture and not process.returncode:
            result["stdout"] = bytes(raw)
        return result


def inspection(client, container, project, service):
    result = client.run(["docker", "inspect", "--format", INSPECT_FORMAT, container])
    if result.get("error"):
        return None, result["error"]
    try:
        value = decode(result["stdout"])
        if not isinstance(value, dict) or set(value) != {
            "Id", "Name", "Created", "Image", "Project", "Service", "State", "RestartCount", "Health",
        }:
            raise ValueError
        if (
            value["Id"] != container or value["Name"] != f"/{project}-{service}-1"
            or value["Project"] != project or value["Service"] != service
            or not isinstance(value["Created"], str) or not 0 < len(value["Created"]) <= 128
            or not isinstance(value["Image"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["Image"])
        ):
            raise ValueError
        state = value["State"]
        if (
            not isinstance(state, dict) or set(state) != {"Status", "Running", "ExitCode", "OOMKilled"}
            or state["Status"] not in STATUSES or type(state["Running"]) is not bool
            or type(state["OOMKilled"]) is not bool or not bounded_integer(state["ExitCode"])
            or not bounded_integer(value["RestartCount"])
        ):
            raise ValueError
        health = value["Health"]
        if health is not None and (
            not isinstance(health, dict) or set(health) != {"Status", "FailingStreak"}
            or health["Status"] not in {"starting", "healthy", "unhealthy"}
            or not bounded_integer(health["FailingStreak"])
        ):
            raise ValueError
        return value, None
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None, "invalid_identity"


def identity(value):
    return tuple(value[key] for key in ("Id", "Name", "Created", "Image", "Project", "Service"))


def record_summary(raw):
    try:
        value = decode(raw)
        if not isinstance(value, dict) or set(value) != {
            "record_valid", "initialized", "phase", "heartbeat_age", "poll_age", "cycle_age",
        }:
            raise ValueError
        if value["record_valid"] is not True or type(value["initialized"]) is not bool or value["phase"] not in PHASES:
            raise ValueError
        for key in ("heartbeat_age", "poll_age", "cycle_age"):
            age = value[key]
            if age is None and key != "heartbeat_age":
                continue
            if type(age) not in {int, float} or not math.isfinite(age) or not 0 <= age <= 97200:
                raise ValueError
            value[key] = round(age, 1)
        return value
    except (ValueError, TypeError, KeyError, UnicodeError):
        return {"record_valid": False, "error": "invalid_record"}


def diagnose(project, *, client=None):
    client = client or Client()
    workers = {}
    for service, stage in SERVICES.items():
        worker = workers[service] = {}
        found = client.run(["docker", "compose", "--project-name", project, "ps", "--all", "--quiet", service])
        if found.get("error"):
            worker["error"] = found["error"]
            continue
        ids = found.get("stdout", b"").split()
        if not ids:
            worker["error"] = "missing_container"
            continue
        if len(ids) != 1 or not re.fullmatch(rb"[a-f0-9]{64}", ids[0]):
            worker["error"] = "invalid_identity"
            continue
        container = ids[0].decode("ascii")
        before, error = inspection(client, container, project, service)
        if error:
            worker["error"] = error
            continue
        worker.update({"state": before["State"], "restart_count": before["RestartCount"], "health": before["Health"]})
        checks = worker["checks"] = {}
        commands = {
            "startup": ["python", "-m", "shadai.workers.probe", "startup", "--stage", stage],
            "liveness": ["python", "-m", "shadai.workers.probe", "liveness", "--stage", stage],
            "readiness": ["python", "/app/entrypoint.py", "python", "-m", "shadai.workers.probe",
                          "readiness", "--stage", stage],
            "record": ["python", "-c", RECORD_COMMAND, stage],
        }
        for mode, command in commands.items():
            result = client.run(["docker", "exec", container, *command], capture=mode == "record")
            after, error = inspection(client, container, project, service)
            if error or identity(before) != identity(after):
                worker["error"] = "identity_changed" if error == "invalid_identity" or not error else error
                break
            checks[mode] = {key: result[key] for key in ("exit_code", "error") if key in result}
            if mode == "record" and not result.get("error"):
                worker["record"] = record_summary(result.get("stdout", b""))
            if result.get("error") == "deadline":
                break
    return {"schema": 1, "workers": workers}


def report_bytes(report):
    raw = json.dumps(report, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > REPORT_LIMIT:
        return b'{"schema":1,"error":"output_budget"}\n'
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, choices=("open-shadow-ai",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = diagnose(args.project)
    except Exception:
        report = {"schema": 1, "error": "nonzero"}
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(report_bytes(report))
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
