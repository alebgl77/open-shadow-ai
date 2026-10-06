"""Startup failure diagnostics without executing or claiming Docker proof."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadai.qualification.journal import LABEL, RunJournal, atomic_json, resource_identity
from shadai.qualification.lab import WRITERS, Docker, DockerOperationError, Laboratory, failure_evidence
from shadai.qualification.schemas import QualificationError, load_profile

ROOT = Path(__file__).resolve().parents[1]
SECRET = "https://user:private-token@secret.example.test/provider?key=private-token"


def prepared_lab(tmp_path, monkeypatch):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    lab = Laboratory(ROOT, tmp_path / "run", profile, "exact-context")
    monkeypatch.setattr("shadai.qualification.lab.os.getuid", lambda: 1001, raising=False)
    monkeypatch.setattr("shadai.qualification.lab.os.getgid", lambda: 1001, raising=False)

    def prepare(resume):
        lab.journal = RunJournal.create(lab.directory, profile, lab.config_hash, lab.context)
        lab.tenant = "q-" + lab.journal.value["run_id"].replace("-", "")
        atomic_json(lab.directory / "source.json", {"unit_test": True})

    monkeypatch.setattr(lab, "prepare", prepare)
    monkeypatch.setattr(lab, "compose", Mock(return_value=""))
    monkeypatch.setattr(lab, "discover", Mock())
    monkeypatch.setattr(lab, "change", Mock())
    monkeypatch.setattr(lab, "inspector", Mock(return_value={}))
    monkeypatch.setattr(lab, "wait_ready", Mock(return_value="http://127.0.0.1:12345"))
    return lab


@pytest.mark.parametrize("stage", [
    "starting_compose", "starting_discover", "initialize_stop", "initialize_inspector", "initialize_start",
    "readiness", "enroll",
])
def test_failure_before_scenarios_keeps_stage_without_message(tmp_path, monkeypatch, stage):
    lab = prepared_lab(tmp_path, monkeypatch)
    error = RuntimeError(SECRET)
    if stage == "starting_compose":
        lab.compose.side_effect = error
    elif stage == "starting_discover":
        lab.discover.side_effect = error
    elif stage in {"initialize_stop", "initialize_start"}:
        lab.change.side_effect = [error] if stage == "initialize_stop" else [None, error]
    elif stage in {"initialize_inspector", "enroll"}:
        lab.inspector.side_effect = [error] if stage == "initialize_inspector" else [{}, error]
    else:
        lab.wait_ready.side_effect = error
    assert lab.execute() == 2
    result = json.loads((lab.directory / "report.json").read_text())
    assert result["scenarios"] == []
    assert set(lab.profile["scenarios"]) <= set(result["missing_evidence"])
    assert result["evidence"]["failure"] == {
        "phase": "initialized" if stage in {"initialize_start", "readiness", "enroll"} else "starting",
        "stage": stage, "error_type": "RuntimeError", "code": "exception",
    }
    assert SECRET not in json.dumps(result)
    assert lab.journal.value["phase"] == "interrupted"
    if stage == "starting_compose":
        lab.discover.assert_called_once_with()


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt(SECRET)])
def test_discover_failure_preserves_primary_and_cancellation(tmp_path, monkeypatch, primary):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.compose.side_effect = primary
    lab.discover.side_effect = PermissionError(SECRET)
    assert lab.execute() == 2
    result = json.loads((lab.directory / "report.json").read_text())
    failure = result["evidence"]["failure"]
    assert failure["stage"] == "starting_compose"
    assert failure["error_type"] == type(primary).__name__
    assert failure["secondary"] == [{
        "phase": "starting", "stage": "starting_discover", "error_type": "PermissionError", "code": "exception",
    }]
    if type(primary) is DockerOperationError:
        assert failure["code"] == "docker_nonzero" and failure["returncode"] == 17
    assert lab.journal.value["cancelled"] is isinstance(primary, KeyboardInterrupt)
    assert lab.journal.value["phase"] == ("cancelled" if isinstance(primary, KeyboardInterrupt) else "interrupted")
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("secondary", [KeyboardInterrupt(SECRET), SystemExit(SECRET)])
def test_discover_cancellation_survives_prior_compose_failure(tmp_path, monkeypatch, secondary):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.compose.side_effect = DockerOperationError("docker_nonzero", 17)
    lab.discover.side_effect = secondary
    assert lab.execute() == 2
    result = json.loads((lab.directory / "report.json").read_text())
    assert result["evidence"]["failure"] == {
        "phase": "starting", "stage": "starting_compose", "error_type": "DockerOperationError",
        "code": "docker_nonzero", "returncode": 17,
        "secondary": [{"phase": "starting", "stage": "starting_discover", "error_type": type(secondary).__name__,
                       "code": "exception"}],
    }
    assert result["exit_code"] == 2 and result["scenarios"] == []
    assert lab.journal.value["cancelled"] is True
    assert lab.journal.value["phase"] == "cancelled"
    assert SECRET not in json.dumps(result)


def test_unknown_exception_class_and_scenario_reason_cannot_publish_secrets(tmp_path, monkeypatch):
    lab = prepared_lab(tmp_path, monkeypatch)
    malicious = type(SECRET, (RuntimeError,), {})(SECRET)
    monkeypatch.setattr(lab, "send", Mock(side_effect=malicious))
    assert lab.execute() == 2
    result = json.loads((lab.directory / "report.json").read_text())
    assert result["scenarios"][0]["reason"] == "UnexpectedError"
    assert result["evidence"]["failure"] == {
        "phase": "baseline", "stage": "scenario", "error_type": "UnexpectedError", "code": "exception",
    }
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("kind,expected,returncode", [
    ("nonzero", "docker_nonzero", 27), ("timeout", "docker_timeout", None),
    ("process", "docker_process_error", None), ("output", "docker_output_budget", 0),
])
def test_docker_diagnostics_exclude_upstream_args_and_output(kind, expected, returncode):
    def runner(command, **kwargs):
        if kind == "timeout":
            raise subprocess.TimeoutExpired([SECRET], 1, output=SECRET, stderr=SECRET)
        if kind == "process":
            raise OSError(SECRET)
        return SimpleNamespace(returncode=27 if kind == "nonzero" else 0, stderr=SECRET,
                               stdout="x" * (4 * 1048576 + 1) if kind == "output" else SECRET)

    with pytest.raises(DockerOperationError) as caught:
        Docker("exact-context", runner=runner).call("compose", "up", SECRET)
    value = failure_evidence(caught.value, "starting", "starting_compose")
    assert value["code"] == expected
    assert value.get("returncode") == returncode
    assert SECRET not in str(caught.value) and SECRET not in json.dumps(value)


@pytest.mark.parametrize("value", [True, 256, -256, SECRET, None])
def test_unbounded_or_noninteger_exit_status_is_not_published(value):
    error = DockerOperationError("docker_nonzero", value)
    assert "returncode" not in failure_evidence(error, "starting", "starting_compose")


@pytest.mark.parametrize("value", [-255, 255])
def test_exit_status_exact_bounds_are_preserved(value):
    assert failure_evidence(DockerOperationError("docker_nonzero", value), "starting", "starting_compose")[
        "returncode"
    ] == value


def test_mutated_diagnostic_fields_fall_back_to_fixed_values():
    error = DockerOperationError(SECRET, SECRET)
    error.code, error.returncode = [SECRET], SECRET
    assert failure_evidence(error, SECRET, [SECRET]) == {
        "phase": "unknown", "stage": "unknown", "error_type": "DockerOperationError", "code": "docker_process_error",
    }


def test_successful_report_does_not_add_failure_evidence(tmp_path, monkeypatch):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.profile["scenarios"] = ["baseline"]
    monkeypatch.setattr(lab, "send", Mock(return_value={"accepted": lab.profile["load"]["total_events"]}))
    monkeypatch.setattr(lab, "drain", Mock(return_value={}))
    monkeypatch.setattr(lab, "execute_special", Mock())
    assert lab.execute() == 0
    assert "failure" not in json.loads((lab.directory / "report.json").read_text())["evidence"]


def test_cli_exception_class_name_is_not_public_output(tmp_path, monkeypatch, capsys):
    spec = importlib.util.spec_from_file_location("qualification_lab_entry", ROOT / "scripts/qualification-lab.py")
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    monkeypatch.setattr(entry, "load_profile", Mock(side_effect=type(SECRET, (ValueError,), {})(SECRET)))
    assert entry.main(["run", "--profile", "unused", "--run-dir", str(tmp_path), "--execute"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "schema": 1, "status": "not_evaluated", "reason": "UnexpectedError", "exit_code": 2,
    }


class OneOffDocker:
    """Docker lookup semantics; Compose build progress is not a container identity."""

    def __init__(self, lab, output, corrupt=None):
        self.lab, self.output, self.corrupt = lab, output, corrupt
        self.containers, self.calls = {}, []
        self.helper_id = "a" * 64
        for index, service in enumerate(sorted(WRITERS)):
            container = self.inspection(f"{index + 1:064x}", service)
            self.containers[container["Id"]] = container
            lab.journal.add_resources([resource_identity(
                "container", container, lab.journal.value["run_id"], "source", lab.journal.value["projects"]["source"]
            )])

    def inspection(self, identifier, service):
        return {
            "Id": identifier, "Created": "2026-10-06T00:00:00Z", "Image": "sha256:" + "b" * 64,
            "Config": {"Labels": {
                LABEL + "run": self.lab.journal.value["run_id"], LABEL + "role": "source",
                "com.docker.compose.project": self.lab.journal.value["projects"]["source"],
                "com.docker.compose.service": service,
            }}, "State": {"Running": service != "inspector"},
        }

    def runner(self, command, **kwargs):
        args = command[3:]
        self.calls.append(tuple(args))
        if args[0] == "compose":
            assert args[7:10] == ["run", "--no-deps", "-d"]
            assert "--rm" not in args
            assert all(not container["State"]["Running"] for container in self.containers.values())
            name = args[args.index("--name") + 1]
            self.helper_name = name
            self.helper = self.inspection(self.helper_id, "inspector")
            self.helper["Name"] = "/" + name
            if self.corrupt in {"Id", "Created", "Image", "Name"}:
                self.helper[self.corrupt] = None if self.corrupt == "Created" else "invalid"
            elif self.corrupt == "preexisting":
                self.helper["Config"]["Labels"][LABEL + "role"] = "foreign"
            elif self.corrupt:
                self.helper["Config"]["Labels"][self.corrupt] = "foreign"
            self.containers[self.helper_id] = self.helper
            if self.corrupt == "preexisting":
                return SimpleNamespace(returncode=1, stdout="", stderr="Conflict. Container name is in use: " + SECRET)
            if self.corrupt == "absent":
                self.containers.pop(self.helper_id)
            stdout = self.output.replace("<ID>", self.helper_id)
        elif args[:2] == ["container", "inspect"]:
            lookup = self.helper_id if getattr(self, "helper_name", None) == args[2] else args[2]
            if lookup not in self.containers:
                return SimpleNamespace(returncode=1, stdout="", stderr="No such container: " + SECRET)
            stdout = json.dumps([self.containers[lookup]])
        elif args[0] == "container":
            operation, identifier = args[1:3]
            assert identifier in self.containers
            if operation in {"stop", "start"}:
                self.containers[identifier]["State"]["Running"] = operation == "start"
                stdout = identifier
            else:
                assert identifier == self.helper_id
                if operation == "wait":
                    if getattr(self, "wait_error", None) is not None:
                        raise self.wait_error
                    stdout = "0"
                elif operation == "logs":
                    stdout = '{"initialized":true,"retention":{"schema":1}}'
                else:
                    assert operation == "rm"
                    self.containers.pop(identifier)
                    stdout = identifier
        else:
            pytest.fail("Unexpected Docker operation")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")


@pytest.mark.parametrize("output", ["<ID>", "#1 building\n" + SECRET + "\n<ID>", "<ID>\n#2 done", "f" * 64])
def test_one_off_identity_survives_build_progress_with_writers_stopped(tmp_path, monkeypatch, output):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.prepare(False)
    cli = OneOffDocker(lab, output)
    lab.docker = Docker("exact-context", runner=cli.runner)
    lab.compose = Laboratory.compose.__get__(lab)
    lab.change = Laboratory.change.__get__(lab)
    lab.change("stop", WRITERS)
    assert Laboratory.inspector(lab, "initialize") == {"initialized": True, "retention": {"schema": 1}}
    assert all(not container["State"]["Running"] for container in cli.containers.values())
    assert len(lab.journal.value["resources"]) == len(WRITERS)
    helper_commands = [args for args in cli.calls if args[:2] in {
        ("container", "wait"), ("container", "logs"), ("container", "rm"),
    }]
    assert [args[1] for args in helper_commands] == ["wait", "logs", "rm"]
    assert all(args[2] == cli.helper_id for args in helper_commands)


@pytest.mark.parametrize("label", [LABEL + "run", LABEL + "role", "com.docker.compose.project",
                                    "com.docker.compose.service", "Id", "Created", "Image", "Name", "preexisting",
                                    "absent"])
def test_one_off_named_lookup_never_accepts_or_removes_foreign_container(tmp_path, monkeypatch, label):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.prepare(False)
    cli = OneOffDocker(lab, "<ID>", label)
    lab.docker = Docker("exact-context", runner=cli.runner)
    lab.compose = Laboratory.compose.__get__(lab)
    lab.change = Laboratory.change.__get__(lab)
    lab.change("stop", WRITERS)
    with pytest.raises(QualificationError):
        Laboratory.inspector(lab, "initialize")
    assert (cli.helper_id in cli.containers) is (label != "absent")
    assert len(lab.journal.value["resources"]) == len(WRITERS)
    assert not any(args[:2] in {("container", "wait"), ("container", "logs"), ("container", "rm")}
                   for args in cli.calls)


@pytest.mark.parametrize("error", [KeyboardInterrupt(SECRET), SystemExit(SECRET),
                                   DockerOperationError("docker_nonzero", 7)])
def test_one_off_wait_failure_keeps_writers_stopped_and_removes_owned_helper(tmp_path, monkeypatch, error):
    lab = prepared_lab(tmp_path, monkeypatch)
    lab.prepare(False)
    cli = OneOffDocker(lab, "#1 building\n<ID>")
    cli.wait_error = error
    lab.docker = Docker("exact-context", runner=cli.runner)
    lab.compose = Laboratory.compose.__get__(lab)
    lab.change = Laboratory.change.__get__(lab)
    lab.change("stop", WRITERS)
    with pytest.raises(type(error)):
        Laboratory.inspector(lab, "initialize")
    assert cli.helper_id not in cli.containers
    assert len(lab.journal.value["resources"]) == len(WRITERS)
    assert all(not container["State"]["Running"] for container in cli.containers.values())
