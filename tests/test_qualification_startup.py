"""Startup failure diagnostics without executing or claiming Docker proof."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadai.qualification.journal import RunJournal, atomic_json
from shadai.qualification.lab import Docker, DockerOperationError, Laboratory, failure_evidence
from shadai.qualification.schemas import load_profile

ROOT = Path(__file__).resolve().parents[1]
SECRET = "https://user:private-token@secret.example.test/provider?key=private-token"


def prepared_lab(tmp_path, monkeypatch):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    lab = Laboratory(ROOT, tmp_path / "run", profile, "exact-context")

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
