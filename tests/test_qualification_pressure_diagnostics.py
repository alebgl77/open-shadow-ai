"""Constant post-pressure diagnostics at the Docker CLI boundary; no Docker proof."""

import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadai.qualification.journal import LABEL, RunJournal, atomic_json, resource_identity
from shadai.qualification.lab import (
    DOCKER_OPERATION_NAMES,
    PRESSURE_CHECKPOINTS,
    Docker,
    DockerOperationError,
    Laboratory,
    docker_operation,
    failure_evidence,
)
from shadai.qualification.schemas import load_profile

ROOT = Path(__file__).resolve().parents[1]
CANARY = "https://user:private-token@secret.example.test/password?argv=private-token"
ARCHIVE = b"bounded synthetic cold archive"
PAIR_STEPS = {
    "seed": {"name_inspect": "container_inspect", "launch": "compose_run", "capture": "container_inspect",
             "wait": "container_wait", "reinspect": "container_inspect", "cleanup_inspect": "container_inspect",
             "remove_inspect": "container_inspect", "remove": "container_rm"},
    "stop": {"inspect": "container_inspect", "stop": "container_stop", "reinspect": "container_inspect"},
    "export": {"source_inspect": "container_inspect", "stopped_inspect": "container_inspect",
               "volume_absence": "volume_inspect", "volume_create": "volume_create", "volume_capture": "volume_inspect",
               "name_inspect": "container_inspect",
               "worker_inspect": "container_inspect", "volume_inspect": "volume_inspect", "create": "container_create",
               "capture": "container_inspect", "inspect": "container_inspect", "start": "container_start",
               "wait": "container_wait", "logs": "container_logs", "copy_inspect": "container_inspect",
               "copy": "container_cp", "remove_inspect": "container_inspect", "remove": "container_rm"},
    "import": {"volume_absence": "volume_inspect", "volume_create": "volume_create", "volume_capture": "volume_inspect",
               "worker_inspect": "container_inspect", "volume_inspect": "volume_inspect", "create": "container_create",
               "capture": "container_inspect", "inspect": "container_inspect", "start": "container_start",
               "wait": "container_wait", "logs": "container_logs", "remove_inspect": "container_inspect",
               "remove": "container_rm"},
    "restore": {"up": "compose_up", "discover_list": "container_list", "discover_inspect": "container_inspect"},
}
PAIR_STEPS["assert"] = PAIR_STEPS["seed"].copy()
CASES = {(f"pressure_{section}_{step}", operation)
         for section, steps in PAIR_STEPS.items() for step, operation in steps.items()}
CASES |= {(f"pressure_{section}_launch", operation)
          for section in ("seed", "assert") for operation in ("container_inspect", "volume_inspect")}
CASES |= {("pressure_restore_up", operation) for operation in ("container_inspect", "volume_inspect")}
CASES |= {("pressure_restore_discover_list", operation) for operation in ("network_ls", "volume_ls")}
CASES |= {("pressure_restore_discover_inspect", "volume_inspect")}
CASES |= {("pressure_export_remove_inspect", "volume_inspect"), ("pressure_export_remove", "volume_rm")}


class CliModel:
    """Retain the real journal/identity/archive checks; replace only the Docker subprocess."""

    def __init__(self, lab):
        self.lab = lab
        self.containers, self.volumes, self.calls, self.pairs = {}, {}, [], []
        self.failure_pair = self.injected = None
        self.restore_failure = self.discover_failure = self.cleanup_failure = None
        self.wait_failure = None
        self.result = {"bytes": len(ARCHIVE), "sha256": hashlib.sha256(ARCHIVE).hexdigest()}
        source = lab.journal.value["projects"]["source"]
        volume = self.volume(source + "_pressure_data", "source")
        self.volumes[volume["Name"]] = volume
        for number, service, role in ((1, "ingest-worker", "source"), (2, "labredis-pressure", "pressure")):
            current = self.container(f"{number:064x}", source + "-" + service + "-1", "source", role, service)
            if service == "labredis-pressure":
                current["Mounts"] = [{"Type": "volume", "Name": volume["Name"]}]
            self.containers[current["Id"]] = current
            lab.journal.add_resources([
                resource_identity("container", current, lab.journal.value["run_id"], role, source)])
        lab.journal.add_resources([
            resource_identity("volume", volume, lab.journal.value["run_id"], "pressure", source)])

    def labels(self, project, role, service=None):
        value = {LABEL + "run": self.lab.journal.value["run_id"], LABEL + "role": role,
                 "com.docker.compose.project": project}
        if service:
            value["com.docker.compose.service"] = service
        return value

    def container(self, identifier, name, project_role, role, service=None):
        project = self.lab.journal.value["projects"][project_role]
        return {"Id": identifier, "Name": "/" + name, "Created": "2026-10-07T00:00:00Z",
                "Image": "sha256:" + "b" * 64, "Config": {"Labels": self.labels(project, role, service)},
                "State": {"Running": True}}

    def volume(self, name, project_role):
        return {"Name": name, "CreatedAt": "2026-10-07T00:00:00Z",
                "Labels": self.labels(self.lab.journal.value["projects"][project_role], "pressure")}

    @staticmethod
    def response(output="", code=0, stderr=""):
        return SimpleNamespace(returncode=code, stdout=output, stderr=stderr)

    def runner(self, command, **kwargs):
        assert command[:3] == ["docker", "--context", self.lab.context]
        args = command[3:]
        pair = getattr(self.lab.docker, "checkpoint", None), docker_operation(args)
        self.calls.append(tuple(args))
        self.pairs.append(pair)
        if pair == self.failure_pair and not self.injected:
            self.injected = pair
            return self.response(CANARY, 17, CANARY)
        if args[0] == "compose":
            verb = args[7]
            if verb == "up":
                if self.restore_failure:
                    raise self.restore_failure
                project = self.lab.journal.value["projects"]["restore"]
                current = self.container("f" * 64, project + "-labredis-pressure-1", "restore", "pressure",
                                         "labredis-pressure")
                current["Mounts"] = [{"Type": "volume", "Name": project + "_pressure_data"}]
                self.containers[current["Id"]] = current
            else:
                assert verb == "run"
                name = args[args.index("--name") + 1]
                mode = "assert" if name.endswith("-assert") else "seed"
                role = "restore" if mode == "assert" else "source"
                current = self.container(("c" if mode == "assert" else "a") * 64, name, role, "pressure",
                                         "pressure-assert" if mode == "assert" else "pressure-test")
                self.containers[current["Id"]] = current
                folder = self.lab.directory / ("pressure-reports" if mode == "assert" else "pressure-artifacts")
                xml = '<testsuite tests="2">' + ''.join(f'<testcase name="{name}"/>' for name in (
                    "test_required_pressure_and_aof_phase",
                    "test_real_redis_oom_before_allocation_and_owned_release_recovers",
                )) + '</testsuite>'
                (folder / f"pressure-{mode}.xml").write_text(xml)
            return self.response(CANARY)  # Compose build output is deliberately unrelated to identity.
        if args[0] == "ps":
            if self.discover_failure:
                raise self.discover_failure
            project = args[-1].rsplit("=", 1)[1]
            return self.response("\n".join(key for key, value in self.containers.items()
                                           if value["Config"]["Labels"]["com.docker.compose.project"] == project))
        kind, operation = args[:2]
        if operation == "ls":
            project = args[-1].rsplit("=", 1)[1]
            if kind == "volume":
                return self.response("\n".join(key for key, value in self.volumes.items()
                                               if value["Labels"]["com.docker.compose.project"] == project))
            return self.response()
        if operation == "inspect":
            objects = self.containers if kind == "container" else self.volumes
            target = args[2]
            current = objects.get(target) or next((item for item in objects.values()
                                                  if item.get("Name", "").lstrip("/") == target), None)
            return self.response(json.dumps([current])) if current else self.response("", 1, "No such " + kind)
        if operation == "create":
            labels = dict(value.split("=", 1) for index, value in enumerate(args)
                          if index and args[index - 1] == "--label")
            if kind == "volume":
                current = self.volume(args[-1], "restore")
                current["Labels"] = labels
                self.volumes[current["Name"]] = current
                return self.response(current["Name"])
            project_role = "restore" if labels[LABEL + "role"] == "restore" else "source"
            ident = ("e" if project_role == "restore" else "d") * 64
            name = args[args.index("--name") + 1] if "--name" in args else "archive-helper-" + ident[:1]
            current = self.container(ident, name, project_role, labels[LABEL + "role"])
            self.containers[ident] = current
            return self.response(ident)
        if kind == "volume" and operation == "rm":
            self.volumes.pop(args[2])
            return self.response()
        identifier = args[2].split(":", 1)[0]
        assert identifier in self.containers and len(identifier) == 64
        if operation == "wait":
            if identifier == "a" * 64 and self.wait_failure:
                raise self.wait_failure
            self.containers[identifier]["State"]["Running"] = False
            return self.response("0")
        if operation == "logs":
            return self.response(json.dumps(self.result))
        if operation == "cp":
            Path(args[3]).write_bytes(ARCHIVE)
        elif operation == "rm":
            if identifier == "a" * 64 and self.cleanup_failure:
                raise self.cleanup_failure
            self.containers.pop(identifier)
        elif operation in {"start", "stop"}:
            self.containers[identifier]["State"]["Running"] = operation == "start"
        else:
            raise AssertionError("Unexpected synthetic Docker operation")
        return self.response()


def create_lab(tmp_path, monkeypatch, lab_type=Laboratory, docker_type=Docker):
    profile = load_profile(ROOT / "deploy/qualification/profiles/lab-smoke.json")
    profile["scenarios"] = ["redis_pressure"]
    lab = lab_type(ROOT, tmp_path / "run", profile, "bounded-diagnostic-context")
    lab.journal = RunJournal.create(lab.directory, profile, lab.config_hash, lab.context)
    lab.journal.phase("redis_pressure")
    lab.tenant = "synthetic-owned-installation"
    atomic_json(lab.directory / "source.json", {"synthetic_cli_boundary": True})
    monkeypatch.setattr("shadai.qualification.lab.os.getuid", lambda: 1001, raising=False)
    monkeypatch.setattr("shadai.qualification.lab.os.getgid", lambda: 1001, raising=False)
    monkeypatch.setattr(lab, "environment", lambda role: {"CANARY": CANARY})
    cli = CliModel(lab)
    lab.docker = docker_type(lab.context, runner=cli.runner)
    return lab, cli


@pytest.fixture
def diagnostic_lab(tmp_path, monkeypatch):
    return create_lab(tmp_path, monkeypatch)


def test_healthy_flow_visits_all_known_operations_without_failure_evidence(diagnostic_lab):
    lab, cli = diagnostic_lab
    lab.experiment_redis_pressure("unused")
    assert set(cli.pairs) == CASES
    assert lab.write_report() == 0
    assert "failure" not in json.loads((lab.directory / "report.json").read_text())["evidence"]
    assert lab.pressure_section is None and lab.docker.checkpoint is None
    assert [args[2] for args in cli.calls if args[:2] == ("container", "rm")] == [
        "a" * 64, "d" * 64, "e" * 64, "c" * 64]


@pytest.mark.parametrize("checkpoint,operation", sorted(CASES))
def test_each_known_call_refuses_with_exact_constant_context(diagnostic_lab, checkpoint, operation):
    lab, cli = diagnostic_lab
    cli.failure_pair = checkpoint, operation
    with pytest.raises(DockerOperationError) as raised:
        lab.experiment_redis_pressure(CANARY)
    assert cli.injected == (checkpoint, operation) and raised.value.returncode == 17
    assert lab.write_report() != 0
    proof = json.loads((lab.directory / "report.json").read_text())["evidence"]["failure"]
    assert proof["checkpoint"] == proof["stage"] == checkpoint and proof["operation"] == operation
    assert proof["code"] == "docker_nonzero" and proof["returncode"] == 17
    assert CANARY not in json.dumps(proof) and len(json.dumps(proof)) <= 2048
    assert lab.pressure_section is None and lab.docker.checkpoint is None


@pytest.mark.parametrize("secondary", [DockerOperationError("docker_nonzero", 29),
                                      KeyboardInterrupt(CANARY), SystemExit(CANARY)])
def test_restore_discover_preserves_primary_and_secondary_cancellation(diagnostic_lab, secondary):
    lab, cli = diagnostic_lab
    primary = DockerOperationError("docker_nonzero", 17)
    cli.restore_failure, cli.discover_failure = primary, secondary
    expected = type(secondary) if isinstance(secondary, (KeyboardInterrupt, SystemExit)) else DockerOperationError
    with pytest.raises(expected) as raised:
        lab.experiment_redis_pressure("unused")
    assert raised.value is (secondary if isinstance(secondary, (KeyboardInterrupt, SystemExit)) else primary)
    assert lab.failure["returncode"] == 17 and lab.failure["stage"] == "pressure_restore_up"
    assert lab.failure["secondary"][0]["stage"] == "pressure_restore_discover_list"
    assert CANARY not in json.dumps(lab.failure) and lab.write_report() != 0


@pytest.mark.parametrize("secondary", [DockerOperationError("docker_nonzero", 29),
                                      KeyboardInterrupt(CANARY), SystemExit(CANARY)])
def test_seed_cleanup_preserves_primary_or_secondary_cancellation_and_owned_record(diagnostic_lab, secondary):
    lab, cli = diagnostic_lab
    primary = DockerOperationError("docker_nonzero", 17)
    cli.wait_failure, cli.cleanup_failure = primary, secondary
    expected = type(secondary) if isinstance(secondary, (KeyboardInterrupt, SystemExit)) else DockerOperationError
    with pytest.raises(expected) as raised:
        lab.experiment_redis_pressure("unused")
    assert raised.value is (secondary if isinstance(secondary, (KeyboardInterrupt, SystemExit)) else primary)
    assert lab.failure["stage"] == "pressure_seed_wait" and lab.failure["returncode"] == 17
    assert lab.failure["secondary"][0]["stage"] == "pressure_seed_remove"
    assert "a" * 64 in cli.containers and any(row["id"] == "a" * 64 for row in lab.journal.value["resources"])
    assert CANARY not in json.dumps(lab.failure) and lab.write_report() != 0


@pytest.mark.parametrize("kind", ["nonzero", "timeout", "output", "process"])
def test_upstream_canaries_and_untrusted_context_cannot_enter_envelope(kind):
    def runner(command, **kwargs):
        assert CANARY in command and kwargs["env"]["CANARY"] == CANARY
        if kind == "timeout":
            raise subprocess.TimeoutExpired([CANARY], 1, output=CANARY, stderr=CANARY)
        if kind == "process":
            raise OSError(CANARY)
        return SimpleNamespace(returncode=1 if kind == "nonzero" else 0, stderr=CANARY,
                               stdout=(CANARY + "x" * (4 * 1048576)) if kind == "output" else CANARY)

    docker = Docker("explicit-context", runner=runner)
    docker.checkpoint, docker.last_completed = "pressure_export_logs", "pressure_export_wait"
    with pytest.raises(DockerOperationError) as raised:
        docker.call("container", "logs", CANARY, environment={"CANARY": CANARY})
    proof = failure_evidence(raised.value, "redis_pressure", "scenario")
    assert proof["operation"] == "container_logs" and proof["checkpoint"] == "pressure_export_logs"
    assert proof["last_completed"] == "pressure_export_wait" and CANARY not in json.dumps(proof)
    raised.value.operation, raised.value.checkpoint, raised.value.last_completed = CANARY, [CANARY], CANARY
    mutated = failure_evidence(raised.value, CANARY, CANARY)
    assert CANARY not in json.dumps(mutated) and len(json.dumps(mutated)) <= 2048
    docker.checkpoint = CANARY
    with pytest.raises(DockerOperationError) as raised:
        docker.call(CANARY, CANARY, environment={"CANARY": CANARY})
    assert CANARY not in json.dumps(failure_evidence(raised.value, CANARY, CANARY))


def test_unknown_operation_and_exception_class_are_fixed(diagnostic_lab):
    lab, _ = diagnostic_lab
    malicious = type(CANARY, (RuntimeError,), {})(CANARY)
    with pytest.raises(type(malicious)):
        with lab.pressure_diagnostics("export"):
            lab.pressure_checkpoint("logs")
            raise malicious
    assert lab.failure["error_type"] == "UnexpectedError" and CANARY not in json.dumps(lab.failure)
    assert docker_operation((CANARY, CANARY)) == "unknown"
    assert docker_operation(("compose", "--project-name", CANARY, CANARY, CANARY, CANARY, CANARY, "up")) == "unknown"
    assert all(type(value) is str for value in DOCKER_OPERATION_NAMES | PRESSURE_CHECKPOINTS)


def test_report_execute_marks_secondary_cancellation_without_losing_primary(tmp_path, monkeypatch):
    from test_qualification_startup import prepared_lab

    lab = prepared_lab(tmp_path, monkeypatch)
    lab.profile["scenarios"] = ["redis_pressure"]
    primary = DockerOperationError("docker_nonzero", 17, operation="compose_up", checkpoint="pressure_restore_up")

    def special(url, completed):
        lab.journal.phase("redis_pressure")
        lab.failure = failure_evidence(primary, "redis_pressure", "pressure_restore_up")
        lab.failure["secondary"] = [failure_evidence(SystemExit(CANARY), "redis_pressure",
                                                   "pressure_restore_discover_list")]
        raise SystemExit(CANARY)

    monkeypatch.setattr(lab, "execute_special", Mock(side_effect=special))
    assert lab.execute() == 2
    proof = json.loads((lab.directory / "report.json").read_text())
    assert proof["evidence"]["failure"]["returncode"] == 17
    assert lab.journal.value["cancelled"] and lab.journal.value["phase"] == "cancelled"
    assert CANARY not in json.dumps(proof)
