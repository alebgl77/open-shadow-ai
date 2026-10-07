"""Probe peer dependency ownership and one shared window; synthetic Docker only."""

import asyncio
import copy
import json
import subprocess

import pytest
from test_qualification_pressure_diagnostics import CliModel, create_lab

import shadai.qualification.lab as lab_module
from shadai.qualification.journal import LABEL, resource_identity, verify_resource
from shadai.qualification.lab import (
    DOCKER_OPERATION_NAMES,
    PROBE_CHECKPOINTS,
    PROBE_SERVICES,
    Docker,
    DockerOperationError,
    docker_operation,
    probe_failure_evidence,
)
from shadai.qualification.schemas import QualificationError
from shadai.workers import probe as worker_probe
from shadai.workers.probe import READINESS_REASONS


class Clock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class DependencyCli(CliModel):
    def __init__(self, lab, clock):
        super().__init__(lab)
        self.clock = clock
        self.suspended = False
        self.ready = True
        self.recreated = False
        self.starting_reads = 0
        self.starting_until = None
        self.inspect_cost = 0
        self.readiness_cost = 0
        self.preflight = False
        self.peer_failure = None
        self.foreign_after_launch = False
        self.launches = []
        self.discovery_deadlines = []
        self.readiness_records = []
        self.diagnostic_pairs = []
        self.diagnostic_failure = None
        self.diagnostic_error = None
        self.readiness_diagnostic = CANARY
        self.injected = None
        project = lab.journal.value["projects"]["source"]
        self.dependency_ids = {"redis": "3" * 64, "clickhouse": "4" * 64, "migrate": "6" * 64}
        for service, identifier in self.dependency_ids.items():
            current = self.container(identifier, project + "-" + service + "-1", "source", "source", service)
            current["State"] = ({"Status": "exited", "Running": False, "ExitCode": 0} if service == "migrate"
                                else {"Running": True, "Health": {"Status": "healthy"}})
            self.containers[identifier] = current
            lab.journal.add_resources([
                resource_identity("container", current, lab.journal.value["run_id"], "source", project)])
        self.containers["0" * 63 + "1"]["RestartCount"] = 0

    def runner(self, command, **kwargs):
        args = command[3:]
        pair = (self.lab.docker.checkpoint, docker_operation(args), self.lab.probe_service)
        self.diagnostic_pairs.append(pair)
        if pair == self.diagnostic_failure and self.injected is None:
            self.injected = pair
            if self.diagnostic_error is not None:
                raise self.diagnostic_error
            return self.response(CANARY, code=17, stderr=CANARY)
        if args[0] == "ps":
            self.discovery_deadlines.append((self.lab.deadline, self.lab.docker.deadline))
        if args[:2] == ["container", "inspect"] and self.preflight:
            self.clock.now += self.inspect_cost
            if args[2] == self.dependency_ids["redis"] and self.starting_until is not None:
                self.starting_reads += 1
                if self.starting_reads > self.starting_until:
                    self.containers[args[2]]["State"]["Health"]["Status"] = "healthy"
        if args[:3] == ["container", "start", self.dependency_ids["redis"]]:
            self.preflight = True
        if args[:2] == ["container", "exec"]:
            assert args[2] in self.containers
            self.calls.append(tuple(args))
            if "shadai.workers.probe" in args:
                mode = args[args.index("shadai.workers.probe") + 1]
                record = next(x for x in self.lab.journal.value["resources"] if x["id"] == args[2])
                return self.response(self.readiness_diagnostic, code=0 if self.probe_status(record, mode) else 1,
                                     stderr=CANARY)
            self.suspended = "SIGSTOP" in args[-1]
            return self.response()
        if args[0] == "compose" and args[7] == "up" and args[-1] == "probe-ingest-peer":
            self.calls.append(tuple(args))
            self.launches.append({"arguments": args[7:], "timeout": kwargs["timeout"],
                                  "deadline": self.lab.deadline, "docker_deadline": self.lab.docker.deadline})
            project = self.lab.journal.value["projects"]["source"]
            if "--no-deps" not in args:
                old = self.containers.pop(self.dependency_ids["redis"])
                replacement = copy.deepcopy(old)
                replacement["Id"], replacement["Image"] = "8" * 64, "sha256:" + "c" * 64
                replacement["Created"] = "2026-10-07T00:00:01Z"
                self.containers[replacement["Id"]] = replacement
                self.recreated = True
            peer = self.container("b" * 64, project + "-probe-ingest-peer-1", "source", "source", "probe-ingest-peer")
            self.containers[peer["Id"]] = peer
            if self.foreign_after_launch:
                self.containers[self.dependency_ids["redis"]]["Config"]["Labels"][LABEL + "run"] = "foreign-run"
            if self.peer_failure is not None:
                raise self.peer_failure
            return self.response()
        return super().runner(command, **kwargs)

    def probe_status(self, record, mode):
        if mode == "liveness" and record["service"] == "ingest-worker":
            return not self.suspended
        if mode == "readiness":
            if self.preflight:
                self.readiness_records.append(record["id"])
                self.clock.now += self.readiness_cost
            return self.ready and self.containers[self.dependency_ids["redis"]]["State"]["Running"] is True
        return True


@pytest.fixture
def dependencies(tmp_path, monkeypatch):
    lab, _ = create_lab(tmp_path, monkeypatch)
    clock = Clock()
    monkeypatch.setattr(lab_module.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(lab_module.time, "sleep", clock.sleep)
    cli = DependencyCli(lab, clock)
    lab.docker = Docker(lab.context, runner=cli.runner)
    lab.deadline, lab.docker.deadline = 1000.0, 900.0
    return lab, cli, clock


CANARY = "https://user:private-token@secret.example.test/password?argv=private-token"


def assert_probe_failure(lab, checkpoint, *, service=None, operation=None):
    value = lab.failure
    assert value["phase"] == "probes" and value["stage"] == value["checkpoint"] == checkpoint
    assert set(value) <= {"phase", "stage", "checkpoint", "operation", "service", "last_completed",
                          "error_type", "code", "returncode", "secondary", "reason_code", "secondary_reason"}
    if service is not None:
        assert value["service"] == service
    if operation is not None:
        assert value["operation"] == operation
    serialized = json.dumps(value)
    assert CANARY not in serialized and len(serialized.encode("utf-8")) <= 2048
    assert lab.write_report() != 0
    assert lab.probe_section is None and lab.docker.checkpoint is None


def assert_refused_without_adoption(lab, cli, before):
    assert not cli.launches
    assert lab.journal.value["resources"] == before
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert not cli.discovery_deadlines
    assert not any(call[:2] == ("container", "rm") for call in cli.calls)


def test_actual_pressure_then_probes_keeps_old_dependencies_and_physical_guard(dependencies):
    lab, cli, _ = dependencies
    lab.experiment_redis_pressure("unused")
    originals = {name: copy.deepcopy(lab.containers({name})[0]) for name in cli.dependency_ids}
    lab.experiment_probes("unused")
    assert [x["status"] for x in lab.scenarios] == ["passed", "passed"]
    assert cli.launches[0]["arguments"] == ["up", "-d", "--no-deps", "probe-ingest-peer"]
    assert not cli.recreated
    assert cli.readiness_records == ["0" * 63 + "1"]
    assert cli.discovery_deadlines[-1] == (1000.0, 900.0)
    for name, record in originals.items():
        assert lab.containers({name}) == [record]
        verify_resource(record, lab.docker.inspect("container", record["id"]))
    with lab.physical_diagnostics("inspector"):
        lab.guard_all()
    assert not any(row["kind"] == "container" and row["service"] in {"pressure-test", "pressure-assert", ""}
                   for row in lab.journal.value["resources"])


def test_old_peer_argument_reproduces_exact_physical_stale_id_refusal(dependencies):
    lab, cli, _ = dependencies
    lab.compose("up", "-d", "probe-ingest-peer")
    lab.discover()
    assert cli.recreated and len(lab.containers({"redis"})) == 2
    with pytest.raises(DockerOperationError) as caught, lab.physical_diagnostics("inspector"):
        lab.guard_all()
    assert caught.value.returncode == 1
    assert lab.failure["checkpoint"] == lab.failure["last_completed"] == "physical_inspector_guard_inspect"
    assert lab.failure["operation"] == "container_inspect"
    assert any(row["id"] == cli.dependency_ids["redis"] for row in lab.journal.value["resources"])


@pytest.mark.parametrize("service", ["migrate", "redis", "clickhouse"])
@pytest.mark.parametrize("defect", ["missing-record", "missing-container", "foreign-run", "foreign-service",
                                   "duplicate"])
def test_each_dependency_identity_defect_prevents_launch_and_journal_changes(dependencies, service, defect):
    lab, cli, _ = dependencies
    identifier = cli.dependency_ids[service]
    if defect == "missing-record":
        lab.journal.value["resources"] = [x for x in lab.journal.value["resources"] if x["id"] != identifier]
    elif defect == "missing-container":
        del cli.containers[identifier]
    elif defect.startswith("foreign-"):
        label = LABEL + "run" if defect == "foreign-run" else "com.docker.compose.service"
        cli.containers[identifier]["Config"]["Labels"][label] = "foreign-value"
    else:
        duplicate = copy.deepcopy(cli.containers[identifier])
        duplicate["Id"] = "c" * 64
        cli.containers[duplicate["Id"]] = duplicate
        project = lab.journal.value["projects"]["source"]
        lab.journal.add_resources([resource_identity("container", duplicate, lab.journal.value["run_id"],
                                                    "source", project)])
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises((QualificationError, DockerOperationError)):
        lab.experiment_probes("unused")
    assert_refused_without_adoption(lab, cli, before)
    checkpoint = ("registry" if defect == "missing-record" else "unique" if defect == "duplicate"
                  else "inspect" if defect == "missing-container" else "identity")
    section = "dependencies"
    if service == "redis" and defect != "duplicate":
        section = "outage"
        checkpoint = "registry" if defect == "missing-record" else "inspect"
    assert_probe_failure(lab, "probes_" + section + "_" + checkpoint,
                         service=service if checkpoint in {"inspect", "identity"} else None)


@pytest.mark.parametrize("state", [None, [], {}, {"Status": "running", "Running": False, "ExitCode": 0},
                                   {"Status": "exited", "Running": True, "ExitCode": 0},
                                   {"Status": "exited", "Running": 0, "ExitCode": 0},
                                   {"Status": "exited", "Running": False, "ExitCode": 1},
                                   {"Status": "exited", "Running": False, "ExitCode": False},
                                   {"Status": "exited", "Running": False, "ExitCode": 0.0}])
def test_migration_requires_exact_exited_state_and_integer_zero(dependencies, state):
    lab, cli, _ = dependencies
    cli.containers[cli.dependency_ids["migrate"]]["State"] = state
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError):
        lab.experiment_probes("unused")
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_state", service="migrate")


@pytest.mark.parametrize("service", ["redis", "clickhouse"])
@pytest.mark.parametrize("defect", ["missing-health", "list-health", "missing-status", "unhealthy", "bad-status",
                                   "list-status", "running-int"])
def test_store_requires_exact_running_and_supported_health(dependencies, service, defect, monkeypatch):
    lab, cli, _ = dependencies
    state = cli.containers[cli.dependency_ids[service]]["State"]
    # Redis outage restart legitimately rewrites Running; inject at preflight entry.
    original = lab.wait_probe_dependencies
    def inspect_invalid(worker):
        if defect == "missing-health":
            state.pop("Health")
        elif defect == "list-health":
            state["Health"] = []
        elif defect == "missing-status":
            state["Health"] = {}
        elif defect == "unhealthy":
            state["Health"]["Status"] = "unhealthy"
        elif defect == "bad-status":
            state["Health"]["Status"] = False
        elif defect == "list-status":
            state["Health"]["Status"] = []
        else:
            state["Running"] = 1
        return original(worker)
    monkeypatch.setattr(lab, "wait_probe_dependencies", inspect_invalid)
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError):
        lab.experiment_probes("unused")
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_health", service=service)


def test_worker_readiness_false_prevents_launch_under_same_identity(dependencies):
    lab, cli, _ = dependencies
    cli.ready = False
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="not ready"):
        lab.experiment_probes("unused")
    assert cli.readiness_records == ["0" * 63 + "1"]
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_readiness", service="ingest-worker", operation="container_exec")


def test_starting_health_polls_one_second_then_verifies_before_launch(dependencies):
    lab, cli, clock = dependencies
    cli.containers[cli.dependency_ids["redis"]]["State"]["Health"]["Status"] = "starting"
    cli.starting_until = 2
    lab.experiment_probes("unused")
    assert clock.sleeps == [10, 1, 32]
    assert cli.starting_reads > 2 and cli.readiness_records == ["0" * 63 + "1"]
    assert cli.launches[0]["timeout"] == 119
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)


def test_health_starting_exhausts_shared_window_without_launch(dependencies):
    lab, cli, clock = dependencies
    cli.containers[cli.dependency_ids["redis"]]["State"]["Health"]["Status"] = "starting"
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="budget"):
        lab.experiment_probes("unused")
    assert clock.now == 230 and clock.sleeps == [10] + [1] * 120
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_wait")


def test_starting_cancellation_preserves_primary_and_restores_deadlines(dependencies, monkeypatch):
    lab, cli, clock = dependencies
    cli.containers[cli.dependency_ids["redis"]]["State"]["Health"]["Status"] = "starting"
    primary = KeyboardInterrupt("synthetic-cancel")
    def sleep(seconds):
        if seconds <= 1:
            raise primary
        clock.sleep(seconds)
    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(KeyboardInterrupt) as caught:
        lab.experiment_probes("unused")
    assert caught.value is primary
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_wait")


def test_readiness_and_up_consume_one_budget_clipped_to_global_remaining(dependencies):
    lab, cli, _ = dependencies
    lab.deadline, lab.docker.deadline = 190.0, 180.0
    cli.readiness_cost = 15
    lab.experiment_probes("unused")
    assert cli.launches[0]["deadline"] == cli.launches[0]["docker_deadline"] == 180
    assert cli.launches[0]["timeout"] == 55
    assert cli.discovery_deadlines[-1] == (190.0, 180.0)
    assert (lab.deadline, lab.docker.deadline) == (190.0, 180.0)


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt("synthetic")])
def test_peer_launch_failure_restores_budget_before_owned_discovery(dependencies, primary):
    lab, cli, _ = dependencies
    cli.peer_failure = primary
    with pytest.raises(type(primary)) as caught:
        lab.experiment_probes("unused")
    assert caught.value is primary
    assert cli.discovery_deadlines[-1] == (1000.0, 900.0)
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert len(lab.containers({"redis"})) == 1
    assert len(lab.containers({"probe-ingest-peer"})) == 1


def test_foreign_dependency_after_launch_is_refused_without_adoption(dependencies):
    lab, cli, _ = dependencies
    before = copy.deepcopy(lab.journal.value["resources"])
    cli.foreign_after_launch = True
    with pytest.raises(QualificationError):
        lab.experiment_probes("unused")
    assert cli.launches and not cli.recreated
    assert lab.journal.value["resources"] == before
    assert cli.discovery_deadlines[-1] == (1000.0, 900.0)
    assert not any(call[:2] == ("container", "rm") for call in cli.calls)
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert_probe_failure(lab, "probes_peer_discover_identity")


PROBE_DOCKER_CASES = {
    ("probes_baseline_startup_identity", "container_inspect", "ingest-worker"),
    ("probes_baseline_startup", "container_exec", "ingest-worker"),
    ("probes_baseline_liveness_identity", "container_inspect", "ingest-worker"),
    ("probes_baseline_liveness", "container_exec", "ingest-worker"),
    ("probes_baseline_restart", "container_inspect", "ingest-worker"),
    ("probes_outage_inspect", "container_inspect", "redis"),
    ("probes_outage_stop", "container_stop", "redis"),
    ("probes_outage_start", "container_start", "redis"),
    ("probes_outage_reinspect", "container_inspect", "redis"),
    ("probes_outage_liveness_identity", "container_inspect", "ingest-worker"),
    ("probes_outage_liveness", "container_exec", "ingest-worker"),
    ("probes_outage_readiness_identity", "container_inspect", "ingest-worker"),
    ("probes_outage_readiness", "container_exec", "ingest-worker"),
    ("probes_outage_restart", "container_inspect", "ingest-worker"),
    *(("probes_dependencies_inspect", "container_inspect", service) for service in ("redis", "clickhouse", "migrate")),
    ("probes_dependencies_readiness_identity", "container_inspect", "ingest-worker"),
    ("probes_dependencies_readiness", "container_exec", "ingest-worker"),
    *(("probes_peer_guard_inspect", "container_inspect", service)
      for service in ("ingest-worker", "redis", "clickhouse", "migrate", None)),
    ("probes_peer_guard_inspect", "volume_inspect", None),
    ("probes_peer_launch", "compose_up", "probe-ingest-peer"),
    ("probes_peer_discover_list", "container_list", None),
    ("probes_peer_discover_list", "network_ls", None),
    ("probes_peer_discover_list", "volume_ls", None),
    ("probes_peer_discover_inspect", "container_inspect", None),
    ("probes_peer_discover_inspect", "volume_inspect", None),
    ("probes_peer_startup_identity", "container_inspect", "probe-ingest-peer"),
    ("probes_peer_startup", "container_exec", "probe-ingest-peer"),
    ("probes_peer_liveness_identity", "container_inspect", "probe-ingest-peer"),
    ("probes_peer_liveness", "container_exec", "probe-ingest-peer"),
    ("probes_suspend_identity", "container_inspect", "ingest-worker"),
    ("probes_suspend_signal", "container_exec", "ingest-worker"),
    *(("probes_suspend_" + mode, operation, service)
      for mode, operation in (("liveness_identity", "container_inspect"), ("liveness", "container_exec"))
      for service in ("ingest-worker", "probe-ingest-peer")),
    ("probes_resume_identity", "container_inspect", "ingest-worker"),
    ("probes_resume_signal", "container_exec", "ingest-worker"),
    ("probes_resume_inspect", "container_inspect", "probe-ingest-peer"),
    ("probes_resume_stop", "container_stop", "probe-ingest-peer"),
    ("probes_resume_reinspect", "container_inspect", "probe-ingest-peer"),
    *(("probes_witness_" + step, operation, None) for step, operation in (
        ("worker_inspect", "container_inspect"), ("create", "container_create"), ("capture", "container_inspect"),
        ("inspect", "container_inspect"), ("start", "container_start"), ("wait", "container_wait"),
        ("logs", "container_logs"), ("remove_inspect", "container_inspect"), ("remove", "container_rm"))),
}


def diagnostic_case_id(case):
    return ":".join(value or "none" for value in case)


@pytest.mark.parametrize("case", sorted(PROBE_DOCKER_CASES, key=diagnostic_case_id), ids=diagnostic_case_id)
def test_every_probe_docker_leaf_refuses_with_bounded_constant_context(dependencies, case):
    lab, cli, _ = dependencies
    cli.diagnostic_failure = case
    # Direct exec uses the unchanged runner; its timeout must propagate, while Docker.call wraps it.
    cli.diagnostic_error = subprocess.TimeoutExpired(CANARY, 1, output=CANARY, stderr=CANARY)
    with pytest.raises((DockerOperationError, subprocess.TimeoutExpired)):
        lab.experiment_probes(CANARY)
    assert cli.injected == case
    assert_probe_failure(lab, case[0], service=case[2], operation=case[1])
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert not lab.scenarios
    # Only pre-existing finally cleanup/discovery may follow the failed call, never witness creation.
    if not case[0].startswith("probes_witness_"):
        assert not any(call[:2] == ("container", "create") for call in cli.calls)


def test_healthy_probes_visit_every_known_docker_leaf_and_restore_context(dependencies):
    lab, cli, clock = dependencies
    lab.experiment_probes(CANARY)
    assert set(cli.diagnostic_pairs) == PROBE_DOCKER_CASES
    assert lab.failure is None and lab.probe_section is None and lab.docker.checkpoint is None
    assert lab.stage == "scenario" and lab.probe_operation == "unknown" and lab.probe_service is None
    assert clock.sleeps == [10, 32]
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert lab.scenarios[0]["scenario"] == "probes" and lab.scenarios[0]["status"] == "passed"


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17), KeyboardInterrupt(CANARY),
                                  SystemExit(CANARY)])
@pytest.mark.parametrize("secondary", [DockerOperationError("docker_nonzero", 29), KeyboardInterrupt(CANARY),
                                    SystemExit(CANARY)])
def test_launch_finally_diagnostics_keep_first_failure_without_changing_propagated_secondary(
        dependencies, primary, secondary):
    lab, cli, _ = dependencies
    cli.peer_failure, cli.discover_failure = primary, secondary
    with pytest.raises(type(secondary)) as caught:
        lab.experiment_probes(CANARY)
    assert caught.value is secondary
    assert_probe_failure(lab, "probes_peer_launch", service="probe-ingest-peer", operation="compose_up")
    assert lab.failure["error_type"] == type(primary).__name__
    assert lab.failure["secondary"][0]["checkpoint"] == "probes_peer_discover_list"
    assert lab.failure["secondary"][0]["error_type"] == type(secondary).__name__
    assert cli.discovery_deadlines[-1] == (1000.0, 900.0)
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)


@pytest.mark.parametrize("primary", [AssertionError(CANARY), KeyboardInterrupt(CANARY), SystemExit(CANARY)])
@pytest.mark.parametrize("secondary", [DockerOperationError("docker_nonzero", 29), KeyboardInterrupt(CANARY),
                                    SystemExit(CANARY)])
def test_resume_finally_keeps_both_diagnostics_and_original_exception_flow(
        dependencies, monkeypatch, primary, secondary):
    lab, cli, clock = dependencies
    def sleep(seconds):
        if seconds == 32:
            raise primary
        clock.sleep(seconds)
    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    original = cli.runner
    def runner(command, **kwargs):
        if "SIGCONT" in command[-1]:
            raise secondary
        return original(command, **kwargs)
    lab.docker.runner = runner
    with pytest.raises(type(secondary)) as caught:
        lab.experiment_probes(CANARY)
    assert caught.value is secondary
    assert_probe_failure(lab, "probes_suspend_wait")
    assert lab.failure["error_type"] == type(primary).__name__
    assert lab.failure["secondary"][0]["checkpoint"] == "probes_resume_signal"
    assert lab.failure["secondary"][0]["error_type"] == type(secondary).__name__
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert not any(call[:2] == ("container", "create") for call in cli.calls)


@pytest.mark.parametrize("bad", [CANARY, "probes_dependencies_future", "probes_peer_launch\n", None, [], {}, True])
def test_probe_envelope_scrubs_unknown_nested_context_and_attacker_types(bad):
    attacker = type(CANARY, (DockerOperationError,), {})("docker_nonzero", 17)
    attacker.add_note(CANARY)
    attacker.stdout = attacker.stderr = attacker.env = attacker.args = (CANARY,)
    value = probe_failure_evidence(attacker, bad, bad, bad, bad)
    assert value == {"phase": "probes", "stage": "unknown", "error_type": "UnexpectedError", "code": "exception"}
    assert CANARY not in json.dumps(value)


@pytest.mark.parametrize("checkpoint", sorted(PROBE_CHECKPOINTS))
def test_every_probe_constant_is_revalidated_at_emission_with_fixed_payload_bound(checkpoint):
    error = DockerOperationError("docker_nonzero", -255, operation="container_exec", checkpoint=checkpoint)
    error.args = (CANARY,)
    error.add_note(CANARY)
    error.code = CANARY
    error.operation = [CANARY]
    value = probe_failure_evidence(error, checkpoint, "container_exec", "probe-ingest-peer", checkpoint)
    assert value["checkpoint"] == checkpoint and value["code"] == "docker_process_error"
    assert value["operation"] == "container_exec" and value["returncode"] == -255
    value["secondary"] = [copy.deepcopy(value)]
    assert len(json.dumps(value).encode("utf-8")) <= 2048 and CANARY not in json.dumps(value)
    for key in value["secondary"][0]:
        assert key in {"phase", "stage", "error_type", "code", "returncode", "checkpoint", "operation",
                       "service", "last_completed"}
    error.returncode = True
    invalid = probe_failure_evidence(error, checkpoint, CANARY, CANARY, CANARY)
    assert "returncode" not in invalid and "service" not in invalid and "last_completed" not in invalid
    assert invalid["operation"] == "unknown"


def test_untrusted_probe_section_and_operation_cannot_publish_caller_text(dependencies):
    lab, _, _ = dependencies
    lab.probe_section = CANARY
    lab.probe_checkpoint("readiness", operation=CANARY, service=CANARY)
    assert lab.stage == "scenario" and lab.docker.checkpoint is None
    lab.probe_section = "dependencies"
    lab.probe_checkpoint("readiness", operation=CANARY, service=CANARY)
    assert lab.probe_operation == "unknown" and lab.probe_service is None
    assert PROBE_SERVICES and "container_exec" in DOCKER_OPERATION_NAMES


def test_absent_worker_registry_refuses_before_any_docker_call(dependencies):
    lab, cli, _ = dependencies
    lab.journal.value["resources"] = [x for x in lab.journal.value["resources"] if x["service"] != "ingest-worker"]
    with pytest.raises(QualificationError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_baseline_registry", service="ingest-worker")
    assert not cli.calls and not cli.launches


def test_global_budget_refuses_before_worker_inspection_transport(dependencies):
    lab, cli, clock = dependencies
    lab.deadline = lab.docker.deadline = clock.now
    with pytest.raises(QualificationError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_baseline_startup_identity", service="ingest-worker")
    assert not cli.calls and not cli.launches


def test_readiness_consumes_shared_budget_before_peer_launch(dependencies):
    lab, cli, _ = dependencies
    cli.readiness_cost = 120
    with pytest.raises(QualificationError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_dependencies_launch_budget")
    assert not cli.launches and not cli.discovery_deadlines
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)


def test_witness_json_refusal_reports_only_constant_result_checkpoint(dependencies):
    lab, cli, _ = dependencies
    original = cli.runner
    def runner(command, **kwargs):
        if command[3:5] == ["container", "logs"]:
            return cli.response(CANARY, stderr=CANARY)
        return original(command, **kwargs)
    lab.docker.runner = runner
    with pytest.raises(json.JSONDecodeError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_witness_result")
    assert lab.failure["error_type"] == "JSONDecodeError"
    assert not any(call[:2] == ("container", "rm") for call in cli.calls)
    # An interrupted witness remains journaled for the unchanged identity-checked cleanup.
    assert any(x["kind"] == "container" and x["id"] == "d" * 64 for x in lab.journal.value["resources"])


@pytest.mark.parametrize("reason", sorted(READINESS_REASONS - {"phase_unready"}))
def test_fixed_readiness_reason_is_diagnostic_only_and_never_authorizes_peer(dependencies, reason):
    lab, cli, _ = dependencies
    cli.ready = False
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": reason, "secondary_reason": "none"})
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_dependencies_readiness", service="ingest-worker", operation="container_exec")
    assert lab.failure["reason_code"] == reason and lab.failure["secondary_reason"] == "none"
    assert_refused_without_adoption(lab, cli, before)
    assert lab.probe_reason is lab.probe_secondary_reason is None


@pytest.mark.parametrize("raw", [
    "", CANARY, CANARY + json.dumps({"schema": 1, "reason": "poll_stale", "secondary_reason": "none"}),
    '{"schema":1,"schema":1,"reason":"poll_stale","secondary_reason":"none"}',
    json.dumps({"schema": True, "reason": "poll_stale", "secondary_reason": "none"}),
    json.dumps({"schema": 1, "reason": CANARY, "secondary_reason": "none"}),
    json.dumps({"schema": 1, "reason": "poll_stale", "secondary_reason": "none", "pid": CANARY}),
    " " * 257,
])
def test_untrusted_readiness_output_is_unavailable_without_leaking_or_retry(dependencies, raw):
    lab, cli, _ = dependencies
    cli.ready = False
    cli.readiness_diagnostic = raw
    with pytest.raises(QualificationError):
        lab.experiment_probes(CANARY)
    assert_probe_failure(lab, "probes_dependencies_readiness")
    assert lab.failure["reason_code"] == "diagnostic_unavailable" and not cli.launches
    assert cli.readiness_records == ["0" * 63 + "1"]


def test_ready_exit_zero_with_false_reason_payload_cannot_change_health_result(dependencies):
    lab, cli, _ = dependencies
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"})
    lab.experiment_probes(CANARY)
    assert lab.failure is None and lab.probe_reason is lab.probe_secondary_reason is None
    assert lab.scenarios[0]["status"] == "passed" and len(cli.launches) == 1


def test_readiness_reason_and_secondary_are_revalidated_before_publication():
    error = QualificationError(CANARY)
    proof = probe_failure_evidence(error, "probes_dependencies_readiness", "container_exec", "ingest-worker", None,
                                   reason_code="retention_unready", secondary_reason="dependency_cleanup_error")
    assert proof["reason_code"] == "retention_unready" and proof["secondary_reason"] == "dependency_cleanup_error"
    assert CANARY not in json.dumps(proof) and len(json.dumps(proof).encode()) <= 2048
    for checkpoint in ("probes_dependencies_readiness", "probes_peer_launch"):
        value = probe_failure_evidence(error, checkpoint, "container_exec", "ingest-worker", None,
                                       reason_code=CANARY, secondary_reason={"password": CANARY})
        assert "reason_code" not in value and "secondary_reason" not in value and CANARY not in json.dumps(value)


def test_delayed_real_phase_publication_waits_then_uses_exit_zero_before_peer(dependencies, monkeypatch):
    lab, cli, clock = dependencies
    process = worker_probe.ProcessProbe("ingest", clock=lambda: clock.now)
    process.data = {"initialized": True, "heartbeat_monotonic": clock.now, "phase": "blocked",
                    "phase_started_monotonic": clock.now, "last_poll_monotonic": clock.now,
                    "last_successful_cycle_monotonic": clock.now}
    published = copy.deepcopy(process.data)
    process.poll()
    assert process.data["phase"] == "idle" and published["phase"] == "blocked"
    monkeypatch.setattr(worker_probe, "read_probe", lambda *args, **kwargs: (published.copy(), clock.now))
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"})
    original = cli.probe_status
    results, waits = [], []

    def status(record, mode):
        if mode == "readiness" and cli.preflight and lab.probe_section == "dependencies":
            original(record, mode)
            diagnostic = worker_probe.ReadinessDiagnostic()
            ready = worker_probe.local_check(mode, "ingest", diagnostic=diagnostic)
            results.append(ready)
            return ready
        return original(record, mode)

    def sleep(seconds):
        clock.sleep(seconds)
        if seconds <= 1:
            waits.append(seconds)
            if len(waits) == 2:
                published.update(copy.deepcopy(process.data))
                published["heartbeat_monotonic"] = clock.now

    cli.probe_status = status
    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    original_runner = cli.runner

    def runner(command, **kwargs):
        if command[3] == "compose" and command[10] == "up":
            assert results[-1] is True and len(results) == 3
            assert lab.probe_reason is lab.probe_secondary_reason is None
        return original_runner(command, **kwargs)

    lab.docker.runner = runner
    lab.experiment_probes("unused")
    assert results == [False, False, True] and waits == [1, 1]
    assert clock.sleeps == [10, 1, 1, 32]
    assert cli.launches[0]["deadline"] == cli.launches[0]["docker_deadline"] == 230
    assert cli.launches[0]["timeout"] == 118
    assert cli.readiness_records == ["0" * 63 + "1"] * 3
    assert (lab.deadline, lab.docker.deadline) == (1000.0, 900.0)
    assert lab.failure is None
    pairs = cli.diagnostic_pairs
    for service in ("migrate", "redis", "clickhouse"):
        assert pairs.count(("probes_dependencies_inspect", "container_inspect", service)) == 3
    assert pairs.count(("probes_dependencies_readiness_identity", "container_inspect", "ingest-worker")) == 3


def test_persistent_phase_unready_exhausts_original_window_without_peer(dependencies):
    lab, cli, clock = dependencies
    cli.ready = False
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"})
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="budget"):
        lab.experiment_probes("unused")
    assert clock.now == 230 and clock.sleeps == [10] + [1] * 120
    assert len(cli.readiness_records) == 120
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_wait")
    assert "reason_code" not in lab.failure and "secondary_reason" not in lab.failure


@pytest.mark.parametrize("mutation", ["worker_identity", "store_identity", "store_health", "store_stopped",
                                      "migration_exit", "migration_running"])
def test_recovery_revalidates_every_identity_and_state_after_each_phase_refusal(dependencies, monkeypatch, mutation):
    lab, cli, clock = dependencies
    cli.ready = False
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"})
    before = copy.deepcopy(lab.journal.value["resources"])

    def sleep(seconds):
        clock.sleep(seconds)
        if seconds <= 1:
            worker = cli.containers["0" * 63 + "1"]
            store = cli.containers[cli.dependency_ids["redis"]]
            migration = cli.containers[cli.dependency_ids["migrate"]]
            if mutation == "worker_identity":
                worker["Created"] = "foreign"
            elif mutation == "store_identity":
                store["Created"] = "foreign"
            elif mutation == "store_health":
                store["State"]["Health"]["Status"] = "unhealthy"
            elif mutation == "store_stopped":
                store["State"]["Running"] = False
            elif mutation == "migration_exit":
                migration["State"]["ExitCode"] = 1
            else:
                migration["State"].update(Status="running", Running=True)

    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    with pytest.raises(QualificationError):
        lab.experiment_probes("unused")
    assert len(cli.readiness_records) == 1 and clock.sleeps == [10, 1]
    assert_refused_without_adoption(lab, cli, before)


def test_starting_stores_revalidate_worker_identity_before_next_wait(dependencies, monkeypatch):
    lab, cli, clock = dependencies
    cli.containers[cli.dependency_ids["redis"]]["State"]["Health"]["Status"] = "starting"
    before = copy.deepcopy(lab.journal.value["resources"])

    def sleep(seconds):
        clock.sleep(seconds)
        if seconds <= 1:
            cli.containers["0" * 63 + "1"]["Created"] = "foreign"

    monkeypatch.setattr(lab_module.time, "sleep", sleep)
    with pytest.raises(QualificationError):
        lab.experiment_probes("unused")
    assert not cli.readiness_records and clock.sleeps == [10, 1]
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_readiness_identity", service="ingest-worker")


@pytest.mark.parametrize("raw", [
    json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "dependency_cleanup_error"}),
    '{"schema":1,"reason":"phase_unready","secondary_reason":"none","reason":"phase_unready"}',
    '{"schema":1,"reason":"phase_unready","secondary_reason":"none"',
    json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"}) + "\n{}",
])
def test_phase_secondary_or_nonexact_json_refuses_without_recovery_wait(dependencies, raw):
    lab, cli, clock = dependencies
    cli.ready, cli.readiness_diagnostic = False, raw
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="not ready"):
        lab.experiment_probes("unused")
    assert len(cli.readiness_records) == 1 and clock.sleeps == [10]
    assert_refused_without_adoption(lab, cli, before)
    assert_probe_failure(lab, "probes_dependencies_readiness")


@pytest.mark.parametrize("primary", [DockerOperationError("docker_nonzero", 17),
                                   subprocess.TimeoutExpired(CANARY, 1, output=CANARY, stderr=CANARY),
                                   KeyboardInterrupt(CANARY), SystemExit(CANARY), asyncio.CancelledError(CANARY)])
def test_later_readiness_exception_retains_identity_without_stale_phase_reason(dependencies, monkeypatch, primary):
    lab, cli, clock = dependencies
    cli.ready = False
    cli.readiness_diagnostic = json.dumps({"schema": 1, "reason": "phase_unready", "secondary_reason": "none"})
    before = copy.deepcopy(lab.journal.value["resources"])
    original, calls = cli.runner, []

    def runner(command, **kwargs):
        if lab.probe_section == "dependencies" and command[3:5] == ["container", "exec"]:
            calls.append(kwargs.copy())
            if len(calls) == 2:
                raise primary
        return original(command, **kwargs)

    lab.docker.runner = runner
    with pytest.raises(type(primary)) as caught:
        lab.experiment_probes("unused")
    assert caught.value is primary and len(calls) == 2 and clock.sleeps == [10, 1]
    assert "reason_code" not in lab.failure and "secondary_reason" not in lab.failure
    assert_refused_without_adoption(lab, cli, before)


@pytest.mark.parametrize("inspect_cost", [30, 40])
def test_inspections_exhaust_budget_before_new_readiness_exec(dependencies, inspect_cost):
    lab, cli, _ = dependencies
    cli.inspect_cost = inspect_cost
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="budget"):
        lab.experiment_probes("unused")
    assert not cli.readiness_records
    assert_refused_without_adoption(lab, cli, before)


def test_real_ready_exit_at_exact_deadline_cannot_authorize_peer(dependencies):
    lab, cli, clock = dependencies
    lab.deadline = lab.docker.deadline = 118.0
    cli.readiness_cost = 8
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="budget"):
        lab.experiment_probes("unused")
    assert clock.now == 118 and len(cli.readiness_records) == 1
    assert not cli.launches and lab.journal.value["resources"] == before
    assert (lab.deadline, lab.docker.deadline) == (118.0, 118.0)
    assert_probe_failure(lab, "probes_dependencies_launch_budget")
    assert "reason_code" not in lab.failure
