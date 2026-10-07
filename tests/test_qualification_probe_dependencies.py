"""Probe peer dependency ownership and one shared window; synthetic Docker only."""

import copy

import pytest
from test_qualification_pressure_diagnostics import CliModel, create_lab

import shadai.qualification.lab as lab_module
from shadai.qualification.journal import LABEL, resource_identity, verify_resource
from shadai.qualification.lab import Docker, DockerOperationError
from shadai.qualification.schemas import QualificationError


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
        verify_resource(record, self.lab.docker.inspect("container", record["id"]))
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
    monkeypatch.setattr(lab, "probe_status", cli.probe_status)
    return lab, cli, clock


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


def test_worker_readiness_false_prevents_launch_under_same_identity(dependencies):
    lab, cli, _ = dependencies
    cli.ready = False
    before = copy.deepcopy(lab.journal.value["resources"])
    with pytest.raises(QualificationError, match="not ready"):
        lab.experiment_probes("unused")
    assert cli.readiness_records == ["0" * 63 + "1"]
    assert_refused_without_adoption(lab, cli, before)


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
