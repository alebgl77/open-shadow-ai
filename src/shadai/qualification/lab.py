"""Owned disposable Docker laboratory orchestration, using only host stdlib."""

import base64
import hashlib
import json
import os
import platform
import secrets
import stat
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from shadai.qualification.http_transport import HttpTransport
from shadai.qualification.journal import LABEL, RunJournal, atomic_json, resource_identity, verify_resource
from shadai.qualification.load import LoadSender
from shadai.qualification.schemas import SCENARIOS, QualificationError, canonical_bytes, report

SERVICES = {
    "api",
    "ingest-worker",
    "correlation-worker",
    "purge-worker",
    "postgres",
    "clickhouse",
    "redis",
    "labredis-pressure",
    "migrate",
}
TOOLS = {"node-exporter", "probe-ingest-peer"}
WRITERS = {"api", "ingest-worker", "correlation-worker", "purge-worker"}
STORES = {"postgres", "clickhouse", "redis"}


class Docker:
    def __init__(self, context, *, runner=subprocess.run):
        if not context or any(char.isspace() for char in context):
            raise QualificationError("An explicit Docker context is required")
        self.context, self.runner = context, runner
        self.deadline = None

    def call(self, *args, environment=None, timeout=120, absent=False):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError("Laboratory wall budget exhausted")
            timeout = min(timeout, remaining)
        result = self.runner(
            ["docker", "--context", self.context, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
        if result.returncode:
            import re

            if absent and re.search(r"\bno such (?:container|network|volume|object)\b", result.stderr, re.I):
                return None
            raise QualificationError("Docker operation failed; upstream output retained by Docker only")
        if len(result.stdout) > 4 * 1048576:
            raise QualificationError("Docker output exceeds proof budget")
        return result.stdout.strip()

    def inspect(self, kind, identifier, *, absent=False):
        result = self.call(kind, "inspect", identifier, absent=absent)
        return None if result is None else json.loads(result)[0]


class Laboratory:
    def __init__(self, repository, directory, profile, context, *, docker=None):
        self.repository = Path(repository).resolve()
        self.directory = Path(directory).absolute()
        self.profile, self.context = profile, context
        self.compose_file = self.repository / "deploy/qualification/compose.yaml"
        self.config_hash = hashlib.sha256(self.compose_file.read_bytes() + canonical_bytes(profile)).hexdigest()
        self.docker = docker or Docker(context)
        self.journal = None
        self.sender = None
        self.scenarios = []
        self.deadline = None

    def remaining(self):
        if self.deadline is None:
            return self.profile["limits"]["max_wall_seconds"]
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise QualificationError("Laboratory wall budget exhausted")
        return remaining

    def local_deadline(self, seconds):
        return time.monotonic() + min(seconds, self.remaining())

    def sleep(self, seconds):
        time.sleep(min(seconds, self.remaining()))
        self.remaining()

    def retained_bytes(self):
        total, count = 0, 0
        for directory, directories, files in os.walk(self.directory, followlinks=False):
            self.remaining()
            for name in [*directories, *files]:
                metadata = (Path(directory) / name).lstat()
                if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                    raise QualificationError("Run artifacts must be regular files or directories without links")
                if stat.S_ISREG(metadata.st_mode):
                    total += metadata.st_size
                    count += 1
                    if count > 100000 or total > self.profile["limits"]["max_disk_bytes"]:
                        raise QualificationError("Cumulative run artifact budget exhausted")
        return total

    def artifact_remaining(self, reserve=0):
        available = self.profile["limits"]["max_disk_bytes"] - self.retained_bytes() - reserve
        if available <= 0:
            raise QualificationError("Cumulative run artifact budget exhausted")
        return available

    def prepare(self, resume=False):
        if platform.system() != "Linux" or os.getuid() == 0:
            raise QualificationError("Lab execution requires a nonroot Linux orchestrator")
        self.docker.call("info", "--format", "{{json .ServerVersion}}", timeout=20)
        factory = RunJournal.resume if resume else RunJournal.create
        self.journal = factory(self.directory, self.profile, self.config_hash, self.context)
        self.tenant = "q-" + self.journal.value["run_id"].replace("-", "")
        self.run_profile = {**self.profile, "installation": self.tenant}
        if resume:
            self.guard_all()
            self.verify_secrets()
            if json.loads((self.directory / "source.json").read_text()) != self.source_proof():
                raise QualificationError("Resume source or execution environment changed")
        else:
            self.make_secrets()
            atomic_json(self.directory / "profile.json", self.run_profile)
            atomic_json(self.directory / "source.json", self.source_proof())
        self.scenarios = (
            json.loads((self.directory / "report.json").read_text()).get("scenarios", [])
            if (self.directory / "report.json").exists()
            else []
        )

    def source_proof(self):
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repository,
            capture_output=True,
            text=True,
            check=True,
            timeout=min(10, self.remaining()),
        ).stdout.strip()
        files = [
            *self.repository.glob("src/**/*.py"),
            *self.repository.glob("docker/**"),
            *self.repository.glob("catalog/builtin/*.yaml"),
            self.compose_file,
        ]
        hashes = {
            str(path.relative_to(self.repository)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
            if path.is_file()
        }
        return {
            "revision": revision,
            "source_sha256": hashes,
            "environment": {
                "system": platform.system(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "uid": os.getuid(),
                "gid": os.getgid(),
                "runtime_production_uid": 10001,
                "docker_context": self.context,
            },
        }

    def make_secrets(self):
        directory = self.directory / "secrets"
        directory.mkdir(mode=0o700)
        values = {
            name: secrets.token_urlsafe(48)
            for name in ("pg_password", "redis_password", "redis_pressure_password", "ch_password", "jwt_secret")
        }
        values["encryption_key"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        hashes = {}
        for name, value in values.items():
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as file:
                file.write(value)
            hashes[name] = hashlib.sha256(value.encode()).hexdigest()
        atomic_json(self.directory / "secret-hashes.json", hashes)

    def verify_secrets(self):
        expected = json.loads((self.directory / "secret-hashes.json").read_text())
        actual = {
            name: hashlib.sha256((self.directory / "secrets" / name).read_bytes()).hexdigest() for name in expected
        }
        if actual != expected:
            raise QualificationError("Lab key material changed after journaling")

    def environment(self, role="source"):
        return {
            **os.environ,
            "SHADAI_QUAL_REPO": str(self.repository),
            "SHADAI_QUAL_DIR": str(self.directory),
            "SHADAI_QUAL_RUN": self.journal.value["run_id"],
            "SHADAI_QUAL_ROLE": role,
            "SHADAI_QUAL_TENANT": self.tenant,
            "SHADAI_QUAL_UID": str(os.getuid()),
            "SHADAI_QUAL_GID": str(os.getgid()),
        }

    def compose(self, *args, role="source", timeout=120):
        self.guard_all()
        project = self.journal.value["projects"][role]
        return self.docker.call(
            "compose",
            "--project-name",
            project,
            "--file",
            str(self.compose_file),
            "--env-file",
            str(self.directory / "empty.env"),
            *args,
            environment=self.environment(role),
            timeout=min(timeout, self.remaining()),
        )

    def discover(self, role="source"):
        project = self.journal.value["projects"][role]
        records = []
        for kind, command in (("container", "ps"), ("network", "network"), ("volume", "volume")):
            args = [command, "-aq"] if kind == "container" else [command, "ls", "-q"]
            identifiers = self.docker.call(*args, "--filter", "label=com.docker.compose.project=" + project)
            for identifier in identifiers.splitlines():
                inspected = self.docker.inspect(kind, identifier)
                labels = inspected.get("Config", {}).get("Labels", {}) if kind == "container" else inspected["Labels"]
                actual_role = labels.get(LABEL + "role")
                if actual_role not in {role, "pressure"}:
                    raise QualificationError("Foreign resource shares the lab project name")
                records.append(resource_identity(kind, inspected, self.journal.value["run_id"], actual_role, project))
        self.journal.add_resources(records)

    def guard_all(self):
        if self.journal:
            for record in self.journal.value["resources"]:
                inspected = self.docker.inspect(record["kind"], record["id"])
                verify_resource(record, inspected)

    def containers(self, services, role="source"):
        if not set(services) <= SERVICES | TOOLS:
            raise QualificationError("Unknown lab service")
        records = [
            item
            for item in self.journal.value["resources"]
            if item["kind"] == "container"
            and item["project"] == self.journal.value["projects"][role]
            and item["service"] in services
        ]
        if {item["service"] for item in records} != set(services):
            raise QualificationError("Required lab container identity is absent")
        return records

    def change(self, operation, services, role="source"):
        for record in self.containers(services, role):
            inspected = self.docker.inspect("container", record["id"])
            verify_resource(record, inspected)
            self.docker.call("container", operation, record["id"])
            state = self.docker.inspect("container", record["id"])["State"]
            if operation == "stop" and state["Running"]:
                raise QualificationError("Container did not stop")

    def inspector(self, action, *, case="baseline", role="source"):
        name = self.journal.value["projects"][role] + "-inspector-" + uuid4().hex[:12]
        identifier = self.compose(
            "run",
            "--no-deps",
            "-d",
            "--name",
            name,
            "inspector",
            "python",
            "-m",
            "shadai.qualification",
            "fixture",
            action,
            "--run-id",
            self.journal.value["run_id"],
            "--case",
            case,
            role=role,
        )
        inspected = self.docker.inspect("container", identifier)
        record = resource_identity(
            "container", inspected, self.journal.value["run_id"], role, self.journal.value["projects"][role]
        )
        self.journal.add_resources([record])
        try:
            code = self.docker.call("container", "wait", identifier, timeout=180)
            output = self.docker.call("container", "logs", identifier)
            if int(code) != 0:
                raise QualificationError("Lab inspector failed its requested proof")
            return json.loads(output.splitlines()[-1])
        finally:
            self.remove(record)

    def remove(self, record, *, volumes=False):
        if record["kind"] == "volume" and not volumes:
            return
        inspected = self.docker.inspect(record["kind"], record["id"], absent=True)
        if inspected is not None:
            verify_resource(record, inspected)
            self.docker.call(record["kind"], "rm", record["id"])
        self.journal.value["resources"] = [item for item in self.journal.value["resources"] if item != record]
        self.journal.save()

    def wait_ready(self, role="source"):
        deadline = self.local_deadline(120)
        port = self.compose("port", "api", "8443", role=role)
        if not port.startswith("127.0.0.1:"):
            raise QualificationError("Lab API is not published on an ephemeral loopback port")
        url = "http://" + port
        transport = HttpTransport()
        while time.monotonic() < deadline:
            status, _, error = transport.request(url + "/ready", deadline=deadline, timeout=3)
            if status == 200 and error == "none":
                return url
            self.sleep(min(1, max(0, deadline - time.monotonic())))
        raise QualificationError("Lab API readiness prerequisite failed")

    def send(self, url, case, *, total=None):
        profile = self.run_profile
        if total is not None:
            profile = {**profile, "load": {**profile["load"], "total_events": total}}
        used = sum(json.loads(path.read_text()).get("requests", 0) for path in self.directory.glob("*-load.json"))
        available = self.profile["limits"]["max_requests"] - used
        if available <= 0:
            raise QualificationError("Laboratory cumulative HTTP request budget exhausted")
        profile = {
            **profile,
            "limits": {**profile["limits"], "max_wall_seconds": self.remaining(), "max_requests": available},
        }
        collector = "qualification-" + self.journal.value["run_id"].replace("-", "")
        self.sender = LoadSender(profile, self.journal.value["run_id"], case, self.directory, collector)
        try:
            return self.sender.run(url, (self.directory / "collector-key").read_text(), deadline=self.deadline)
        finally:
            self.sender = None

    def drain(self, case, role="source"):
        deadline = self.local_deadline(self.profile["load"]["drain_timeout_seconds"])
        while time.monotonic() < deadline:
            result = self.inspector("verify_load", case=case, role=role)
            if not (result["missing"] or result["missing_receipts"] or result["missing_correlations"]):
                return result
            self.sleep(min(2, max(0, deadline - time.monotonic())))
        raise AssertionError("Accepted logical events did not reach receipts and correlation within the budget")

    def record(self, scenario, **measurements):
        self.scenarios = [item for item in self.scenarios if item["scenario"] != scenario]
        self.scenarios.append(
            {"scenario": scenario, "required": True, "executed": True, "status": "passed", "measurements": measurements}
        )
        self.journal.phase(scenario, completed=True)
        self.write_report()

    def write_report(self, missing=None):
        result = report(
            self.profile,
            self.scenarios,
            evidence={
                "run_id": self.journal.value["run_id"],
                "installation": self.tenant,
                "source": json.loads((self.directory / "source.json").read_text()),
                "laboratory_only": True,
                "production_rpo_rto": "not_evaluated",
            },
            missing=missing,
        )
        atomic_json(self.directory / "report.json", result)
        return result["exit_code"]

    def execute(self, resume=False):
        self.deadline = time.monotonic() + self.profile["limits"]["max_wall_seconds"]
        self.docker.deadline = self.deadline
        self.prepare(resume)
        (self.directory / "empty.env").touch(mode=0o600, exist_ok=True)
        try:
            if not resume:
                self.journal.phase("starting")
                try:
                    self.compose("up", "-d", "--build", *sorted(SERVICES), timeout=600)
                finally:
                    self.discover()
            if "initialized" not in self.journal.value["completed"]:
                self.change("stop", WRITERS)
                self.inspector("initialize")
                self.journal.phase("initialized", completed=True)
                self.change("start", WRITERS)
            url = self.wait_ready()
            if not (self.directory / "collector-key").exists():
                self.inspector("enroll")
            completed = set(self.journal.value["completed"])
            if "baseline" in self.profile["scenarios"] and "baseline" not in completed:
                self.journal.phase("baseline")
                load = self.send(url, "baseline")
                assert load["accepted"] == self.profile["load"]["total_events"]
                persisted = self.drain("baseline")
                self.record("baseline", load=load, verification=persisted)
            if "pause_ingest" in self.profile["scenarios"] and "pause_ingest" not in completed:
                self.journal.phase("pause_ingest")
                self.change("stop", {"ingest-worker"})
                load = self.send(url, "pause_ingest", total=20)
                backlog = self.inspector("inventory", case="paused")["pipeline"]
                assert any(
                    row["undelivered"]
                    for stage in backlog["stages"]
                    for row in stage["streams"]
                    if stage["stage"] == "ingest"
                )
                self.change("start", {"ingest-worker"})
                before = time.monotonic()
                self.record(
                    "pause_ingest",
                    load=load,
                    backlog=backlog,
                    verification=self.drain("pause_ingest"),
                    recovery_seconds=time.monotonic() - before,
                )
            if "correlation_outage" in self.profile["scenarios"] and "correlation_outage" not in completed:
                self.journal.phase("correlation_outage")
                self.change("stop", {"correlation-worker"})
                load = self.send(url, "correlation_outage", total=20)
                deadline = self.local_deadline(60)
                while time.monotonic() < deadline:
                    backlog = self.inspector("inventory", case="correlation-outage")["pipeline"]
                    if any(
                        row["undelivered"]
                        for stage in backlog["stages"]
                        for row in stage["streams"]
                        if stage["stage"] == "correlation"
                    ):
                        break
                    self.sleep(min(1, max(0, deadline - time.monotonic())))
                else:
                    raise AssertionError("Correlation outage did not retain observable backlog")
                self.change("start", {"correlation-worker"})
                before = time.monotonic()
                self.record(
                    "correlation_outage",
                    load=load,
                    backlog=backlog,
                    verification=self.drain("correlation_outage"),
                    recovery_seconds=time.monotonic() - before,
                )
            self.execute_special(url, completed)
            return self.write_report()
        except (KeyboardInterrupt, BaseException) as exc:
            if self.sender:
                self.sender.stop()
            self.journal.value["cancelled"] = isinstance(exc, (KeyboardInterrupt, SystemExit))
            phase = self.journal.value["phase"]
            if phase in SCENARIOS:
                self.scenarios = [item for item in self.scenarios if item["scenario"] != phase]
                self.scenarios.append(
                    {
                        "scenario": phase,
                        "required": True,
                        "executed": True,
                        "status": "failed" if isinstance(exc, AssertionError) else "not_evaluated",
                        "reason": type(exc).__name__,
                    }
                )
            self.journal.phase("cancelled" if self.journal.value["cancelled"] else "interrupted")
            return self.write_report([phase])

    def execute_special(self, url, completed):
        for scenario in ("reclaim", "redis_pressure", "probes", "physical", "cold_restore"):
            if scenario in self.profile["scenarios"] and scenario not in completed:
                self.journal.phase(scenario)
                self.remaining()
                getattr(self, "experiment_" + scenario)(url)

    def experiment_reclaim(self, url):
        self.change("stop", {"clickhouse"})
        load = self.send(url, "reclaim", total=20)
        deadline = self.local_deadline(60)
        while time.monotonic() < deadline:
            pipeline = self.inspector("pipeline")["pipeline"]
            if any(
                row["pending"] for stage in pipeline["stages"] if stage["stage"] == "ingest" for row in stage["streams"]
            ):
                break
            self.sleep(min(1, max(0, deadline - time.monotonic())))
        else:
            raise AssertionError("No real consumer PEL was witnessed before termination")
        self.change("stop", {"ingest-worker"})
        self.change("start", {"clickhouse"})
        self.change("start", {"ingest-worker"})
        before = time.monotonic()
        persisted = self.drain("reclaim")
        self.record(
            "reclaim",
            load=load,
            witnessed_pel=pipeline,
            terminated_after_witness=True,
            verification=persisted,
            recovery_seconds=time.monotonic() - before,
        )

    def run_owned(self, command, *, role="source", volumes=(), root=False, caps=(), archive=None):
        project = self.journal.value["projects"][role]
        worker = self.containers({"ingest-worker"})[0]
        inspected = self.docker.inspect("container", worker["id"])
        verify_resource(worker, inspected)
        args = [
            "container",
            "create",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--user",
            "0:0" if root else f"{os.getuid()}:{os.getgid()}",
            "--tmpfs",
            "/tmp:rw,size=1073741824",
            "--label",
            LABEL + "run=" + self.journal.value["run_id"],
            "--label",
            LABEL + "role=" + role,
            "--label",
            "com.docker.compose.project=" + project,
            "--entrypoint",
            "python",
        ]
        for capability in caps:
            if capability not in {"DAC_READ_SEARCH", "CHOWN", "FOWNER"}:
                raise QualificationError("Unapproved archive helper capability")
            args.extend(["--cap-add", capability])
        for volume, destination, readonly in volumes:
            current = self.docker.inspect("volume", volume["id"])
            verify_resource(volume, current)
            args.extend(
                [
                    "--mount",
                    "type=volume,src=" + volume["id"] + ",dst=" + destination + (",readonly" if readonly else ""),
                ]
            )
        if archive:
            path = self.directory / archive
            if path.is_symlink() or path.parent != self.directory or not path.is_file():
                raise QualificationError("Archive must be a regular owned-run file")
            args.extend(["--mount", "type=bind,src=" + str(path) + ",dst=/archive.tar,readonly"])
        args.extend([inspected["Image"], *command])
        identifier = self.docker.call(*args)
        record = resource_identity(
            "container", self.docker.inspect("container", identifier), self.journal.value["run_id"], role, project
        )
        self.journal.add_resources([record])
        return record

    def helper_result(self, record, *, copy_archive=None):
        inspected = self.docker.inspect("container", record["id"])
        verify_resource(record, inspected)
        self.docker.call("container", "start", record["id"])
        code = int(self.docker.call("container", "wait", record["id"], timeout=180))
        output = self.docker.call("container", "logs", record["id"])
        if code != 0:
            raise QualificationError("Archive helper failed")
        result = json.loads(output.splitlines()[-1])
        if copy_archive:
            verify_resource(record, self.docker.inspect("container", record["id"]))
            destination = self.directory / copy_archive
            if destination.exists():
                raise QualificationError("Archive destination already exists")
            if type(result.get("bytes")) is not int or not 0 < result["bytes"] <= self.artifact_remaining():
                raise QualificationError("Cold archive exceeds cumulative remaining artifact budget")
            self.docker.call("container", "cp", record["id"] + ":/tmp/archive.tar", str(destination))
            destination.chmod(0o600)
            if destination.is_symlink() or destination.stat().st_size != result["bytes"]:
                raise QualificationError("Copied archive size differs from the owned helper proof")
            self.retained_bytes()
        self.remove(record)
        return result

    def volume(self, service, role="source"):
        container = self.containers({service}, role)[0]
        inspected = self.docker.inspect("container", container["id"])
        verify_resource(container, inspected)
        mounts = [item for item in inspected["Mounts"] if item["Type"] == "volume"]
        if len(mounts) != 1:
            raise QualificationError("Store volume mapping is not exact")
        return next(
            item
            for item in self.journal.value["resources"]
            if item["kind"] == "volume" and item["id"] == mounts[0]["Name"]
        )

    def archive_store(self, service):
        from shadai.qualification.snapshot import digest_file

        available = min(self.artifact_remaining(reserve=10485760), 1073741824 - 10485760)
        volume = self.volume(service)
        container = self.containers({service})[0]
        if self.docker.inspect("container", container["id"])["State"]["Running"]:
            raise QualificationError("A cold snapshot requires verified stopped stores")
        name = service + "-cold.tar"
        record = self.run_owned(
            [
                "-m",
                "shadai.qualification",
                "snapshot",
                "export",
                "--archive",
                "/tmp/archive.tar",
                "--max-bytes",
                str(available),
            ],
            volumes=[(volume, "/volume", True)],
            root=True,
            caps=["DAC_READ_SEARCH"],
        )
        result = self.helper_result(record, copy_archive=name)
        if digest_file(self.directory / name) != result["sha256"]:
            raise QualificationError("Copied cold archive does not match the helper manifest")
        return {**result, "archive": name, "source_volume": volume}

    def fresh_restore_volume(self, source, *, service):
        archive = self.directory / source["archive"]
        if (
            archive.parent != self.directory
            or archive.is_symlink()
            or not archive.is_file()
            or archive.stat().st_size != source["bytes"]
        ):
            raise QualificationError("Import archive differs from its exact owned size proof")
        self.retained_bytes()
        suffix = {
            "postgres": "pg_data",
            "clickhouse": "ch_data",
            "redis": "redis_data",
            "labredis-pressure": "pressure_data",
        }[service]
        project = self.journal.value["projects"]["restore"]
        name = project + "_" + suffix
        if self.docker.inspect("volume", name, absent=True) is not None:
            raise QualificationError("Restore volume name already exists; fresh empty volume required")
        role = "pressure" if service == "labredis-pressure" else "restore"
        self.docker.call(
            "volume",
            "create",
            "--label",
            LABEL + "run=" + self.journal.value["run_id"],
            "--label",
            LABEL + "role=" + role,
            "--label",
            "com.docker.compose.project=" + project,
            "--label",
            "com.docker.compose.volume=" + suffix,
            name,
        )
        record = resource_identity(
            "volume", self.docker.inspect("volume", name), self.journal.value["run_id"], role, project
        )
        self.journal.add_resources([record])
        helper = self.run_owned(
            [
                "-m",
                "shadai.qualification",
                "snapshot",
                "import",
                "--archive",
                "/archive.tar",
                "--sha256",
                source["sha256"],
                "--max-bytes",
                str(self.profile["limits"]["max_disk_bytes"]),
            ],
            role="restore",
            volumes=[(record, "/volume", False)],
            root=True,
            caps=["DAC_READ_SEARCH", "CHOWN", "FOWNER"],
            archive=source["archive"],
        )
        self.helper_result(helper)
        return record

    def experiment_cold_restore(self, url):
        self.change("stop", WRITERS)
        fixture = self.inspector("seed_pending")
        assert fixture["pel_witnessed"]
        self.inspector("inventory", case="source")
        self.change("stop", STORES)
        before = time.monotonic()
        archives = {service: self.archive_store(service) for service in sorted(STORES)}
        atomic_json(
            self.directory / "cold-manifest.json",
            {
                "schema": 1,
                "run_id": self.journal.value["run_id"],
                "config_sha256": self.config_hash,
                "secret_hashes": json.loads((self.directory / "secret-hashes.json").read_text()),
                "archives": archives,
                "pending_fixture": fixture,
            },
        )
        self.verify_secrets()
        for service, archive in archives.items():
            self.fresh_restore_volume(archive, service=service)
        try:
            self.compose("up", "-d", "--wait", "--wait-timeout", "180", *sorted(STORES), role="restore", timeout=180)
        finally:
            self.discover("restore")
        self.inspector("inventory", case="restore", role="restore")
        source = json.loads((self.directory / "source-inventory.json").read_text())
        restored = json.loads((self.directory / "restore-inventory.json").read_text())
        assert source == restored, "Exact cold source/restore inventories differ before worker startup"
        try:
            self.compose("up", "-d", *sorted(WRITERS), role="restore", timeout=180)
        finally:
            self.discover("restore")
        restored_url = self.wait_ready("restore")
        # Reclaimed pending work and a fresh scoped event must both persist after startup.
        fresh = self.send(restored_url, "restored-fresh", total=10)
        self.verify_fresh_restore(fresh)
        verification = self.drain("restored-fresh", "restore")
        self.verify_fresh_restore(fresh, verification)
        self.record(
            "cold_restore",
            exact_inventory_before_workers=True,
            pending_fixture=fixture,
            fresh_load=fresh,
            fresh_verification=verification,
            measured_restore_seconds=time.monotonic() - before,
            production_rpo_rto="not_evaluated",
        )

    @staticmethod
    def verify_fresh_restore(fresh, verification=None):
        identifiers = fresh["accepted_scoped_ids"]
        assert type(fresh["accepted"]) is int and fresh["accepted"] == 10
        assert len(identifiers) == len(set(identifiers)) == 10
        if verification is not None:
            assert verification["expected_logical_events"] == 11
            assert verification["persisted"] == verification["receipts"] == verification["correlation_receipts"] == 11
            assert not any(verification[key] for key in ("missing", "missing_receipts", "missing_correlations"))
            assert verification["restored_pending_fixture_persisted"] is True

    def experiment_redis_pressure(self, url):
        import xml.etree.ElementTree as ET

        phases = []
        (self.directory / "pressure-reports").mkdir(mode=0o700, exist_ok=True)
        (self.directory / "pressure-artifacts").mkdir(mode=0o700, exist_ok=True)
        for mode in ("seed", "assert"):
            role = "source" if mode == "seed" else "restore"
            if mode == "assert":
                self.change("stop", {"labredis-pressure"})
                archive = self.archive_store("labredis-pressure")
                self.fresh_restore_volume(archive, service="labredis-pressure")
                try:
                    self.compose("up", "-d", "--wait", "--wait-timeout", "60", "labredis-pressure", role="restore")
                finally:
                    self.discover("restore")
            name = self.journal.value["projects"][role] + "-pressure-" + mode
            service = "pressure-test" if mode == "seed" else "pressure-assert"
            output = "/qualification/pressure-seed.xml" if mode == "seed" else "/reports/pressure-assert.xml"
            identifier = self.compose(
                "run",
                "--build",
                "--no-deps",
                "-d",
                "--name",
                name,
                "-e",
                "SHADAI_REDIS_PRESSURE_MODE=" + mode,
                service,
                "python",
                "-m",
                "pytest",
                "-q",
                "-m",
                "redis_pressure",
                "-p",
                "no:cacheprovider",
                "--junitxml=" + output,
                role=role,
            )
            inspected = self.docker.inspect("container", identifier)
            record = resource_identity(
                "container", inspected, self.journal.value["run_id"], "pressure", self.journal.value["projects"][role]
            )
            self.journal.add_resources([record])
            code = int(self.docker.call("container", "wait", identifier, timeout=180))
            verify_resource(record, self.docker.inspect("container", identifier))
            self.remove(record)
            result = ET.parse(
                self.directory
                / ("pressure-artifacts/pressure-seed.xml" if mode == "seed" else "pressure-reports/pressure-assert.xml")
            )
            tests = list(result.iter("testcase"))
            assert code == 0 and tests and not list(result.iter("skipped")) and not list(result.iter("failure"))
            assert not list(result.iter("error"))
            assert {
                "test_required_pressure_and_aof_phase",
                "test_real_redis_oom_before_allocation_and_owned_release_recovers",
            } <= {item.get("name") for item in tests}
            phases.append({"phase": mode, "executed_tests": len(tests), "skipped": 0})
        self.record(
            "redis_pressure",
            phases=phases,
            separate_store=True,
            maxmemory_bytes=33554432,
            policy="noeviction",
            aof_cold_clone=True,
        )

    def probe_status(self, record, mode):
        verify_resource(record, self.docker.inspect("container", record["id"]))
        command = ["python", "-m", "shadai.workers.probe", mode, "--stage", "ingest"]
        if mode == "readiness":
            command = ["python", "/app/entrypoint.py", *command]
        result = self.docker.runner(
            ["docker", "--context", self.context, "container", "exec", record["id"], *command],
            capture_output=True,
            text=True,
            timeout=min(8, self.remaining()),
        )
        return result.returncode == 0

    def experiment_probes(self, url):
        worker = self.containers({"ingest-worker"})[0]
        assert self.probe_status(worker, "startup") and self.probe_status(worker, "liveness")
        before = self.docker.inspect("container", worker["id"])["RestartCount"]
        self.change("stop", {"redis"})
        self.sleep(10)
        assert self.probe_status(worker, "liveness") and not self.probe_status(worker, "readiness")
        assert self.docker.inspect("container", worker["id"])["RestartCount"] == before
        self.change("start", {"redis"})
        try:
            self.compose("up", "-d", "probe-ingest-peer")
        finally:
            self.discover()
        peer = self.containers({"probe-ingest-peer"})[0]
        deadline = self.local_deadline(30)
        while time.monotonic() < deadline and not self.probe_status(peer, "startup"):
            self.sleep(min(1, max(0, deadline - time.monotonic())))
        assert self.probe_status(peer, "liveness")
        verify_resource(worker, self.docker.inspect("container", worker["id"]))
        signal_command = (
            "from shadai.workers.probe import read_probe; import os,signal; "
            "v,_=read_probe('ingest'); os.kill(v['pid'],signal.SIGSTOP)"
        )
        self.docker.call("container", "exec", worker["id"], "python", "-c", signal_command)
        try:
            self.sleep(32)
            assert not self.probe_status(worker, "liveness") and self.probe_status(peer, "liveness")
        finally:
            budget_deadline = self.docker.deadline
            self.docker.deadline = time.monotonic() + 10
            try:
                verify_resource(worker, self.docker.inspect("container", worker["id"]))
                self.docker.call(
                    "container",
                    "exec",
                    worker["id"],
                    "python",
                    "-c",
                    "from shadai.workers.probe import read_probe; import os,signal; "
                    "v,_=read_probe('ingest'); os.kill(v['pid'],signal.SIGCONT)",
                )
                self.change("stop", {"probe-ingest-peer"})
            finally:
                self.docker.deadline = budget_deadline
        witness = self.run_owned(["-m", "shadai.qualification.probe_witness"])
        suspended = self.helper_result(witness)
        self.record(
            "probes",
            dependency_outage_liveness=True,
            readiness_false_on_outage=True,
            restart_count_unchanged=True,
            sigstop_stale_not_masked_by_peer=True,
            suspended_async_io=suspended,
        )

    def experiment_physical(self, url):
        from shadai.qualification.physical import host_exporter_proof

        metrics = self.inspector("physical")
        records = self.containers(STORES | WRITERS)
        for record in records:
            verify_resource(record, self.docker.inspect("container", record["id"]))
        stats = self.docker.call("stats", "--no-stream", "--format", "{{json .}}", *(item["id"] for item in records))
        rows = [json.loads(line) for line in stats.splitlines()]
        assert len(rows) == len(records)
        volumes = []
        for service in sorted(STORES):
            volume = self.volume(service)
            helper = self.run_owned(
                [
                    "-c",
                    "import os,json; s=os.statvfs('/volume'); "
                    "print(json.dumps({'size_bytes':s.f_blocks*s.f_frsize,'available_bytes':s.f_bavail*s.f_frsize,"
                    "'filesystem_id':s.f_fsid,'provenance':'statvfs owned volume mount'}))",
                ],
                volumes=[(volume, "/volume", True)],
                root=True,
                caps=["DAC_READ_SEARCH"],
            )
            volumes.append({"store": service, "volume_id": volume["id"], **self.helper_result(helper)})
        try:
            self.compose("up", "-d", "node-exporter")
        finally:
            self.discover()
        exporter = self.containers({"node-exporter"})[0]
        verify_resource(exporter, self.docker.inspect("container", exporter["id"]))
        deadline = self.local_deadline(30)
        while True:
            try:
                physical = host_exporter_proof(
                    self.context, self.journal.value["projects"]["source"], exporter["id"], deadline=deadline
                )
                break
            except QualificationError:
                if time.monotonic() >= deadline:
                    raise
                self.sleep(min(1, max(0, deadline - time.monotonic())))
        self.record(
            "physical",
            redis_and_filesystem=metrics,
            containers=rows,
            owned_volumes=volumes,
            host_exporter=physical,
            provenance="Docker stats memory usage/cache policy, not application RSS",
            filesystem_sum=False,
        )

    def clean(self, *, execute=False, remove_volumes=False):
        planned = sorted(
            self.journal.value["resources"], key=lambda item: {"container": 0, "network": 1, "volume": 2}[item["kind"]]
        )
        if not execute:
            return {
                "schema": 1,
                "execute": False,
                "resources": [item for item in planned if item["kind"] != "volume" or remove_volumes],
                "remove_volumes": remove_volumes,
            }
        for record in planned:
            if record["kind"] == "container":
                inspected = self.docker.inspect("container", record["id"], absent=True)
                if inspected is not None:
                    verify_resource(record, inspected)
                    if inspected["State"]["Running"]:
                        self.docker.call("container", "stop", record["id"])
            self.remove(record, volumes=remove_volumes)
        self.journal.phase("cleaned")
        return {"schema": 1, "cleaned": True, "volumes_removed": remove_volumes}
