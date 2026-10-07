"""Source-backed Docker inspection controls; real native version collection is mandatory CI."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


OBSERVER = load(ROOT / "scripts/observe-clickhouse-version.py", "clickhouse_version_observer")
PRINCIPAL = load(ROOT / "scripts/component_principal.py", "clickhouse_principal_validator")
CAPTURE = json.loads((ROOT / "tests/fixtures/component-scanner/clickhouse-current-amd64.json").read_bytes())
CID = "b" * 64
CONFIG = CAPTURE["config"]
SUBJECT = {"archive_sha256": CAPTURE["capture"]["archive_sha256"],
           "image_manifest": CAPTURE["capture"]["image_manifest"],
           "image_config": CAPTURE["capture"]["image_config"], "platform": "linux/amd64"}


class DockerModel:
    """Only Docker transport is modeled; all guards run against literal inspection shapes."""

    def __init__(self):
        self.calls = []
        self.exists = False
        self.record = None
        self.mutate = None
        self.image_mutate = None
        self.endpoint = "unix:///var/run/docker.sock"
        self.start_error = None
        self.create_error = None
        self.rm_error = None
        self.post_remove_exists = False
        self.start_stdout = PRINCIPAL.STDOUT
        self.start_stderr = b""
        self.start_code = 0
        self.create_reply = (CID + "\n").encode()

    def run(self, command, **kwargs):
        assert command[:3] == ["docker", "--context", "default"]
        self.calls.append((command[3:], kwargs))
        args = command[3:]
        if args[:2] == ["context", "inspect"]:
            value = self.endpoint
        elif args[:2] == ["image", "inspect"]:
            assert args[-1] == SUBJECT["image_config"]
            value = {"Id": SUBJECT["image_config"], "Os": "linux", "Architecture": "amd64",
                     "RootFS": {"Type": "layers", "Layers": CONFIG["rootfs"]["diff_ids"]}}
            if self.image_mutate:
                self.image_mutate(value)
        elif args[:2] == ["container", "ls"]:
            return 0, (CID + "\n").encode() if self.exists or self.post_remove_exists else b"", b""
        elif args[0] == "create":
            required = {"--pull=never", "--network=none", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=512m", "--memory-swap=512m",
                "--cpus=1", "--ipc=none", "--entrypoint=/usr/bin/clickhouse"}
            assert required <= set(args) and not any(part in args for part in ("--publish", "--privileged", "--mount"))
            assert args[-3:] == [SUBJECT["image_config"], "server", "--version"]
            assert args[args.index("--tmpfs") + 1] == "/var/lib/clickhouse:" + OBSERVER.TMPFS
            name, nonce = args[args.index("--name") + 1], args[args.index("--label") + 1].split("=", 1)[1]
            self.record = {"Id": CID, "Name": "/" + name, "Image": SUBJECT["image_config"], "Nonce": nonce,
                "Path": "/usr/bin/clickhouse", "Args": ["server", "--version"], "User": "65534:65534",
                "Env": copy.deepcopy(CONFIG["config"]["Env"]),
                "Entrypoint": ["/usr/bin/clickhouse"], "Cmd": ["server", "--version"],
                "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"], "PidsLimit": 32, "Memory": 536870912,
                    "MemorySwap": 536870912, "NanoCpus": 1000000000, "IpcMode": "none", "Privileged": False,
                    "Binds": None, "PortBindings": {}, "AutoRemove": False,
                    "Tmpfs": {"/var/lib/clickhouse":
                        "rw,nosuid,nodev,noexec,size=1048576,uid=65534,gid=65534,mode=0700"}},
                "Mounts": [], "State": {"Status": "created", "Running": False, "ExitCode": 0,
                                         "OOMKilled": False, "Error": ""}}
            self.exists = True
            if self.create_error:
                raise self.create_error
            return 0, self.create_reply, b""
        elif args[:2] == ["container", "inspect"]:
            assert args[-1] == CID
            value = copy.deepcopy(self.record)
            if self.mutate:
                self.mutate(value)
        elif args[0] == "start":
            assert args == ["start", "--attach", CID] and kwargs["limit"] == 256 and kwargs["timeout"] == 20
            self.record["State"]["Status"] = "exited"
            if self.start_error:
                raise self.start_error
            return self.start_code, self.start_stdout, self.start_stderr
        elif args[0] == "rm":
            assert args == ["rm", "--force", CID]
            if self.rm_error:
                raise self.rm_error
            self.exists = False
            return 0, (CID + "\n").encode(), b""
        else:
            raise AssertionError("Unexpected Docker transport command")
        return 0, json.dumps(value).encode(), b""


def observer(model):
    return OBSERVER.Observer(subject=SUBJECT, config=CONFIG, deadline=time.monotonic() + 110, client=model.run)


def test_exact_source_backed_docker_inspection_runs_once_and_disposes_verified_id():
    model = DockerModel()
    value = observer(model)
    value.collect()
    value.cleanup()
    assert value.removed is True and model.exists is False
    assert sum(args[0] == "create" for args, _ in model.calls) == 1
    assert sum(args[0] == "start" for args, _ in model.calls) == 1
    assert sum(args[0] == "rm" for args, _ in model.calls) == 1
    assert all(args[-1] == CID for args, _ in model.calls if args[:2] == ["container", "inspect"])


@pytest.mark.parametrize("key", ["Id", "Name", "Image", "Nonce", "Path", "Args", "User", "Entrypoint", "Cmd"])
def test_foreign_or_changed_identity_is_refused_before_start_and_never_removed(key):
    model = DockerModel()
    model.mutate = lambda record: record.update({key: "foreign"})
    value = observer(model)
    with pytest.raises(OBSERVER.ObservationError):
        value.collect()
    with pytest.raises(OBSERVER.ObservationError):
        value.cleanup()
    assert not any(args[0] in {"start", "rm"} for args, _ in model.calls)
    assert model.exists is True


@pytest.mark.parametrize("mutation", ["proxy", "token", "extra", "duplicate", "missing", "reordered", "type"])
def test_created_environment_must_equal_selected_image_before_start_and_cleanup(mutation):
    model = DockerModel()
    def change(record):
        if mutation in {"proxy", "token", "extra"}:
            record["Env"].append({"proxy": "HTTP_PROXY=caller", "token": "TOKEN=caller",
                                  "extra": "EXTRA=caller"}[mutation])
        elif mutation == "duplicate":
            record["Env"].append(record["Env"][0])
        elif mutation == "missing":
            record.pop("Env")
        elif mutation == "reordered":
            record["Env"].reverse()
        else:
            record["Env"] = {"PATH": "caller"}
    model.mutate = change
    value = observer(model)
    with pytest.raises(OBSERVER.ObservationError, match="container_controls"):
        value.collect()
    with pytest.raises(OBSERVER.ObservationError, match="container_controls"):
        value.cleanup()
    assert not any(args[0] in {"start", "rm"} for args, _ in model.calls)


@pytest.mark.parametrize("key", ["NetworkMode", "ReadonlyRootfs", "CapDrop", "SecurityOpt", "PidsLimit", "Memory",
    "MemorySwap", "NanoCpus", "IpcMode", "Privileged", "Binds", "PortBindings", "AutoRemove", "Tmpfs"])
def test_every_host_control_refuses_drift_without_deleting_changed_resource(key):
    model = DockerModel()
    def mutate(record):
        record["HostConfig"][key] = "foreign"
    model.mutate = mutate
    value = observer(model)
    with pytest.raises(OBSERVER.ObservationError):
        value.collect()
    with pytest.raises(OBSERVER.ObservationError):
        value.cleanup()
    assert not any(args[0] in {"start", "rm"} for args, _ in model.calls)


@pytest.mark.parametrize("mounts", [[{"Type": "bind"}], [{"Type": "volume"}], [{"Type": "tmpfs"}], None])
def test_tmpfs_host_config_never_excuses_any_bind_volume_or_mount_descriptor(mounts):
    model = DockerModel()
    model.mutate = lambda record: record.update({"Mounts": mounts})
    value = observer(model)
    with pytest.raises(OBSERVER.ObservationError):
        value.collect()
    assert not any(args[0] == "start" for args, _ in model.calls)


@pytest.mark.parametrize("mutation", ["extra", "path", "size", "readonly"])
def test_tmpfs_requires_only_exact_bounded_path_and_options(mutation):
    model = DockerModel()
    def mutate(record):
        tmpfs = record["HostConfig"]["Tmpfs"]
        if mutation == "extra":
            tmpfs["/foreign"] = "rw"
        elif mutation == "path":
            tmpfs["/foreign"] = tmpfs.pop("/var/lib/clickhouse")
        else:
            tmpfs["/var/lib/clickhouse"] = tmpfs["/var/lib/clickhouse"].replace(
                "1048576" if mutation == "size" else "rw", "2097152" if mutation == "size" else "ro")
    model.mutate = mutate
    with pytest.raises(OBSERVER.ObservationError):
        observer(model).collect()


@pytest.mark.parametrize("mutation", ["id", "platform", "rootfs", "remote", "volume", "collision"])
def test_loaded_image_daemon_and_precreate_identity_refusals_never_create(mutation):
    model = DockerModel()
    value = observer(model)
    if mutation in {"id", "platform", "rootfs"}:
        def change(image):
            if mutation == "id":
                image["Id"] = "sha256:" + "0" * 64
            elif mutation == "platform":
                image["Architecture"] = "arm64"
            else:
                image["RootFS"]["Layers"] = []
        model.image_mutate = change
    elif mutation == "remote":
        model.endpoint = "tcp://foreign:2376"
    elif mutation == "volume":
        value.config = copy.deepcopy(CONFIG)
        value.config["config"]["Volumes"]["/foreign"] = {}
    else:
        model.exists = True
    with pytest.raises(OBSERVER.ObservationError):
        value.collect()
    value.cleanup()
    assert not any(args[0] in {"create", "start", "rm"} for args, _ in model.calls)


@pytest.mark.parametrize("mutation", ["stdout", "stderr", "exit", "state-exit", "oom", "state-error", "running"])
def test_cli_output_and_exit_state_must_be_exact_and_valid_owned_failures_still_clean(mutation):
    model = DockerModel()
    if mutation == "stdout":
        model.start_stdout = PRINCIPAL.STDOUT.rstrip(b"\n")
    elif mutation == "stderr":
        model.start_stderr = b"private diagnostic never published"
    elif mutation == "exit":
        model.start_code = 1
    else:
        def change(record):
            if record["State"]["Status"] == "exited":
                key = {"state-exit": "ExitCode", "oom": "OOMKilled", "state-error": "Error",
                       "running": "Running"}[mutation]
                record["State"][key] = "private" if key == "Error" else 1 if key == "ExitCode" else True
        model.mutate = change
    value = observer(model)
    with pytest.raises(OBSERVER.ObservationError):
        value.collect()
    value.cleanup()
    assert not model.exists and value.removed


@pytest.mark.parametrize("error", [TimeoutError("private exception"), KeyboardInterrupt()])
def test_lost_create_or_start_primary_has_owned_immutable_cleanup_and_reserved_budget(error):
    model = DockerModel()
    model.create_error = error
    value = observer(model)
    with pytest.raises(type(error)) as raised:
        value.collect()
    assert raised.value is error
    value.deadline = time.monotonic() - 1
    value.cleanup()
    assert value.removed and not model.exists
    assert all(options["deadline"] > time.monotonic() - 1 for args, options in model.calls if args[0] == "rm")


def test_cleanup_rechecks_name_and_image_after_valid_execution_and_preserves_foreign_drift():
    model = DockerModel()
    value = observer(model)
    value.collect()
    model.mutate = lambda record: record.update({"Name": "/foreign"})
    with pytest.raises(OBSERVER.ObservationError):
        value.cleanup()
    assert model.exists and not value.removed and not any(args[0] == "rm" for args, _ in model.calls)


@pytest.mark.parametrize("kind", ["remove", "absence"])
def test_removal_or_absence_failure_never_claims_successful_cleanup(kind):
    model = DockerModel()
    value = observer(model)
    value.collect()
    if kind == "remove":
        model.rm_error = OBSERVER.ObservationError("docker_nonzero_or_stderr")
    else:
        model.post_remove_exists = True
    with pytest.raises(OBSERVER.ObservationError):
        value.cleanup()
    assert not value.removed


@pytest.fixture
def integrated(tmp_path, monkeypatch):
    # The native-platform boundary is modeled on Windows; production refuses
    # Windows before any POSIX owner check or Docker action.
    if os.name == "nt":
        monkeypatch.setattr(OBSERVER.os, "getuid", lambda: tmp_path.stat().st_uid, raising=False)
        # POSIX anchored publication/deletion are verified by mandatory Linux
        # tests; the Windows full-collector fixture models those boundaries.
        monkeypatch.setattr(OBSERVER, "clear_stale_receipt", lambda path: path.unlink(missing_ok=True))
    root = tmp_path / "source"
    for directory in ("requirements", "scripts", "deploy/service-builds"):
        shutil.copytree(ROOT / directory, root / directory)
    (root / ".github/workflows").mkdir(parents=True)
    shutil.copy2(ROOT / ".github/workflows/ci.yml", root / ".github/workflows/ci.yml")
    shutil.copy2(ROOT / ".dockerignore", root / ".dockerignore")
    output = root / "artifacts/image-audit/clickhouse.principal-observation.json"
    output.parent.mkdir(parents=True)
    archive = root / "artifacts/runtime.oci.tar"
    archive.write_bytes(b"explicit mocked immutable OCI transport boundary")
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    model = DockerModel()
    state = SimpleNamespace(model=model, root=root, output=output, archive=archive, layout_cleanup_error=None,
                            post_layout_drift=False, source_drift=False, published=[], clients=[], events=[])
    # SYNTHETIC current recipe/source graph for the modeled OCI transport.
    # Historical native capture bytes and their original claims remain untouched.
    current = copy.deepcopy(CAPTURE)
    recipe = (root / "deploy/service-builds/Dockerfile.clickhouse").read_bytes()
    binding = load(root / "scripts/component_source.py", "synthetic_clickhouse_fixture_source")
    predicate = current["provenance"][0]["statement"]["predicate"]
    predicate["runDetails"]["metadata"]["buildkit_metadata"]["source"]["infos"][0]["data"] = \
        base64.b64encode(recipe).decode()
    predicate["buildDefinition"]["internalParameters"]["buildConfig"]["llbDefinition"] = \
        binding.expected_clickhouse_graph(recipe, "linux/amd64")
    monkeypatch.setattr(OBSERVER, "ROOT", root)
    monkeypatch.setattr(OBSERVER, "native_platform", lambda: "linux/amd64")
    # Only the host-specific filesystem/syscall boundary is modeled here;
    # dedicated publication tests exercise its real guards and Linux commit.
    monkeypatch.setattr(OBSERVER, "publication_functions", lambda: (None, None))
    monkeypatch.setattr(OBSERVER, "secure_namespace", lambda *args: None)
    monkeypatch.setenv("GITHUB_RUN_ID", "37537893022")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_JOB", "derived-service-builds")

    def client(command, **kwargs):
        state.clients.append(command)
        if command[0] == "git":
            return 0, (current["capture"]["merge"] + "\n").encode() if command[1] == "rev-parse" else b"", b""
        return model.run(command, **kwargs)
    monkeypatch.setattr(OBSERVER, "run", client)

    @contextmanager
    def prepared_layout(*args, **kwargs):
        state.events.append("layout-enter")
        def unchanged():
            state.events.append("layout-check")
            if state.post_layout_drift:
                raise ValueError("synthetic OCI drift")
            if state.source_drift:
                (root / "scripts/component_principal.py").write_bytes(b"changed")
            return {}
        try:
            yield SimpleNamespace(evidence={"archive_sha256": archive_hash,
                "image_manifests": [current["capture"]["image_manifest"].removeprefix("sha256:")],
                "image_configs": {current["capture"]["image_manifest"].removeprefix("sha256:"):
                                  SUBJECT["image_config"]}},
                assert_unchanged=unchanged)
        finally:
            state.events.append("layout-cleanup")
            if state.layout_cleanup_error:
                raise state.layout_cleanup_error
    original = OBSERVER.script

    def script(name):
        if name == "oci_scan_layout":
            return SimpleNamespace(prepared_layout=prepared_layout)
        value = original(name)
        if name == "component_source":
            value.subject_documents = lambda *args: {"manifest": current["manifest"], "config": current["config"],
                                                     "provenance": current["provenance"][0]}
        return value
    monkeypatch.setattr(OBSERVER, "script", script)
    monkeypatch.setattr(OBSERVER, "archive_sha", lambda *args: hashlib.sha256(archive.read_bytes()).hexdigest())

    def publish(path, data, **kwargs):
        assert not model.exists and state.events[-1] == "layout-cleanup"
        state.events.append("publish-precommit")
        kwargs["precommit"]()
        state.events.append("publish")
        state.published.append(data)
        path.write_bytes(data)
    monkeypatch.setattr(OBSERVER, "atomic_receipt", publish)
    state.args = SimpleNamespace(input=archive, platform="linux/amd64", source_commit=current["capture"]["merge"],
                                 repository="alebgl77/open-shadow-ai", output=output)
    return state


def test_full_collector_publishes_bound_receipt_only_after_both_owned_cleanups(integrated):
    receipt = OBSERVER.collect(integrated.args)
    assert json.loads(integrated.output.read_bytes()) == receipt
    assert receipt["subject"]["archive_sha256"] == hashlib.sha256(integrated.archive.read_bytes()).hexdigest()
    assert receipt["authentication"] == {"builder_provenance": "unverified", "publisher_signature": "unverified"}
    assert receipt["cleanup"] == {"container_removed": True, "absence_verified": True}
    assert integrated.events == ["layout-enter", "layout-check", "layout-cleanup", "publish-precommit", "publish"]
    assert sum(args[0] == "rm" for args, _ in integrated.model.calls) == 1
    assert integrated.model.calls[-1][0][:2] == ["container", "ls"]


@pytest.mark.parametrize("kind", [
    "container-cleanup", "layout-cleanup", "layout-drift", "source-drift", "output", "ci"])
def test_full_collector_refusal_never_leaves_stale_or_new_receipt(integrated, kind, monkeypatch):
    integrated.output.write_text('{"status":"old"}')
    if kind == "container-cleanup":
        integrated.model.rm_error = OBSERVER.ObservationError("docker_nonzero_or_stderr")
    elif kind == "layout-cleanup":
        integrated.layout_cleanup_error = ValueError("owned_cleanup_failed")
    elif kind == "layout-drift":
        integrated.post_layout_drift = True
    elif kind == "source-drift":
        integrated.source_drift = True
    elif kind == "output":
        integrated.model.start_stdout = b"wrong version"
    else:
        monkeypatch.setenv("GITHUB_RUN_ID", "0")
    reason = {"container-cleanup": "owned_cleanup_failed", "layout-cleanup": "owned_cleanup_failed",
              "layout-drift": "synthetic OCI drift", "source-drift": "source_or_archive_drift",
              "output": "cli_version_output", "ci": "Principal observation requires current numeric CI identity"}
    with pytest.raises(ValueError, match="^" + reason[kind] + "$") as raised:
        OBSERVER.collect(integrated.args)
    assert integrated.published == []
    # Invalid CI preflight is before any owned stale-file deletion; it must not
    # create a new receipt. Other refusals clear a previously owned stale receipt.
    assert integrated.output.exists() is (kind == "ci")
    if kind == "ci":
        assert not integrated.clients and not integrated.events and not integrated.model.calls
    else:
        assert type(raised.value) is (ValueError if kind in {"layout-cleanup", "layout-drift"}
                                      else OBSERVER.ObservationError)
        assert sum(args[0] == "create" for args, _ in integrated.model.calls) == 1
        assert sum(args[0] == "start" for args, _ in integrated.model.calls) == 1
        assert sum(args[0] == "rm" for args, _ in integrated.model.calls) == 1
        assert integrated.model.exists is (kind == "container-cleanup")
        assert integrated.events[:1] == ["layout-enter"] and "layout-cleanup" in integrated.events
        assert ("layout-check" in integrated.events) is (kind in {"layout-cleanup", "layout-drift", "source-drift"})
        assert ("publish-precommit" in integrated.events) is (kind == "source-drift")
        if kind == "layout-cleanup":
            assert raised.value is integrated.layout_cleanup_error


def test_primary_and_cancel_survive_secondary_container_cleanup_refusal(integrated):
    primary = KeyboardInterrupt()
    integrated.model.start_error = primary
    integrated.model.rm_error = OBSERVER.ObservationError("docker_nonzero_or_stderr")
    with pytest.raises(KeyboardInterrupt) as raised:
        OBSERVER.collect(integrated.args)
    assert raised.value is primary and raised.value.__notes__ == ["owned_cleanup_failed"]
    assert integrated.published == [] and not integrated.output.exists()
    assert integrated.model.exists and integrated.model.calls[-1][0] == ["rm", "--force", CID]
    assert integrated.events == ["layout-enter", "layout-cleanup"]


@pytest.mark.parametrize("kind", ["code", "note"])
def test_process_ownership_refusal_latches_and_container_cleanup_never_launches_another_client(kind):
    model = DockerModel()
    primary = OBSERVER.ObservationError("owned_cleanup_failed") if kind == "code" else KeyboardInterrupt()
    if kind == "note":
        primary.add_note("owned_cleanup_failed")
    model.start_error = primary
    value = observer(model)
    with pytest.raises(type(primary)) as raised:
        value.collect()
    assert raised.value is primary and value.process_refused
    count = len(model.calls)
    with pytest.raises(OBSERVER.ObservationError, match="owned_cleanup_failed"):
        value.cleanup()
    with pytest.raises(OBSERVER.ObservationError, match="owned_cleanup_failed"):
        value.ids()
    assert len(model.calls) == count and model.exists and not value.removed


def test_full_collector_lifecycle_refusal_aborts_with_no_new_clients_or_receipt(integrated):
    primary = KeyboardInterrupt()
    primary.add_note("owned_cleanup_failed")
    integrated.model.start_error = primary
    with pytest.raises(KeyboardInterrupt) as raised:
        OBSERVER.collect(integrated.args)
    assert raised.value is primary and raised.value.__notes__ == ["owned_cleanup_failed"]
    assert integrated.model.calls[-1][0] == ["start", "--attach", CID]
    assert integrated.clients[-1] == ["docker", "--context", "default", "start", "--attach", CID]
    assert integrated.model.exists and integrated.events == ["layout-enter", "layout-cleanup"]
    assert not integrated.published and not integrated.output.exists()


def test_other_client_failures_and_nonexact_notes_preserve_owned_container_cleanup():
    model = DockerModel()
    primary = TimeoutError("deadline")
    primary.add_note("owned_cleanup_failed-extra")
    model.start_error = primary
    value = observer(model)
    with pytest.raises(TimeoutError) as raised:
        value.collect()
    assert raised.value is primary and not value.process_refused
    value.cleanup()
    assert value.removed and not model.exists


def test_clean_child_environment_drops_caller_tokens_proxies_and_docker_options(monkeypatch):
    for key in ("GH_TOKEN", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "HTTPS_PROXY", "GRYPE_DB_CACHE_DIR",
                "SYFT_EXCLUDE"):
        monkeypatch.setenv(key, "private-caller-value")
    child = OBSERVER.environment()
    assert not any(key in child for key in ("GH_TOKEN", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "HTTPS_PROXY",
                                           "GRYPE_DB_CACHE_DIR", "SYFT_EXCLUDE"))


@pytest.mark.parametrize("program,limit,timeout,reason", [
    ("import sys;sys.stdout.buffer.write(b'x'*257)", 256, 5, "output_budget"),
    ("import sys;sys.stderr.buffer.write(b'x'*257)", 256, 5, "output_budget"),
    ("import threading;threading.Event().wait(10)", 256, 0.1, "deadline"),
])
def test_real_bounded_client_caps_both_streams_and_reaps_timeout(program, limit, timeout, reason):
    with pytest.raises(OBSERVER.ObservationError, match=reason):
        OBSERVER.run([sys.executable, "-I", "-c", program], deadline=time.monotonic() + 5, limit=limit, timeout=timeout)


def test_real_client_preserves_exact_binary_stdout_and_stderr():
    code, stdout, stderr = OBSERVER.run([sys.executable, "-I", "-c",
        "import sys;sys.stdout.buffer.write(b'out\\r\\n\\x1a');sys.stderr.buffer.write(b'err')"],
        deadline=time.monotonic() + 5, limit=256)
    assert (code, stdout, stderr) == (0, b"out\r\n\x1a", b"err")


@pytest.mark.parametrize("phase", ["constructor", "start", "started-then-interrupt", "completed-then-interrupt"])
def test_reader_start_failure_aborts_invocation_and_never_parent_closes_transferred_lease(monkeypatch, phase):
    lifecycle = load(ROOT / "scripts/grype_runtime.py", "observer_shared_start_controls")
    original_script, original_thread = OBSERVER.script, OBSERVER.threading.Thread
    leases, children = [], []
    class Lease(lifecycle.ReaderDescriptors):
        def __init__(self, *args):
            super().__init__(*args)
            self.closed_by = []
            leases.append(self)
        def close(self):
            if self.transferred:
                self.closed_by.append(OBSERVER.threading.current_thread())
            return super().close()
    class Child(lifecycle.OwnedPopen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            children.append(self)
    class Reader(original_thread):
        def __init__(self, *args, **kwargs):
            if phase == "constructor":
                raise RuntimeError("fixed constructor control")
            super().__init__(*args, **kwargs)
        def start(self):
            if phase in {"started-then-interrupt", "completed-then-interrupt"}:
                super().start()
                if phase == "completed-then-interrupt":
                    self.join(2)
                    assert not self.is_alive()
                raise KeyboardInterrupt()
            raise RuntimeError("fixed start control")
    lifecycle.ReaderDescriptors, lifecycle.OwnedPopen = Lease, Child
    monkeypatch.setattr(OBSERVER, "script", lambda name:
                        lifecycle if name == "grype_runtime" else original_script(name))
    monkeypatch.setattr(OBSERVER.threading, "Thread", Reader)
    with pytest.raises(KeyboardInterrupt if phase.endswith("interrupt") else RuntimeError) as raised:
        program = "pass" if phase == "completed-then-interrupt" else "import threading;threading.Event().wait(10)"
        OBSERVER.run([sys.executable, "-I", "-c", program],
            deadline=time.monotonic() + 5, limit=256)
    assert children[0].returncode is not None
    assert all(owner is not OBSERVER.threading.current_thread() for lease in leases for owner in lease.closed_by)
    if phase == "constructor":
        assert all(lease.read_fd is None and not lease.transferred for lease in leases)
    else:
        assert raised.value.__notes__ == ["owned_cleanup_failed"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX WNOWAIT ownership and descendants required in native Linux CI")
def test_real_unreaped_leader_group_is_killed_before_wait_and_descendant_cannot_hold_pipe(tmp_path, monkeypatch):
    events = []
    real_waitid, real_killpg = OBSERVER.os.waitid, OBSERVER.os.killpg
    def peek(*args):
        events.append("peek")
        return real_waitid(*args)
    def kill(pid, signum):
        events.append("kill")
        assert signum == signal.SIGKILL
        return real_killpg(pid, signum)
    monkeypatch.setattr(OBSERVER.os, "waitid", peek)
    monkeypatch.setattr(OBSERVER.os, "killpg", kill)
    program = "import os,threading;pid=os.fork();threading.Event().wait(10) if pid==0 else None"
    with pytest.raises(OBSERVER.ObservationError, match="deadline"):
        OBSERVER.run([sys.executable, "-I", "-c", program], deadline=time.monotonic() + 5, limit=256, timeout=0.1)
    assert events[-2:] == ["peek", "kill"]


@pytest.fixture
def publication_directory():
    home = Path.home()
    OBSERVER.secure_namespace(home)
    directory = Path(tempfile.mkdtemp(prefix="shadai-receipt-qa-", dir=home))
    try:
        yield directory
    finally:
        assert directory.parent == home and directory.name.startswith("shadai-receipt-qa-")
        shutil.rmtree(directory)


@pytest.mark.skipif(os.name != "posix", reason="POSIX exclusive atomic publication required in native Linux CI")
def test_atomic_receipt_partial_writes_are_completed_and_collision_is_preserved(publication_directory, monkeypatch):
    tmp_path = publication_directory
    output = tmp_path / "clickhouse.principal-observation.json"
    original = OBSERVER.os.write
    monkeypatch.setattr(OBSERVER.os, "write", lambda fd, data: original(fd, data[:3]))
    OBSERVER.atomic_receipt(output, b"all-reviewed-bytes\n")
    assert output.read_bytes() == b"all-reviewed-bytes\n" and output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(OBSERVER.ObservationError, match="publication_refused"):
        OBSERVER.atomic_receipt(output, b"replacement")
    assert output.read_bytes() == b"all-reviewed-bytes\n"
    assert len(list(tmp_path.glob("*.pending"))) == 1


@pytest.mark.skipif(os.name != "posix", reason="Real POSIX ownership refusal with open writer required in Linux CI")
def test_lost_process_ownership_stops_both_readers_without_numeric_signal_reap_or_finalizer(monkeypatch):
    lifecycle = load(ROOT / "scripts/grype_runtime.py", "observer_shared_ownership_refusal")
    original_script = OBSERVER.script
    real_waitid, real_killpg, real_waitpid = os.waitid, os.killpg, os.waitpid
    children, events = [], []
    class Child(lifecycle.OwnedPopen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            children.append(self)
        def wait(self, *args, **kwargs):
            events.append("wait")
            return super().wait(*args, **kwargs)
        def poll(self):
            events.append("poll")
            return super().poll()
        def _internal_poll(self, *args, **kwargs):
            events.append("finalizer-poll")
            return super()._internal_poll(*args, **kwargs)
    lifecycle.OwnedPopen = Child
    def ownership_refusal(*args):
        events.append("peek")
        raise ChildProcessError()
    monkeypatch.setattr(OBSERVER, "script", lambda name:
                        lifecycle if name == "grype_runtime" else original_script(name))
    monkeypatch.setattr(lifecycle.os, "waitid", ownership_refusal)
    monkeypatch.setattr(lifecycle.os, "killpg", lambda *args: events.append("unsafe-signal"))
    started = time.monotonic()
    try:
        with pytest.raises(lifecycle.GrypeRuntimeError, match="owned_cleanup_failed") as raised:
            OBSERVER.run([sys.executable, "-I", "-c", "import threading;threading.Event().wait(10)"],
                deadline=time.monotonic() + 5, limit=256)
        child = children[0]
        assert child._ownership_abandoned and child.returncode is None
        child.__del__()
        assert events == ["peek"] and raised.value.__notes__ == ["owned_cleanup_failed"]
        assert time.monotonic() - started < 3
    finally:
        # This test fixture independently proves its still-owned real child;
        # the collector never restores or invents ownership after refusal.
        child = children[0]
        status = real_waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert status is None or status.si_pid == child.pid
        real_killpg(child.pid, signal.SIGKILL)
        real_waitpid(child.pid, 0)


@pytest.mark.skipif(os.name != "posix", reason="Start-before-ack and numeric FD reuse required in native Linux CI")
def test_ambiguous_thread_start_preserves_private_lease_when_original_fd_is_reused(tmp_path, monkeypatch):
    lifecycle = load(ROOT / "scripts/grype_runtime.py", "observer_shared_late_reader")
    original_script, original_thread = OBSERVER.script, OBSERVER.threading.Thread
    gate, target_live = OBSERVER.threading.Event(), OBSERVER.threading.Event()
    readers, leases, borrowed = [], [], []
    class Lease(lifecycle.ReaderDescriptors):
        def __init__(self, source_fd, *args):
            borrowed.append(source_fd)
            super().__init__(source_fd, *args)
            leases.append(self)
    class Reader(original_thread):
        def __init__(self, *, target, args, **kwargs):
            def delayed():
                target_live.set()
                gate.wait(5)
                target(*args)
            super().__init__(target=delayed, **kwargs)
            readers.append(self)
        def start(self):
            super().start()
            assert target_live.wait(2)
            raise KeyboardInterrupt()
        @property
        def ident(self):
            return None  # Missing acknowledgment never authorizes parent FD disposal.
    lifecycle.ReaderDescriptors = Lease
    monkeypatch.setattr(OBSERVER, "script", lambda name:
                        lifecycle if name == "grype_runtime" else original_script(name))
    monkeypatch.setattr(OBSERVER.threading, "Thread", Reader)
    replacement = None
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            OBSERVER.run([sys.executable, "-I", "-c", "import threading;threading.Event().wait(10)"],
                deadline=time.monotonic() + 5, limit=256)
        assert raised.value.__notes__ == ["owned_cleanup_failed"]
        assert leases[0].transferred and leases[0].read_fd is not None
        foreign = tmp_path / "foreign"
        foreign.write_bytes(b"foreign-owned-byte-control")
        opened = os.open(foreign, os.O_RDONLY)
        replacement = borrowed[0]
        if opened != replacement:
            os.dup2(opened, replacement)
            os.close(opened)
        gate.set()
        for reader in readers:
            reader.join(2)
            assert not reader.is_alive()
        assert leases[0].read_fd is None
        assert os.read(replacement, 128) == b"foreign-owned-byte-control"
    finally:
        gate.set()
        for reader in readers:
            reader.join(2)
        if replacement is not None:
            os.close(replacement)


@pytest.mark.skipif(os.name != "posix", reason="POSIX receipt fsync failure and owned rollback required in Linux CI")
@pytest.mark.parametrize("phase", ["write", "file-fsync", "directory-fsync"])
def test_receipt_write_or_fsync_failure_cannot_publish_accepted_bytes(publication_directory, monkeypatch, phase):
    tmp_path = publication_directory
    output = tmp_path / "clickhouse.principal-observation.json"
    real_fsync = os.fsync
    calls = []
    def refuse(fd):
        calls.append(fd)
        if phase == "file-fsync" and len(calls) == 1 or phase == "directory-fsync" and len(calls) == 2:
            raise OSError("fixed fsync refusal")
        return real_fsync(fd)
    if phase == "write":
        monkeypatch.setattr(OBSERVER.os, "write", lambda *args: 0)
    else:
        monkeypatch.setattr(OBSERVER.os, "fsync", refuse)
    with pytest.raises((OSError, OBSERVER.ObservationError)):
        OBSERVER.atomic_receipt(output, b"candidate")
    assert not output.exists() and list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="Anchored POSIX stale receipt refusal required in native Linux CI")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "parent-symlink"])
def test_stale_cleanup_refuses_foreign_file_or_parent_alias(tmp_path, kind):
    directory = tmp_path / "real"
    directory.mkdir()
    foreign = directory / "foreign"
    foreign.write_bytes(b"foreign-owned-control")
    output = directory / "clickhouse.principal-observation.json"
    if kind == "symlink":
        output.symlink_to(foreign)
    elif kind == "hardlink":
        os.link(foreign, output)
    else:
        output.write_bytes(b"foreign-receipt-control")
        alias = tmp_path / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        output = alias / output.name
    with pytest.raises(OBSERVER.ObservationError, match="receipt_path"):
        OBSERVER.clear_stale_receipt(output)
    assert foreign.read_bytes() == b"foreign-owned-control" and output.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX numeric FD reuse during close refusal required in Linux CI")
def test_atomic_close_refusal_never_retries_a_released_numeric_file_descriptor(publication_directory, monkeypatch):
    tmp_path = publication_directory
    output = tmp_path / "clickhouse.principal-observation.json"
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"foreign-descriptor-control")
    real_open, real_close = os.open, os.close
    owned, replacement, calls = [], [], []
    def opened(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        if flags & os.O_EXCL:
            owned.append(descriptor)
        return descriptor
    def close(descriptor):
        if descriptor in owned:
            calls.append(descriptor)
            real_close(descriptor)
            recycled = real_open(foreign, os.O_RDONLY)
            replacement.append(recycled)
            assert recycled == descriptor
            raise OSError("fixed close refusal")
        return real_close(descriptor)
    monkeypatch.setattr(OBSERVER.os, "open", opened)
    monkeypatch.setattr(OBSERVER.os, "close", close)
    try:
        with pytest.raises(OSError):
            OBSERVER.atomic_receipt(output, b"candidate")
        assert calls == owned and len(calls) == 1 and not output.exists()
        assert os.read(replacement[0], 128) == b"foreign-descriptor-control"
        assert list(tmp_path.iterdir()) == [foreign]
    finally:
        for descriptor in replacement:
            real_close(descriptor)


class ReceiptFileSystem:
    """Model native syscall/namespace races; the commit is the last traced IO."""

    def __init__(self, output, phase="healthy"):
        self.output, self.phase = output.absolute(), phase
        self.files, self.descriptors, self.events = {}, {}, []
        self.sequence, self.first_parent, self.pending = 20, None, None
        self.close_failed, self.syncs = False, 0
        self.primary = OSError("fixed primary refusal")
        self.parents = {p: self.metadata(i + 1, directory=True, uid=0)
                        for i, p in enumerate([*reversed(self.output.parent.parents), self.output.parent])}
        self.parents[self.output.parent].st_uid = 42
        self.api = SimpleNamespace(open=self.open, close=self.close, fstat=self.fstat, stat=self.stat,
            lstat=self.lstat, getuid=lambda: 42, write=self.write, fsync=self.fsync, unlink=self.unlink,
            fsencode=os.fsencode, path=os.path, O_RDONLY=os.O_RDONLY, O_WRONLY=os.O_WRONLY,
            O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL, O_DIRECTORY=0x100000, O_NOFOLLOW=0x200000)

    @staticmethod
    def metadata(inode, *, directory=False, uid=42):
        return SimpleNamespace(st_dev=5, st_ino=inode, st_uid=uid, st_nlink=1, st_size=0,
                               st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o600))

    def event(self, name):
        assert not self.events or self.events[-1] != "commit", "IO after successful commit"
        self.events.append(name)

    def open(self, path, flags, *args, **kwargs):
        self.event("open")
        if isinstance(path, Path):
            if self.close_failed and self.phase == "parent-close-cleanup-refused":
                raise PermissionError("fixed reopen refusal")
            record = self.parents[path]
        else:
            assert flags & os.O_EXCL and path.endswith(".pending")
            self.pending = self.output.with_name(path)
            record = self.metadata(100)
            self.files[self.pending] = (record, bytearray())
        self.sequence += 1
        self.descriptors[self.sequence] = record
        if isinstance(path, Path) and self.first_parent is None:
            self.first_parent = self.sequence
        return self.sequence

    def close(self, descriptor):
        self.event("close:" + str(descriptor))
        record = self.descriptors.pop(descriptor)
        fail = self.phase in {"file-close", "cleanup-cancel"} and stat.S_ISREG(record.st_mode) or \
            self.phase in {"parent-close", "parent-close-cleanup-refused"} and descriptor == self.first_parent
        if fail and not self.close_failed:
            self.close_failed = True
            self.descriptors[descriptor] = self.metadata(999)
            if self.phase == "cleanup-cancel":
                raise KeyboardInterrupt()
            raise self.primary
        if descriptor == self.first_parent and self.phase == "post-close-swap":
            self.parents[self.output.parent] = self.metadata(777, directory=True)

    def fstat(self, descriptor):
        self.event("fstat")
        return self.descriptors[descriptor]

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.event("stat")
        assert follow_symlinks is False and dir_fd in self.descriptors
        return self.lstat(self.output.with_name(name))

    def lstat(self, path):
        self.event("lstat")
        if path in self.parents:
            return self.parents[path]
        if path not in self.files:
            raise FileNotFoundError()
        record = self.files[path][0]
        if self.phase in {"pending-inode", "pending-hardlink", "pending-mode", "pending-owner", "pending-size"}:
            key = {"pending-inode": "st_ino", "pending-hardlink": "st_nlink", "pending-mode": "st_mode",
                   "pending-owner": "st_uid", "pending-size": "st_size"}[self.phase]
            setattr(record, key, 101 if key == "st_ino" else 2 if key == "st_nlink" else
                    stat.S_IFREG | 0o644 if key == "st_mode" else 99 if key == "st_uid" else 999)
        return record

    def write(self, descriptor, data):
        self.event("write")
        if self.phase in {"write", "cleanup-cancel"}:
            raise self.primary
        if self.phase == "cancel":
            raise KeyboardInterrupt()
        record = self.descriptors[descriptor]
        value = next(value for current, value in self.files.values() if current is record)
        value.extend(data)
        record.st_size = len(value)
        return len(data)

    def fsync(self, descriptor):
        self.event("fsync")
        self.syncs += 1
        if self.phase == "file-fsync" and self.syncs == 1 or self.phase == "parent-fsync" and self.syncs == 2:
            raise self.primary

    def unlink(self, name, *, dir_fd):
        self.event("unlink")
        assert dir_fd in self.descriptors
        del self.files[self.output.with_name(name)]

    def rename(self, first, source, second, destination, flags):
        self.event("rename")
        assert (first, second, flags) == (-100, -100, 1)
        assert not self.descriptors, "Owned FD survived until terminal rename"
        assert source == os.fsencode(self.pending) and destination == os.fsencode(self.output)
        if self.phase in {"EEXIST", "ENOSYS", "EINVAL", "EXDEV"}:
            return -1
        self.files[self.output] = self.files.pop(self.pending)
        self.events.append("commit")
        return 0


@pytest.fixture
def terminal_model(tmp_path, monkeypatch):
    def model(phase="healthy"):
        value = ReceiptFileSystem(tmp_path / PRINCIPAL.RECEIPT_NAME, phase)
        monkeypatch.setattr(OBSERVER, "os", value.api)
        monkeypatch.setattr(OBSERVER, "publication_functions", lambda: (value.rename, None))
        monkeypatch.setattr(OBSERVER, "local_filesystem", lambda *args: value.event("local-fs"))
        return value
    return model


def test_terminal_commit_is_last_io_with_all_owned_descriptors_already_closed(terminal_model):
    model = terminal_model()
    OBSERVER.atomic_receipt(model.output, b"verified-candidate", precommit=lambda: model.event("source-cleanup"))
    assert model.events[-2:] == ["rename", "commit"]
    assert bytes(model.files[model.output][1]) == b"verified-candidate" and model.pending not in model.files
    assert model.events.index("source-cleanup") < model.events.index("close:" + str(model.first_parent))


@pytest.mark.parametrize("phase", ["write", "file-fsync", "parent-fsync", "file-close", "parent-close",
                                  "parent-close-cleanup-refused", "cancel", "post-close-swap",
                                  "pending-inode", "pending-hardlink", "pending-mode", "pending-owner", "pending-size",
                                  "cleanup-cancel"])
def test_every_precommit_failure_leaves_no_canonical_even_when_pending_cleanup_refuses(terminal_model, phase):
    model = terminal_model(phase)
    with pytest.raises(KeyboardInterrupt if phase == "cancel" else (OSError, OBSERVER.ObservationError)) as raised:
        OBSERVER.atomic_receipt(model.output, b"verified-candidate")
    assert model.output not in model.files and "rename" not in model.events
    assert all(path.name.endswith(".pending") for path in model.files)
    if phase in {"write", "file-fsync", "parent-fsync", "file-close", "parent-close",
                 "parent-close-cleanup-refused", "cleanup-cancel"}:
        assert raised.value is model.primary
    if model.close_failed:
        assert model.events.count("close:" + str(next(fd for fd, value in model.descriptors.items()
                                                     if value.st_ino == 999))) == 1
        assert "owned_cleanup_failed" in raised.value.__notes__


@pytest.mark.parametrize("phase", ["EEXIST", "ENOSYS", "EINVAL", "EXDEV"])
def test_terminal_syscall_refusal_has_one_attempt_no_fallback_and_preserves_collision(terminal_model, phase):
    model = terminal_model(phase)
    if phase == "EEXIST":
        model.files[model.output] = (model.metadata(123), bytearray(b"foreign-canonical"))
    with pytest.raises(OBSERVER.ObservationError, match="^publication_refused$"):
        OBSERVER.atomic_receipt(model.output, b"verified-candidate")
    assert model.events[-1] == "rename" and model.events.count("rename") == 1
    assert bytes(model.files[model.pending][1]) == b"verified-candidate"
    if phase == "EEXIST":
        assert bytes(model.files[model.output][1]) == b"foreign-canonical"
    else:
        assert model.output not in model.files


@pytest.mark.parametrize("mutation", ["symlink", "owner", "group-write", "world-write", "sticky", "parent-owner"])
def test_namespace_refusal_precedes_any_created_file_or_descriptor(terminal_model, mutation):
    model = terminal_model()
    ancestor = next(path for path in model.parents if path != model.output.parent)
    record = model.parents[model.output.parent if mutation == "parent-owner" else ancestor]
    if mutation == "symlink":
        record.st_mode = stat.S_IFLNK | 0o777
    elif mutation in {"owner", "parent-owner"}:
        record.st_uid = 99 if mutation == "owner" else 0
    else:
        record.st_mode |= {"group-write": 0o020, "world-write": 0o002, "sticky": 0o1000}[mutation]
    with pytest.raises(OBSERVER.ObservationError, match="publication_namespace"):
        OBSERVER.atomic_receipt(model.output, b"verified-candidate")
    assert not model.files and not model.descriptors and "open" not in model.events


@pytest.mark.parametrize("primary", [ValueError("fixed source refusal"), KeyboardInterrupt()])
def test_precommit_source_failure_preserves_primary_when_pending_cleanup_also_refuses(
        terminal_model, monkeypatch, primary):
    model = terminal_model()
    def fail():
        raise primary
    def cleanup(*args):
        raise PermissionError("fixed cleanup refusal")
    monkeypatch.setattr(OBSERVER, "cleanup_pending", cleanup)
    with pytest.raises(type(primary)) as raised:
        OBSERVER.atomic_receipt(model.output, b"verified-candidate", precommit=fail)
    assert raised.value is primary and raised.value.__notes__ == ["owned_cleanup_failed"]
    assert model.output not in model.files and "rename" not in model.events
    assert all(path.name.endswith(".pending") for path in model.files)


def test_expired_precommit_deadline_has_no_canonical(terminal_model):
    model = terminal_model()
    with pytest.raises(OBSERVER.ObservationError, match="^deadline$"):
        OBSERVER.atomic_receipt(model.output, b"verified-candidate", deadline=time.monotonic() - 1)
    assert not model.files and not model.descriptors and "rename" not in model.events


def test_unsupported_terminal_symbol_refuses_before_creating_pending(tmp_path, monkeypatch):
    def unsupported():
        raise OBSERVER.ObservationError("terminal_publication_unsupported")
    with monkeypatch.context() as boundary:
        boundary.setattr(OBSERVER, "sys", SimpleNamespace(platform="linux"))
        boundary.setattr(OBSERVER, "os", SimpleNamespace(name="posix"))
        boundary.setattr(OBSERVER.ctypes, "sizeof", lambda *args: 8)
        boundary.setattr(OBSERVER.host_platform, "machine", lambda: "x86_64")
        boundary.setattr(OBSERVER.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace())
        with pytest.raises(OBSERVER.ObservationError, match="terminal_publication_unsupported"):
            OBSERVER.publication_functions()
    monkeypatch.setattr(OBSERVER, "publication_functions", unsupported)
    with pytest.raises(OBSERVER.ObservationError, match="terminal_publication_unsupported"):
        OBSERVER.atomic_receipt(tmp_path / PRINCIPAL.RECEIPT_NAME, b"candidate")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("magic,code", [(0xEF53, 0), (0x58465342, 0), (0x9123683E, 0), (0x01021994, 0),
                                      (0x794C7630, 0), (0x6969, 0), (0xFF534D42, 0), (123, 0), (0xEF53, -1)])
def test_local_filesystem_requires_closed_magic_and_successful_native_syscall(magic, code, monkeypatch):
    # Windows tests model the explicitly required Linux64 ABI; production
    # refuses its native four-byte long before invoking either syscall.
    if os.name == "nt":
        monkeypatch.setattr(OBSERVER.ctypes, "c_long", OBSERVER.ctypes.c_int64)
    def filesystem(descriptor, result):
        OBSERVER.ctypes.cast(result, OBSERVER.ctypes.POINTER(OBSERVER.ctypes.c_long))[0] = magic
        return code
    if code == 0 and magic in {0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630}:
        OBSERVER.local_filesystem(7, filesystem)
    else:
        with pytest.raises(OBSERVER.ObservationError, match="publication_filesystem"):
            OBSERVER.local_filesystem(7, filesystem)


@pytest.mark.skipif(os.name != "posix", reason="Actual Linux terminal renameat2 and no post-commit IO required in CI")
def test_real_terminal_commit_has_no_io_after_success(publication_directory, monkeypatch):
    output = publication_directory / PRINCIPAL.RECEIPT_NAME
    real_functions, events = OBSERVER.publication_functions(), []
    def commit(*args):
        result = real_functions[0](*args)
        if result == 0:
            events.append("commit")
        return result
    monkeypatch.setattr(OBSERVER, "publication_functions", lambda: (commit, real_functions[1]))
    for name in ("open", "close", "lstat", "fstat", "fsync", "write", "unlink"):
        original = getattr(OBSERVER.os, name)
        def checked(*args, _function=original, _name=name, **kwargs):
            assert not events, "IO after committed receipt"
            return _function(*args, **kwargs)
        monkeypatch.setattr(OBSERVER.os, name, checked)
    OBSERVER.atomic_receipt(output, b"verified-candidate")
    monkeypatch.undo()
    assert events == ["commit"] and output.read_bytes() == b"verified-candidate"


@pytest.mark.skipif(os.name != "posix", reason="Actual precommit directory close refusal and FD reuse required in CI")
@pytest.mark.parametrize("cleanup_refused", [False, True])
def test_real_directory_close_failure_never_publishes_canonical_or_retries_reused_fd(
        publication_directory, monkeypatch, cleanup_refused):
    output, foreign = publication_directory / PRINCIPAL.RECEIPT_NAME, publication_directory / "foreign"
    foreign.write_bytes(b"foreign-directory-fd-control")
    real_open, real_close = os.open, os.close
    initial, replacement, calls = [], [], []
    def opened(path, flags, *args, **kwargs):
        if Path(path) == publication_directory:
            if replacement and cleanup_refused:
                raise PermissionError("fixed reopen refusal")
        descriptor = real_open(path, flags, *args, **kwargs)
        if Path(path) == publication_directory and not initial:
            initial.append(descriptor)
        return descriptor
    def close(descriptor):
        calls.append(descriptor)
        if descriptor == initial[0] and not replacement:
            assert not output.exists() and len(list(publication_directory.glob("*.pending"))) == 1
            real_close(descriptor)
            replacement.append(real_open(foreign, os.O_RDONLY))
            assert replacement[0] == descriptor
            raise OSError("fixed directory close refusal")
        return real_close(descriptor)
    with monkeypatch.context() as boundary:
        boundary.setattr(OBSERVER.os, "open", opened)
        boundary.setattr(OBSERVER.os, "close", close)
        try:
            with pytest.raises(OSError) as raised:
                OBSERVER.atomic_receipt(output, b"verified-candidate")
            assert not output.exists() and calls.count(initial[0]) == 1
            assert "owned_cleanup_failed" in raised.value.__notes__
            assert os.read(replacement[0], 128) == b"foreign-directory-fd-control"
            assert len(list(publication_directory.glob("*.pending"))) == int(cleanup_refused)
        finally:
            for descriptor in replacement:
                real_close(descriptor)
    assert os.open is real_open and os.close is real_close
