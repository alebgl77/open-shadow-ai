"""Collect a bounded native ClickHouse CLI receipt from the same loaded OCI build."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform as host_platform
import re
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
TMPFS = "rw,nosuid,nodev,noexec,size=1048576,uid=65534,gid=65534,mode=0700"
LABEL = "io.shadai.clickhouse-observation"
IMAGE_FORMAT = '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"RootFS":{{json .RootFS}}}'
CONTAINER_FORMAT = (
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"Nonce":{{json (index .Config.Labels "io.shadai.clickhouse-observation")}},'
    '"Path":{{json .Path}},"Args":{{json .Args}},"User":{{json .Config.User}},'
    '"Env":{{json .Config.Env}},'
    '"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}},'
    '"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},"CapDrop":{{json .HostConfig.CapDrop}},'
    '"SecurityOpt":{{json .HostConfig.SecurityOpt}},"PidsLimit":{{json .HostConfig.PidsLimit}},'
    '"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},'
    '"NanoCpus":{{json .HostConfig.NanoCpus}},"IpcMode":{{json .HostConfig.IpcMode}},'
    '"Privileged":{{json .HostConfig.Privileged}},"Binds":{{json .HostConfig.Binds}},'
    '"PortBindings":{{json .HostConfig.PortBindings}},"AutoRemove":{{json .HostConfig.AutoRemove}},'
    '"Tmpfs":{{json .HostConfig.Tmpfs}}},"Mounts":{{json .Mounts}},'
    '"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},'
    '"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},"Error":{{json .State.Error}}}}'
)


class ObservationError(ValueError):
    """Only fixed public reasons, never Docker output or environment details."""


def script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ObservationError("malformed_inspection")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise ObservationError("malformed_inspection") from None


def native_platform():
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(host_platform.machine())
    if sys.platform != "linux" or os.name != "posix" or architecture is None:
        raise ObservationError("native_platform_required")
    return "linux/" + architecture


def environment():
    # No caller Docker/proxy/token/Grype/Syft options reach the Docker client.
    result = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    if os.environ.get("HOME"):
        result["HOME"] = os.environ["HOME"]
    if os.name == "nt":  # Synthetic subprocess controls only; native collection refuses Windows.
        for key in ("SYSTEMROOT", "WINDIR"):
            if key in os.environ:
                result[key] = os.environ[key]
    return result


def run(command, *, deadline, limit, timeout=5):
    """Drain private FD leases; shared primitives retain unreaped process ownership."""
    expires = min(deadline, time.monotonic() + timeout)
    if expires <= time.monotonic():
        raise ObservationError("deadline")
    lifecycle = script("grype_runtime")
    if os.name == "posix":
        lifecycle.require_owned_waitid()
    child = None
    readers, leases, stops = [], [], []
    buffers, failures = [bytearray(), bytearray()], []
    completed = [threading.Event(), threading.Event()]
    wake = threading.Event()
    primary = None
    start_failed = False
    try:
        child = lifecycle.OwnedPopen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=ROOT, env=environment(), start_new_session=os.name == "posix", shell=False)

        def drain(index, lease, stop):
            try:
                while not stop.is_set():
                    try:
                        block = os.read(lease.read_fd, min(4096, limit + 1 - len(buffers[index])))
                    except BlockingIOError:
                        stop.wait(.025)
                        continue
                    if not block:
                        break
                    if len(buffers[index]) + len(block) > limit:
                        failures.append("output_budget")
                        break
                    if stop.is_set():
                        break
                    buffers[index].extend(block)
            except BaseException:
                failures.append("output_pipe")
            finally:
                try:
                    lease.close()
                except BaseException:
                    failures.append("owned_cleanup_failed")
                completed[index].set()
                wake.set()

        for index, stream in enumerate((child.stdout, child.stderr)):
            lease = lifecycle.ReaderDescriptors(stream.fileno())
            leases.append(lease)
            stop = threading.Event()
            stops.append(stop)
            reader = threading.Thread(target=drain, args=(index, lease, stop), daemon=True)
            readers.append(reader)
            lease.transfer()
            try:
                reader.start()
            except BaseException:
                start_failed = True
                raise
        while True:
            if failures:
                raise ObservationError(failures[0])
            if time.monotonic() >= expires:
                raise ObservationError("deadline")
            code = lifecycle.peek_owned_returncode(child) if os.name == "posix" else child.poll()
            if code is not None and all(event.is_set() for event in completed):
                if failures:
                    raise ObservationError(failures[0])
                return code, bytes(buffers[0]), bytes(buffers[1])
            wake.wait(min(0.01, max(0, expires - time.monotonic())))
            wake.clear()
    except OSError:
        primary = ObservationError("docker_client")
        raise primary from None
    except BaseException as error:
        primary = error
        raise
    finally:
        if child is not None:
            refused = start_failed
            for stop in stops:
                stop.set()
            try:
                lifecycle.terminate_owned_process(child)
            except BaseException:
                refused = True
            for stream in (child.stdout, child.stderr):
                try:
                    stream.close()
                except BaseException:
                    refused = True
            for reader in readers:
                try:
                    reader.join(timeout=2)
                    refused = refused or reader.is_alive()
                except BaseException:
                    refused = True
            for lease in leases:
                if not lease.transferred:
                    try:
                        lease.close_if_untransferred()
                    except BaseException:
                        refused = True
            refused = refused or "owned_cleanup_failed" in failures
            # A transferred lease may still belong to a delayed target or a
            # retained start traceback. Release parent references, never close
            # its reserved numeric FDs or claim a failed join was successful.
            readers.clear()
            leases.clear()
            stops.clear()
            lease = reader = drain = None
            if refused:
                if primary is None:
                    raise ObservationError("owned_cleanup_failed")
                primary.add_note("owned_cleanup_failed")


def image(value, *, subject, config):
    expected = {"Id": subject["image_config"], "Os": config["os"], "Architecture": config["architecture"],
                "RootFS": {"Type": "layers", "Layers": config["rootfs"]["diff_ids"]}}
    if value != expected:
        raise ObservationError("loaded_image_subject")
    return value


def container(value, *, identifier, name, nonce, image_id, expected_env, phase=None):
    if not isinstance(value, dict) or not isinstance(value.get("Id"), str) or \
            not re.fullmatch(r"[a-f0-9]{64}", value["Id"]) or identifier is not None and value["Id"] != identifier:
        raise ObservationError("container_identity")
    expected_host = {"NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"], "PidsLimit": 32, "Memory": 536870912, "MemorySwap": 536870912,
        "NanoCpus": 1000000000, "IpcMode": "none", "Privileged": False, "Binds": None, "PortBindings": {},
        "AutoRemove": False, "Tmpfs": {"/var/lib/clickhouse": TMPFS}}
    expected = {"Id": value["Id"], "Name": "/" + name, "Image": image_id, "Nonce": nonce,
        "Env": expected_env,
        "Path": "/usr/bin/clickhouse", "Args": ["server", "--version"], "User": "65534:65534",
        "Entrypoint": ["/usr/bin/clickhouse"], "Cmd": ["server", "--version"], "HostConfig": expected_host,
        "Mounts": []}
    observed = {key: item for key, item in value.items() if key != "State"}
    if not isinstance(expected_env, list) or any(
            not isinstance(item, str) or '=' not in item for item in expected_env) or \
            len({item.split('=', 1)[0] for item in expected_env}) != len(expected_env):
        raise ObservationError("selected_image_environment")
    if observed != expected or any(type(value["HostConfig"].get(key)) is not type(expected_host[key])
                                  for key in expected_host):
        raise ObservationError("container_controls")
    state = value.get("State")
    if not isinstance(state, dict) or set(state) != {"Status", "Running", "ExitCode", "OOMKilled", "Error"} or \
            type(state["Running"]) is not bool or type(state["OOMKilled"]) is not bool or \
            type(state["ExitCode"]) is not int or not isinstance(state["Error"], str):
        raise ObservationError("container_state")
    if phase is not None and state != {"Status": phase, "Running": False, "ExitCode": 0,
                                      "OOMKilled": False, "Error": ""}:
        raise ObservationError("container_state")
    return value["Id"]


class Observer:
    def __init__(self, *, subject, config, deadline, client=None):
        self.subject, self.config, self.deadline = subject, config, deadline
        self.client = client or run
        self.invocation = str(uuid4())
        self.nonce = uuid4().hex
        self.name = "shadai-clickhouse-observe-" + self.invocation
        self.identifier = None
        self.create_attempted = False
        self.removed = False
        self.process_refused = False

    def command(self, arguments, *, deadline=None, limit=16 * 1024, timeout=5):
        if self.process_refused:
            raise ObservationError("owned_cleanup_failed")
        try:
            code, stdout, stderr = self.client(["docker", "--context", "default", *arguments],
                deadline=self.deadline if deadline is None else deadline, limit=limit, timeout=timeout)
        except BaseException as error:
            notes = getattr(error, "__notes__", ())
            if error.args == ("owned_cleanup_failed",) or isinstance(notes, list) and any(
                    type(note) is str and note == "owned_cleanup_failed" for note in notes):
                self.process_refused = True
            raise
        if type(code) is not int or code != 0 or stderr:
            raise ObservationError("docker_nonzero_or_stderr")
        return stdout

    def ids(self, *, name=False, deadline=None):
        selector = "name=^/" + self.name + "$" if name else "id=" + self.identifier
        raw = self.command(["container", "ls", "--all", "--no-trunc", "--filter", selector, "--format", "{{.ID}}"],
                           deadline=deadline, limit=256)
        if not re.fullmatch(rb"(?:[a-f0-9]{64}\n)?", raw):
            raise ObservationError("container_identity")
        return raw.decode().strip()

    def inspect(self, identifier, *, phase=None, deadline=None):
        if self.identifier is not None and self.identifier != identifier:
            raise ObservationError("container_identity")
        value = decode(self.command(["container", "inspect", "--format", CONTAINER_FORMAT, identifier],
                                    deadline=deadline))
        return container(value, identifier=identifier, name=self.name, nonce=self.nonce,
            image_id=self.subject["image_config"], expected_env=self.config.get("config", {}).get("Env"), phase=phase)

    def loaded_image(self):
        return image(decode(self.command(["image", "inspect", "--format", IMAGE_FORMAT,
                                          self.subject["image_config"]])), subject=self.subject, config=self.config)

    def collect(self):
        endpoint = decode(self.command(["context", "inspect", "default", "--format",
                                        "{{json .Endpoints.docker.Host}}"], limit=256))
        if endpoint != "unix:///var/run/docker.sock":
            raise ObservationError("local_daemon_required")
        if self.config.get("config", {}).get("Volumes") != {"/var/lib/clickhouse": {}}:
            raise ObservationError("unexpected_image_volume")
        self.loaded_image()
        if self.ids(name=True):
            raise ObservationError("container_name_collision")
        self.create_attempted = True
        raw = self.command(["create", "--pull=never", "--name", self.name, "--label", LABEL + "=" + self.nonce,
            "--network=none", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=32", "--memory=512m", "--memory-swap=512m",
            "--cpus=1", "--ipc=none", "--tmpfs", "/var/lib/clickhouse:" + TMPFS,
            "--entrypoint=/usr/bin/clickhouse", self.subject["image_config"], "server", "--version"], limit=256)
        if not re.fullmatch(rb"[a-f0-9]{64}\n", raw):
            raise ObservationError("container_create_reply")
        identifier = raw.decode().strip()
        verified = self.inspect(identifier, phase="created")
        if verified != identifier:
            raise ObservationError("container_identity")
        self.identifier = verified
        output = self.command(["start", "--attach", self.identifier], limit=256, timeout=20)
        if output != script("component_principal").STDOUT:
            raise ObservationError("cli_version_output")
        self.inspect(self.identifier, phase="exited")
        self.loaded_image()

    def cleanup(self):
        if self.process_refused:
            raise ObservationError("owned_cleanup_failed")
        if not self.create_attempted:
            return
        reserve = time.monotonic() + 5
        if self.identifier is None:
            candidate = self.ids(name=True, deadline=reserve)
            if not candidate:
                self.removed = True
                return
            self.identifier = self.inspect(candidate, deadline=reserve)
        self.inspect(self.identifier, deadline=reserve)
        self.command(["rm", "--force", self.identifier], deadline=reserve, limit=256)
        if self.ids(deadline=time.monotonic() + 5):
            raise ObservationError("owned_cleanup_failed")
        self.removed = True


def clear_stale_receipt(output):
    """Clear only the caller's regular receipt through a verified parent FD."""
    baseline = output.parent.lstat()
    if not stat.S_ISDIR(baseline.st_mode) or stat.S_ISLNK(baseline.st_mode):
        raise ObservationError("receipt_path")
    descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    primary = None
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (baseline.st_dev, baseline.st_ino):
            raise ObservationError("receipt_path")
        try:
            stale = os.stat(output.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(stale.st_mode) or stale.st_uid != os.getuid() or stale.st_nlink != 1:
            raise ObservationError("receipt_path")
        current = output.parent.lstat()
        if (current.st_dev, current.st_ino) != (baseline.st_dev, baseline.st_ino):
            raise ObservationError("receipt_path")
        os.unlink(output.name, dir_fd=descriptor)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError:
            if primary is None:
                raise ObservationError("owned_cleanup_failed") from None
            primary.add_note("owned_cleanup_failed")


def publication_functions():
    """Resolve the sole permitted Linux commit primitive before creating bytes."""
    if sys.platform != "linux" or os.name != "posix" or ctypes.sizeof(ctypes.c_long) != 8 or \
            ctypes.sizeof(ctypes.c_void_p) != 8 or \
            host_platform.machine() not in {"x86_64", "aarch64"}:
        raise ObservationError("terminal_publication_unsupported")
    try:
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        filesystem = library.fstatfs
        filesystem.argtypes = [ctypes.c_int, ctypes.c_void_p]
        filesystem.restype = ctypes.c_int
    except (AttributeError, OSError):
        raise ObservationError("terminal_publication_unsupported") from None
    return rename, filesystem


def namespace_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid


def secure_namespace(parent, expected=None):
    """The hosted current UID and root are trusted; no writable/aliased ancestor."""
    chain = []
    for path in [*reversed(parent.parents), parent]:
        value = os.lstat(path)
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or \
                value.st_uid not in {0, os.getuid()} or value.st_mode & 0o1022:
            raise ObservationError("publication_namespace")
        chain.append((path, namespace_identity(value)))
    if chain[-1][1][-1] != os.getuid() or expected is not None and chain != expected:
        raise ObservationError("publication_namespace")
    return chain


def local_filesystem(descriptor, function):
    # Linux native amd64/arm64 statfs starts with signed long f_type. The
    # oversized buffer accommodates the whole structure without ABI guessing.
    result = (ctypes.c_long * 512)()
    if function(descriptor, ctypes.byref(result)) != 0 or result[0] not in {
        0xEF53, 0x58465342, 0x9123683E, 0x01021994, 0x794C7630,
    }:
        raise ObservationError("publication_filesystem")


def pending_identity(path, expected, size):
    value = os.lstat(path)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o7777 != 0o600 or \
            value.st_nlink != 1 or value.st_size != size or (value.st_dev, value.st_ino) != expected:
        raise ObservationError("publication_pending_identity")


def cleanup_pending(path, namespace, owned):
    """Only a pending inode is disposable; an ambiguous FD is never retried."""
    if owned is None:
        return
    secure_namespace(path.parent, namespace)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    primary = None
    try:
        if namespace_identity(os.fstat(descriptor)) != namespace[-1][1]:
            raise ObservationError("owned_cleanup_failed")
        try:
            current = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid() or current.st_nlink != 1 or \
                (current.st_dev, current.st_ino) != owned:
            raise ObservationError("owned_cleanup_failed")
        os.unlink(path.name, dir_fd=descriptor)
    except BaseException as error:
        primary = error
        raise
    finally:
        closing = descriptor
        descriptor = None
        try:
            os.close(closing)
        except BaseException:
            if primary is None:
                raise ObservationError("owned_cleanup_failed") from None
            if "owned_cleanup_failed" not in getattr(primary, "__notes__", []):
                primary.add_note("owned_cleanup_failed")


def atomic_receipt(output, data, *, deadline=None, precommit=None, functions=None):
    """A terminal exclusive rename is the commit; pending bytes are never evidence."""
    output = script("component_principal").canonical_receipt_path(Path(os.path.abspath(output)))
    if not isinstance(data, bytes) or len(data) > 16 * 1024:
        raise ObservationError("receipt_budget")
    rename, filesystem = functions if functions is not None else publication_functions()
    namespace = secure_namespace(output.parent)
    pending = output.with_name(output.name + "." + uuid4().hex + ".pending")
    # Encode before the terminal phase: successful commit has no later IO,
    # cleanup, hashing, encoding, fsync, identity or deadline check.
    source_name, destination_name = os.fsencode(pending), os.fsencode(output)
    descriptor = fd = owned = None
    try:
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if namespace_identity(os.fstat(descriptor)) != namespace[-1][1]:
            raise ObservationError("publication_namespace")
        local_filesystem(descriptor, filesystem)
        fd = os.open(pending.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=descriptor)
        created = os.fstat(fd)
        owned = created.st_dev, created.st_ino
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ObservationError("receipt_write")
            view = view[written:]
        os.fsync(fd)
        closing = fd
        fd = None
        try:
            os.close(closing)
        except OSError as primary:
            primary.add_note("owned_cleanup_failed")
            raise
        os.fsync(descriptor)
        pending_identity(pending, owned, len(data))
        secure_namespace(output.parent, namespace)
        if precommit is not None:
            precommit()
        if deadline is not None and time.monotonic() >= deadline:
            raise ObservationError("deadline")
        closing = descriptor
        descriptor = None
        try:
            os.close(closing)
        except OSError as primary:
            primary.add_note("owned_cleanup_failed")
            raise
        # No owned FD remains. Root/current UID do not concurrently replace this
        # hosted namespace in the narrow pathname check -> rename window.
        secure_namespace(output.parent, namespace)
        pending_identity(pending, owned, len(data))
    except BaseException as primary:
        refused = False
        remaining = (fd, descriptor)
        fd = descriptor = None
        for value in remaining:
            if value is not None:
                try:
                    os.close(value)
                except BaseException:
                    refused = True
        try:
            cleanup_pending(pending, namespace, owned)
        except BaseException:
            refused = True
        if refused and "owned_cleanup_failed" not in getattr(primary, "__notes__", []):
            primary.add_note("owned_cleanup_failed")
        raise
    # Deliberately outside every cleanup/exception handler. A signal after the
    # atomic commit cannot trigger later IO or retroactively erase that commit.
    if rename(-100, source_name, -100, destination_name, 1) != 0:
        raise ObservationError("publication_refused")
    return


def archive_sha(path, deadline):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 4 * 1024**3:
        raise ObservationError("archive_identity")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        digest = hashlib.sha256()
        while True:
            if time.monotonic() >= deadline:
                raise ObservationError("deadline")
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        current = path.lstat()
        def identity(value):
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
        if identity(before) != identity(opened) or identity(opened) != identity(after) or \
                identity(after) != identity(current):
            raise ObservationError("archive_identity")
        return digest.hexdigest()
    finally:
        os.close(fd)


def collect(args):
    total_deadline = time.monotonic() + 120
    deadline = total_deadline - 10  # Reserve the independent 5s + 5s disposal phases.
    principal = script("component_principal")
    ci = principal.ci_identity(os.environ)
    if native_platform() != args.platform or args.output.name != "clickhouse.principal-observation.json":
        raise ObservationError("native_platform_or_receipt_path")
    args.output = principal.canonical_receipt_path(Path(os.path.abspath(args.output)))
    functions = publication_functions()
    secure_namespace(args.output.parent)
    clear_stale_receipt(args.output)
    source = {"commit": args.source_commit, "repository": args.repository}
    def clean_source():
        head_code, head, head_error = run(["git", "rev-parse", "HEAD"], deadline=deadline, limit=256)
        dirty_code, dirty, dirty_error = run(["git", "status", "--porcelain"], deadline=deadline, limit=16 * 1024)
        if head_code or dirty_code or head_error or dirty_error:
            raise ObservationError("clean_source_required")
        head, dirty = head.decode("ascii").strip(), dirty.strip()
        if head != source["commit"] or dirty:
            raise ObservationError("clean_source_required")
    clean_source()
    scan, binding = script("scan-images"), script("component_source")
    fingerprints = scan.source_fingerprints(ROOT, True, True)
    pins = script("verify-image-pins")
    services = pins.check_service_builds(ROOT, pins.inventory(ROOT))
    with script("oci_scan_layout").prepared_layout(args.input, platform=args.platform,
        scratch_parent=args.output.parent,
        expected_source=source, expected_component="clickhouse") as layout:
        manifest = layout.evidence["image_manifests"][0]
        documents = binding.subject_documents(layout, manifest)
        subject = {"archive_sha256": layout.evidence["archive_sha256"],
                   "image_manifest": "sha256:" + manifest.removeprefix("sha256:"),
                   "image_config": layout.evidence["image_configs"][manifest], "platform": args.platform}
        binding.bind_clickhouse(documents["provenance"]["statement"]["predicate"], platform=args.platform,
            selected_manifest=documents["manifest"], root=ROOT, service_manifest=services,
            expected_source=source, expected_ci=ci)
        observer = Observer(subject=subject, config=documents["config"], deadline=deadline)
        primary = None
        try:
            observer.collect()
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                observer.cleanup()
            except BaseException:
                if primary is None:
                    raise ObservationError("owned_cleanup_failed") from None
                if "owned_cleanup_failed" not in getattr(primary, "__notes__", []):
                    primary.add_note("owned_cleanup_failed")
        layout.assert_unchanged()
        observation = {"schema": 1, "kind": "clickhouse-cli-version", "status": "verified",
            "invocation": observer.invocation, "ci": ci, "source": source, "subject": subject,
            "collector_sha256": fingerprints["scripts/observe-clickhouse-version.py"],
            "process_module_sha256": fingerprints["scripts/grype_runtime.py"],
            "command_contract": "clickhouse-server-version-v1", "observation": {"binary": "/usr/bin/clickhouse",
            "argv": ["server", "--version"], "version": principal.VERSION, "reported_build_kind": "official build",
            "stdout_bytes": len(principal.STDOUT), "stdout_sha256": hashlib.sha256(principal.STDOUT).hexdigest(),
            "stderr_bytes": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest(), "docker_cli_exit_code": 0,
            "container_exit_code": 0}, "identity": {"image_id_before": subject["image_config"],
            "image_id_after": subject["image_config"], "container_image_before": subject["image_config"],
            "container_image_after": subject["image_config"],
            "rootfs_diff_ids": documents["config"]["rootfs"]["diff_ids"]},
            "cleanup": {"container_removed": observer.removed, "absence_verified": observer.removed},
            "authentication": {"builder_provenance": "unverified", "publisher_signature": "unverified"}}
        observation["identity"]["env_matches_image"] = True
        principal.validate_receipt(observation, subject=subject, config=documents["config"], expected_source=source,
            expected_ci=ci, collector_sha256=fingerprints["scripts/observe-clickhouse-version.py"],
            process_module_sha256=fingerprints["scripts/grype_runtime.py"])
    def precommit():
        clean_source()
        if time.monotonic() >= total_deadline or scan.source_fingerprints(ROOT, True, True) != fingerprints or \
                archive_sha(args.input, total_deadline) != subject["archive_sha256"]:
            raise ObservationError("source_or_archive_drift")
    atomic_receipt(args.output, json.dumps(observation, sort_keys=True, separators=(",", ":")).encode() + b"\n",
                   deadline=total_deadline, precommit=precommit, functions=functions)
    return observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        collect(args)
    except BaseException:
        print("REFUSED: native principal observation or owned cleanup failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
