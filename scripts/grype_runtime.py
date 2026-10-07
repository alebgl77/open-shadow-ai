"""Pinned, invocation-owned Grype runtime. No scanner acceptance sidecars are written.

Every query uses one freshly downloaded, validated and byte-frozen database.
The caller binds identifiers to its subject and validates advisory coverage.
"""

import hashlib
import json
import os
import platform as host_platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

VERSION = "0.120.1"
COMMIT = "6f8d854af29d3a3086b11a84afa51554a2a245fe"
CHECKSUM_FILE = "c25b6095265b44fd9bbb9dbe76aca8daa394c5f0490793d2b52b16be4f5b71b1"
PINS = {
    "linux/amd64": ("0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d", 32270829),
    "linux/arm64": ("29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514", 29446856),
}
CHUNK = 1024 * 1024
MAX_JSON = 128 * CHUNK
MAX_BINARY = 256 * CHUNK
MAX_DB_FILE = 2 * 1024 * CHUNK
MAX_WORKSPACE = 4 * 1024 * CHUNK
MAX_ENTRIES = 128
MAX_QUERIES = 32
WALL_SECONDS = 600
ASSET_MEMBERS = frozenset({"grype", "LICENSE", "README.md", "CHANGELOG.md"})
DB_URL = "https://grype.anchore.io/databases"
DB_FILES = {"vulnerability.db", "import.json", "last_update_check"}
ANCHORED = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
HEX = re.compile(r"[0-9a-f]{64}")
ERRORS = {
    "platform", "manifest", "config", "filesystem", "identity_changed", "byte_budget", "deadline",
    "download", "archive", "version", "nonzero", "json", "database", "identifier", "query_budget",
    "output_budget", "timeout", "owned_cleanup_failed", "configuration_unobserved",
}
PREPARE_PHASES = frozenset({
    "source_guard", "workspace", "download", "extract", "config", "version", "check_files",
    "update", "adopt_database", "status", "import_validation",
})
FILESYSTEM_REASONS = frozenset({
    "directory_not_safe", "file_not_regular", "hardlink", "tree_unexpected", "root_unexpected",
    "home_nonempty", "tmp_nonempty", "cache_unexpected", "identity_drift", "syscall",
})
TEMPLATE = {
    "check-for-app-update": False, "add-cpes-if-none": False, "only-fixed": False, "only-notfixed": False,
    "ignore-states": "", "ignore": [], "exclude": [], "vex-documents": [], "vex-add": [],
    "include-matcher-suppressions": True, "fail-on-severity": "",
    "db": {"update-url": DB_URL, "auto-update": False, "validate-by-hash-on-start": True,
           "validate-age": True, "max-allowed-built-age": "24h", "require-update-check": True},
}


class GrypeRuntimeError(ValueError):
    def __init__(self, code, *, filesystem_reason=None):
        self.code = code if code in ERRORS else "config"
        self.prepare_phase = None
        self.filesystem_reason = filesystem_reason
        super().__init__(self.code)


def identity(value):
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def unchanged(before, after):
    return identity(before) == identity(after) and (
        before.st_size, before.st_mtime_ns, before.st_ctime_ns
    ) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def safe_stat(path):
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(path, "is_junction", lambda: False)():
        raise GrypeRuntimeError("filesystem", filesystem_reason="directory_not_safe")
    return value


class Directory:
    """Pin every ancestor and use directory-relative operations on POSIX."""

    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.chain = []
        self.fd = None
        current = Path(self.path.anchor)
        try:
            for part in (None, *self.path.parts[1:]):
                parent = self.fd
                if part is not None:
                    current /= part
                observed = safe_stat(current)
                if not stat.S_ISDIR(observed.st_mode):
                    raise GrypeRuntimeError("filesystem", filesystem_reason="directory_not_safe")
                fd = None
                if ANCHORED:
                    fd = os.open(current if part is None else part,
                                 os.O_RDONLY | os.O_DIRECTORY | FLAGS, dir_fd=parent)
                    if identity(os.fstat(fd)) != identity(observed):
                        os.close(fd)
                        raise GrypeRuntimeError("identity_changed")
                self.chain.append((current, identity(observed), fd))
                self.fd = fd
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for path, expected, fd in self.chain:
            if identity(safe_stat(path)) != expected or fd is not None and identity(os.fstat(fd)) != expected:
                raise GrypeRuntimeError("identity_changed")

    def entry(self, name):
        self.check()
        value = (os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                 if ANCHORED else safe_stat(self.path / name))
        if stat.S_ISLNK(value.st_mode):
            raise GrypeRuntimeError("filesystem", filesystem_reason="directory_not_safe")
        return value

    def open(self, name, flags, mode=0o600):
        self.check()
        fd = os.open(name if ANCHORED else self.path / name, flags | FLAGS, mode,
                     **({"dir_fd": self.fd} if ANCHORED else {}))
        try:
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or identity(value) != identity(self.entry(name)):
                reason = "file_not_regular" if not stat.S_ISREG(value.st_mode) else \
                    "hardlink" if value.st_nlink != 1 else "identity_drift"
                raise GrypeRuntimeError("filesystem", filesystem_reason=reason)
            self.check()
            return fd
        except BaseException:
            os.close(fd)
            raise

    def names(self):
        self.check()
        result = set()
        with os.scandir(self.fd if ANCHORED else self.path) as entries:
            for entry in entries:
                if len(result) >= MAX_ENTRIES:
                    raise GrypeRuntimeError("byte_budget")
                result.add(entry.name)
        return result

    def remove(self, name, directory):
        self.check()
        (os.rmdir if directory else os.unlink)(name if ANCHORED else self.path / name,
                                               **({"dir_fd": self.fd} if ANCHORED else {}))

    def chmod(self, name, mode):
        self.check()
        if ANCHORED:
            fd = self.open(name, os.O_RDONLY)
            try:
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
        else:
            os.chmod(self.path / name, mode)

    def close(self):
        for _, _, fd in reversed(self.chain):
            if fd is not None:
                os.close(fd)
        self.chain = []


def remaining(deadline):
    result = deadline - time.monotonic()
    if result <= 0:
        raise GrypeRuntimeError("deadline")
    return result


def hash_fd(fd, *, limit, deadline):
    before = os.fstat(fd)
    if before.st_size > limit or before.st_size < 0:
        raise GrypeRuntimeError("byte_budget")
    os.lseek(fd, 0, os.SEEK_SET)
    checksum, size = hashlib.sha256(), 0
    while True:
        remaining(deadline)
        chunk = os.read(fd, min(CHUNK, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise GrypeRuntimeError("byte_budget")
        checksum.update(chunk)
    if size != before.st_size or not unchanged(before, os.fstat(fd)):
        raise GrypeRuntimeError("identity_changed")
    return checksum.hexdigest()


class FileGuard:
    def __init__(self, directory, name, *, limit, deadline):
        self.parent, self.name, self.limit, self.deadline = directory, name, limit, deadline
        self.fd = directory.open(name, os.O_RDONLY)
        try:
            self.fd_stat = os.fstat(self.fd)
            self.path_stat = directory.entry(name)
            self.sha256 = hash_fd(self.fd, limit=limit, deadline=deadline)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        if not unchanged(self.fd_stat, os.fstat(self.fd)) or \
                not unchanged(self.path_stat, self.parent.entry(self.name)):
            raise GrypeRuntimeError("identity_changed")
        if hash_fd(self.fd, limit=self.limit, deadline=self.deadline) != self.sha256:
            raise GrypeRuntimeError("identity_changed")
        if identity(os.fstat(self.fd)) != identity(self.parent.entry(self.name)):
            raise GrypeRuntimeError("identity_changed")

    def read_json(self):
        self.check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        limit = min(self.limit, MAX_JSON)
        value = os.read(self.fd, limit + 1)
        self.check()
        return decode_json(value, limit)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def decode_json(value, limit=MAX_JSON):
    if len(value) > limit:
        raise GrypeRuntimeError("output_budget")

    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise GrypeRuntimeError("json")
            result[key] = item
        return result

    try:
        result = json.loads(value, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(GrypeRuntimeError("json")))
    except (ValueError, UnicodeError, RecursionError):
        raise GrypeRuntimeError("json") from None
    if not isinstance(result, dict):
        raise GrypeRuntimeError("json")
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def write_all(fd, data):
    while data:
        size = os.write(fd, data)
        if size <= 0:
            raise GrypeRuntimeError("filesystem", filesystem_reason="syscall")
        data = data[size:]


def clean_environment(workspace):
    # An allowlist, rather than an incomplete list of caller overrides.
    result = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
              "HOME": str(workspace / "home"), "XDG_CONFIG_HOME": str(workspace / "home"),
              "XDG_CACHE_HOME": str(workspace / "cache"), "TMPDIR": str(workspace / "tmp")}
    if os.name == "nt":  # Only the synthetic subprocess tests run on Windows.
        for key in ("SYSTEMROOT", "WINDIR"):
            if key in os.environ:
                result[key] = os.environ[key]
    return result


class OwnedPopen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        self._ownership_abandoned = False
        super().__init__(*args, **kwargs)

    def abandon_ownership(self):
        self._ownership_abandoned = True

    def __del__(self, _base_finalizer=subprocess.Popen.__del__):
        if not getattr(self, "_ownership_abandoned", False):
            _base_finalizer(self)


class ReaderDescriptors:
    """Private duplicate FDs: after transfer, only the reader may dispose them."""

    def __init__(self, source_fd, output_fd=None):
        self.read_fd = self.output_fd = None
        self.transferred = False
        try:
            self.read_fd = os.dup(source_fd)
            if output_fd is not None:
                self.output_fd = os.dup(output_fd)
            if os.name == "posix":
                os.set_blocking(self.read_fd, False)
        except BaseException as primary:
            try:
                self.close()
            except GrypeRuntimeError:
                primary.add_note("owned_cleanup_failed")
            raise

    def transfer(self):
        if self.transferred:
            raise GrypeRuntimeError("owned_cleanup_failed")
        self.transferred = True

    def close_if_untransferred(self):
        if self.transferred:
            raise GrypeRuntimeError("owned_cleanup_failed")
        self.close()

    def close(self):
        failed = False
        for field in ("read_fd", "output_fd"):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    os.close(descriptor)
                except OSError:
                    failed = True
        if failed:
            raise GrypeRuntimeError("owned_cleanup_failed")

    def __del__(self, _close=os.close, _error=OSError):
        for field in ("read_fd", "output_fd"):
            descriptor = getattr(self, field, None)
            if descriptor is not None:
                setattr(self, field, None)
                try:
                    _close(descriptor)
                except _error:
                    pass


def require_owned_waitid():
    required = ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")
    if not callable(getattr(os, "waitid", None)) or any(not hasattr(os, name) for name in required) or \
            not hasattr(signal, "SIGCHLD") or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise GrypeRuntimeError("platform")


def refuse_owned_process(child):
    child.abandon_ownership()
    raise GrypeRuntimeError("owned_cleanup_failed") from None


def peek_owned_returncode(child):
    # WNOWAIT pins the owned session leader's PID until group termination.
    # Neither Popen.poll() nor wait() may reap it before that boundary.
    if getattr(child, "_ownership_abandoned", False):
        raise GrypeRuntimeError("owned_cleanup_failed")
    try:
        require_owned_waitid()
        observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except (OSError, GrypeRuntimeError):
        refuse_owned_process(child)
    if observed is None:
        return None
    pid, code, status = (getattr(observed, field, None) for field in ("si_pid", "si_code", "si_status"))
    if type(pid) is not int or pid != child.pid or type(code) is not int or type(status) is not int:
        refuse_owned_process(child)
    if code == os.CLD_EXITED and 0 <= status <= 255:
        return status
    if code in {os.CLD_KILLED, os.CLD_DUMPED} and 0 < status < signal.NSIG:
        return -status
    refuse_owned_process(child)


def terminate_owned_process(child):
    if getattr(child, "_ownership_abandoned", False):
        raise GrypeRuntimeError("owned_cleanup_failed")
    try:
        if os.name == "posix":
            peek_owned_returncode(child)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        raise GrypeRuntimeError("owned_cleanup_failed") from None


def cleanup_process(child, reader, *, stop_event=None):
    failed = False
    if stop_event is not None:
        stop_event.set()
    try:
        terminate_owned_process(child)
    except GrypeRuntimeError:
        failed = True
    if reader is not None:
        try:
            reader.join(timeout=2)
            if reader.is_alive():
                failed = True
        except RuntimeError:
            failed = True
    try:
        child.stdout.close()
    except (OSError, ValueError):
        failed = True
    if failed:
        raise GrypeRuntimeError("owned_cleanup_failed")


def run(command, *, environment, cwd, deadline, limit, output_fd=None, capture=True, monitor=None, timeout=300):
    """Bound stdout before allocation; kill/reap the owned group even after success."""
    remaining(deadline)
    if os.name == "posix":
        require_owned_waitid()
    command_deadline = min(deadline, time.monotonic() + timeout)
    child = None
    reader = None
    descriptors = None
    drain = None
    start_failed = False
    stop = None
    primary = None
    try:
        child = OwnedPopen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=environment, cwd=cwd,
                           start_new_session=os.name == "posix", shell=False)
        done = threading.Event()
        stop = threading.Event()
        result, failures = bytearray(), []
        descriptors = ReaderDescriptors(child.stdout.fileno(), output_fd)

        def drain(lease, stop_event):
            size = 0
            try:
                while not stop_event.is_set():
                    try:
                        chunk = os.read(lease.read_fd, min(CHUNK, limit - size + 1))
                    except BlockingIOError:
                        stop_event.wait(0.025)
                        continue
                    if not chunk:
                        break
                    if size + len(chunk) > limit:
                        failures.append("output_budget")
                        break
                    size += len(chunk)
                    if stop_event.is_set():
                        break
                    if lease.output_fd is not None:
                        pending = chunk
                        while pending and not stop_event.is_set():
                            written = os.write(lease.output_fd, pending)
                            if written <= 0:
                                raise GrypeRuntimeError("filesystem")
                            pending = pending[written:]
                    if capture:
                        result.extend(chunk)
            except (OSError, ValueError):
                failures.append("filesystem")
            finally:
                try:
                    lease.close()
                except GrypeRuntimeError:
                    failures.append("owned_cleanup_failed")
                done.set()

        reader = threading.Thread(target=drain, args=(descriptors, stop), name="grype-owned-output", daemon=True)
        descriptors.transfer()
        try:
            reader.start()
        except BaseException:
            start_failed = True
            raise
        while True:
            if failures:
                raise GrypeRuntimeError(failures[0])
            if monitor is not None:
                monitor()
            budget = remaining(deadline)
            if time.monotonic() >= command_deadline:
                raise GrypeRuntimeError("timeout")
            budget = min(budget, command_deadline - time.monotonic())
            returncode = peek_owned_returncode(child) if os.name == "posix" else child.poll()
            if returncode is not None and done.is_set():
                if failures:
                    raise GrypeRuntimeError(failures[0])
                if returncode:
                    raise GrypeRuntimeError("nonzero")
                return bytes(result)
            done.wait(min(0.025, budget)) if not done.is_set() else time.sleep(min(0.025, budget))
    except BaseException as error:
        primary = error
        raise
    finally:
        if stop is not None:
            stop.set()
        lease_failed = False
        if descriptors is not None and not descriptors.transferred:
            try:
                descriptors.close_if_untransferred()
            except GrypeRuntimeError:
                lease_failed = True
        try:
            if child is not None:
                try:
                    cleanup_process(child, reader, stop_event=stop)
                    if lease_failed or start_failed:
                        raise GrypeRuntimeError("owned_cleanup_failed")
                except GrypeRuntimeError:
                    if primary is None:
                        raise
                    primary.add_note("owned_cleanup_failed")
        finally:
            reader = descriptors = drain = None


# Network DNS/read operations are inside the same cancellable owned process
# protocol. TLS trust is the system CA bundle, never a caller environment path.
DOWNLOAD_CODE = r'''
import ssl,sys,urllib.request,urllib.parse
class Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections=5
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        u=urllib.parse.urlsplit(newurl)
        if (u.scheme!='https' or u.hostname not in {'github.com','release-assets.githubusercontent.com'}
            or u.username or u.password or u.port not in {None,443}):
            raise RuntimeError('redirect')
        return super().redirect_request(req,fp,code,msg,headers,newurl)
ctx=ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect(),urllib.request.HTTPSHandler(context=ctx))
expected=int(sys.argv[2]);size=0
with opener.open(sys.argv[1],timeout=5) as response:
    declared=response.headers.get('Content-Length')
    if declared is not None and int(declared)!=expected: raise RuntimeError('length')
    while True:
        chunk=response.read(min(1048576,expected-size+1))
        if not chunk: break
        size+=len(chunk)
        if size>expected: raise RuntimeError('length')
        sys.stdout.buffer.write(chunk);sys.stdout.buffer.flush()
if size!=expected: raise RuntimeError('length')
'''


def native_platform():
    if sys.platform != "linux" or os.name != "posix":
        raise GrypeRuntimeError("platform")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(host_platform.machine())
    if arch is None:
        raise GrypeRuntimeError("platform")
    return "linux/" + arch


def validate_manifest(value, platform):
    if not isinstance(value, dict) or type(value.get("schema")) is not int or platform not in PINS or value != {
        "schema": 1, "version": VERSION, "commit": COMMIT, "checksum_file_sha256": CHECKSUM_FILE,
        "archives": {name: {"url": f"https://github.com/anchore/grype/releases/download/v{VERSION}/"
                            f"grype_{VERSION}_linux_{name.split('/')[1]}.tar.gz", "sha256": checksum, "bytes": size}
                     for name, (checksum, size) in PINS.items()},
    }:
        raise GrypeRuntimeError("manifest")
    if any(type(item["bytes"]) is not int for item in value["archives"].values()):
        raise GrypeRuntimeError("manifest")
    return value["archives"][platform]


class AssetTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        if self.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or self.name not in ASSET_MEMBERS:
            raise GrypeRuntimeError("archive")
        limit = MAX_BINARY if self.name == "grype" else CHUNK
        if self.size < 0 or self.size > limit:
            raise GrypeRuntimeError("byte_budget")
        return super()._proc_member(archive)


def validate_identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or not value.isascii():
        raise GrypeRuntimeError("identifier")
    if value.startswith("pkg:golang/"):
        pattern = r"pkg:golang/[A-Za-z0-9._~%+/-]+@v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?"
        if value != "pkg:golang/github.com/tianon/gosu@1.19" and not re.fullmatch(pattern, value):
            raise GrypeRuntimeError("identifier")
        if any(part in {"", ".", ".."} for part in value[11:].split("@")[0].split("/")):
            raise GrypeRuntimeError("identifier")
    elif value.startswith("cpe:2.3:a:"):
        parts = value.split(":")
        if len(parts) != 13 or parts[5] in {"", "*", "-"} or not re.fullmatch(r"[A-Za-z0-9._*+-]+", parts[5]):
            raise GrypeRuntimeError("identifier")
        pattern = r"cpe:2\.3:a:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+:[A-Za-z0-9._*+-]+(?::[A-Za-z0-9._*+-]+){7}"
        if not re.fullmatch(pattern, value):
            raise GrypeRuntimeError("identifier")
    else:
        raise GrypeRuntimeError("identifier")


def validate_configuration(value, cache=None, platform=None):
    if not isinstance(value, dict):
        raise GrypeRuntimeError("config")
    if cache is None:
        directory = value.get("db", {}).get("cache-dir") if isinstance(value.get("db"), dict) else None
        if not isinstance(directory, str) or len(directory) > 4096:
            raise GrypeRuntimeError("config")
        parsed = PurePosixPath(directory)
        if not parsed.is_absolute() or str(parsed) != directory or \
                parsed.name != "database" or not re.fullmatch(r"grype-[0-9a-f]{32}", parsed.parent.name) or \
                any(part in {".", ".."} for part in directory.split("/")):
            raise GrypeRuntimeError("config")
        cache = directory
    if platform is None:
        platform = value.get("platform")
    if platform not in PINS:
        raise GrypeRuntimeError("config")
    required = {key: item for key, item in TEMPLATE.items() if key not in {"db", "ignore-states"}}
    required.update({"ignore-wontfix": "", "distro": "", "output-template-file": "", "file": "",
                     "platform": platform, "from": [], "name": ""})
    for key, expected in required.items():
        if key not in value:
            raise GrypeRuntimeError("config")
        actual = value.get(key)
        # Go nil slices serialize as null. Both null and [] mean no filter.
        if expected == [] and actual is None:
            continue
        if actual != expected or isinstance(expected, bool) and type(actual) is not bool:
            raise GrypeRuntimeError("config")
    if value.get("output") != ["json"]:
        raise GrypeRuntimeError("config")
    external = value.get("externalSources")
    if not isinstance(external, dict) or external.get("enable") is not False:
        raise GrypeRuntimeError("config")
    db = value.get("db")
    required_db = {**TEMPLATE["db"], "cache-dir": str(cache), "max-allowed-built-age": 86400000000000,
                   "ca-cert": ""}
    if not isinstance(db, dict) or any(db.get(key) != item or isinstance(item, bool) and type(db.get(key)) is not bool
                                       for key, item in required_db.items()):
        raise GrypeRuntimeError("config")
    if type(db["max-allowed-built-age"]) is not int:
        raise GrypeRuntimeError("config")
    # Keep the pinned matcher defaults, including stock CPE and direct Go matching.
    matches = value.get("match")
    if not isinstance(matches, dict) or matches.get("stock") != {"using-cpes": True}:
        raise GrypeRuntimeError("config")
    golang = matches.get("golang")
    if not isinstance(golang, dict) or golang != {"using-cpes": False, "always-use-cpe-for-stdlib": False,
                                                "allow-main-module-pseudo-version-comparison": False}:
        raise GrypeRuntimeError("config")
    # Reject unknown filter/VEX/suppression settings, not just template keys.
    def inspect(node, depth=0):
        if isinstance(node, dict):
            for key, item in node.items():
                normalized = key.lower().replace("_", "-")
                filters = ("ignore", "exclude", "vex", "suppress", "only-fixed", "only-notfixed")
                if any(word in normalized for word in filters):
                    if depth or key not in required and key not in {"show-suppressed"}:
                        raise GrypeRuntimeError("config")
                inspect(item, depth + 1)
        elif isinstance(node, list):
            for item in node:
                inspect(item, depth + 1)
    inspect(value)


def parse_time(value):
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
            raise ValueError
        return result
    except (ValueError, TypeError):
        raise GrypeRuntimeError("database") from None


def validate_status(value, cache, fetched_at):
    if not isinstance(value, dict) or set(value) - {"schemaVersion", "from", "built", "path", "valid", "error"}:
        raise GrypeRuntimeError("database")
    if value.get("valid") is not True or value.get("error") is not None and value.get("error") != "":
        raise GrypeRuntimeError("database")
    if not isinstance(value.get("schemaVersion"), str) or \
            not re.fullmatch(r"6\.\d{1,3}\.\d{1,3}", value["schemaVersion"]):
        raise GrypeRuntimeError("database")
    if value.get("path") != str(cache / "6" / "vulnerability.db"):
        raise GrypeRuntimeError("database")
    source = value.get("from")
    if not isinstance(source, str) or len(source) > 2048:
        raise GrypeRuntimeError("database")
    try:
        url = urlsplit(source)
        checksum = parse_qs(url.query, strict_parsing=True)
        if url.scheme != "https" or url.netloc != "grype.anchore.io" or url.fragment or \
                not re.fullmatch(r"/databases/v6/[A-Za-z0-9_.:+-]+\.tar\.(?:zst|gz)", url.path) or \
                set(checksum) != {"checksum"} or len(checksum["checksum"]) != 1 or \
                not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum["checksum"][0]):
            raise ValueError
    except ValueError:
        raise GrypeRuntimeError("database") from None
    built, fetched, now = parse_time(value.get("built")), parse_time(fetched_at), datetime.now(UTC)
    if built > fetched or fetched > now or not 0 <= (now - built).total_seconds() <= 86400:
        raise GrypeRuntimeError("database")


class Runtime:
    def __init__(self, scratch_parent, manifest_path, config_path, platform):
        self.deadline = time.monotonic() + WALL_SECONDS
        self.platform = platform
        self.path = Path(os.path.abspath(scratch_parent)) / ("grype-" + uuid4().hex)
        self.directories, self.guards, self.created = [], [], []
        self.directory_cache = {}
        self.configuration = None
        self.configuration_bytes = None
        self.database_status = None
        self.status_bytes = None
        self.queries = 0
        self.closed = False
        self.prepare_phase = None
        self.sources = [(Path(os.path.abspath(p))) for p in (manifest_path, config_path, __file__)]

    def directory(self, path):
        key = os.path.normcase(os.path.abspath(path))
        if key in self.directory_cache:
            self.directory_cache[key].check()
            return self.directory_cache[key]
        value = Directory(path)
        self.directories.append(value)
        self.directory_cache[key] = value
        return value

    def guard(self, path, limit):
        value = FileGuard(self.directory(path.parent), path.name, limit=limit, deadline=self.deadline)
        self.guards.append(value)
        return value

    def mkdir(self, path):
        parent = self.directory(path.parent)
        parent.check()
        os.mkdir(path.name if ANCHORED else path, 0o700, **({"dir_fd": parent.fd} if ANCHORED else {}))
        self.created.append((parent, path.name, identity(parent.entry(path.name)), True))

    def create(self, path):
        parent = self.directory(path.parent)
        fd = parent.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        self.created.append((parent, path.name, identity(os.fstat(fd)), False))
        return fd

    def budget_tree(self):
        self.root.check()
        total, count = 0, 0
        pending = [self.path]
        while pending:
            remaining(self.deadline)
            directory = Directory(pending.pop())
            try:
                for name in directory.names():
                    count += 1
                    if count > MAX_ENTRIES:
                        raise GrypeRuntimeError("byte_budget")
                    value = directory.entry(name)
                    if stat.S_ISDIR(value.st_mode):
                        pending.append(directory.path / name)
                    elif stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_size <= MAX_DB_FILE:
                        total += value.st_size
                    else:
                        raise GrypeRuntimeError("filesystem", filesystem_reason="tree_unexpected")
                    if total > MAX_WORKSPACE:
                        raise GrypeRuntimeError("byte_budget")
            finally:
                directory.close()

    def command(self, arguments, *, limit=MAX_JSON, output_fd=None, capture=True, timeout=120):
        return run([str(self.path / "grype"), "-c", str(self.path / "grype.json"), *arguments],
                   environment=self.environment, cwd=self.path, deadline=self.deadline, limit=limit,
                   output_fd=output_fd, capture=capture, monitor=self.budget_tree, timeout=timeout)

    def prepare(self):
        try:
            self._prepare()
        except BaseException as primary:
            if type(primary) is GrypeRuntimeError:
                primary.prepare_phase = self.prepare_phase
            raise
        else:
            self.prepare_phase = None

    def _prepare(self):
        self.prepare_phase = "source_guard"
        if self.platform != native_platform():
            raise GrypeRuntimeError("platform")
        self.source_guards = [self.guard(path, CHUNK) for path in self.sources]
        asset = validate_manifest(self.source_guards[0].read_json(), self.platform)
        if self.source_guards[1].read_json() != TEMPLATE:
            raise GrypeRuntimeError("config")
        self.prepare_phase = "workspace"
        self.mkdir(self.path)
        self.root = self.directory(self.path)
        for name in ("home", "tmp", "cache", "database"):
            self.mkdir(self.path / name)
        self.cache = self.path / "database"
        self.environment = clean_environment(self.path)
        self.prepare_phase = "download"
        archive = self.path / "asset.tar.gz"
        fd = self.create(archive)
        try:
            run([sys.executable, "-I", "-B", "-c", DOWNLOAD_CODE, asset["url"], str(asset["bytes"])],
                environment=self.environment, cwd=self.path, deadline=self.deadline, limit=asset["bytes"],
                output_fd=fd, capture=False, monitor=self.budget_tree, timeout=120)
        finally:
            os.close(fd)
        self.root.chmod("asset.tar.gz", 0o400)
        self.archive_guard = self.guard(archive, asset["bytes"])
        if self.archive_guard.fd_stat.st_size != asset["bytes"] or self.archive_guard.sha256 != asset["sha256"]:
            raise GrypeRuntimeError("download")
        self.prepare_phase = "extract"
        binary = self.path / "grype"
        seen = set()
        os.lseek(self.archive_guard.fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(self.archive_guard.fd), "rb") as source, \
                tarfile.open(fileobj=source, mode="r|gz", tarinfo=AssetTarInfo) as members:
            for member in members:
                remaining(self.deadline)
                if member.name in seen or len(seen) >= len(ASSET_MEMBERS):
                    raise GrypeRuntimeError("archive")
                seen.add(member.name)
                if member.name != "grype":
                    continue
                fd = self.create(binary)
                try:
                    with members.extractfile(member) as stream:
                        size = 0
                        while chunk := stream.read(CHUNK):
                            remaining(self.deadline)
                            size += len(chunk)
                            if size > member.size:
                                raise GrypeRuntimeError("byte_budget")
                            write_all(fd, chunk)
                        if size != member.size or not size:
                            raise GrypeRuntimeError("archive")
                finally:
                    os.close(fd)
        if "grype" not in seen:
            raise GrypeRuntimeError("archive")
        self.archive_guard.check()
        self.root.chmod("grype", 0o500)
        self.binary_guard = self.guard(binary, MAX_BINARY)
        self.prepare_phase = "config"
        config = json.loads(canonical(TEMPLATE))
        config["db"]["cache-dir"] = str(self.cache)
        fd = self.create(self.path / "grype.json")
        try:
            write_all(fd, canonical(config))
        finally:
            os.close(fd)
        self.root.chmod("grype.json", 0o400)
        self.config_guard = self.guard(self.path / "grype.json", CHUNK)
        self.prepare_phase = "version"
        version = decode_json(self.command(["version", "-o", "json"], limit=CHUNK), CHUNK)
        if version.get("version") != VERSION or version.get("application") != "grype" or \
                version.get("platform") != self.platform or version.get("gitCommit") != COMMIT:
            raise GrypeRuntimeError("version")
        self.prepare_phase = "check_files"
        self.check_files()
        if self.directory(self.cache).names():
            raise GrypeRuntimeError("database")
        self.prepare_phase = "update"
        self.command(["db", "update"], limit=CHUNK, timeout=300)
        self.fetched_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        self.prepare_phase = "adopt_database"
        self.adopt_database()
        database = self.directory(self.cache / "6")
        for name in database.names():
            database.chmod(name, 0o400)
        self.db_guards = {name: self.guard(self.cache / "6" / name, MAX_DB_FILE) for name in database.names()}
        self.file_table = {"6/" + name: guard.sha256 for name, guard in sorted(self.db_guards.items())}
        self.table_sha256 = hashlib.sha256(canonical(self.file_table)).hexdigest()
        self.prepare_phase = "status"
        self.database_status = decode_json(self.command(["db", "status", "-o", "json"], limit=CHUNK), CHUNK)
        validate_status(self.database_status, self.cache, self.fetched_at)
        self.status_bytes = canonical(self.database_status)
        self.prepare_phase = "import_validation"
        imported = self.db_guards["import.json"].read_json()
        if imported.get("source") != self.database_status["from"] or \
                imported.get("client_version") != "6.1.10" or \
                not isinstance(imported.get("digest"), str) or \
                not re.fullmatch(r"xxh64:[0-9a-f]{16}", imported["digest"]):
            raise GrypeRuntimeError("database")
        self.prepare_phase = "check_files"
        self.check_files()

    def adopt_database(self):
        cache = self.directory(self.cache)
        cache_names = cache.names()
        if "6" not in cache_names:
            raise GrypeRuntimeError("database")
        directory = self.directory(self.cache / "6")
        self.created.append((cache, "6", identity(cache.entry("6")), True))
        names = directory.names()
        for name in sorted(names & DB_FILES):
            value = directory.entry(name)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > MAX_DB_FILE:
                raise GrypeRuntimeError("database")
            self.created.append((directory, name, identity(value), False))
        if cache_names != {"6"} or not {"vulnerability.db", "import.json"} <= names or names - DB_FILES:
            raise GrypeRuntimeError("database")

    def check_files(self):
        remaining(self.deadline)
        if self.status_bytes is not None and canonical(self.database_status) != self.status_bytes or \
                self.configuration_bytes is not None and canonical(self.configuration) != self.configuration_bytes:
            raise GrypeRuntimeError("identity_changed")
        if hasattr(self, "file_table") and hashlib.sha256(canonical(self.file_table)).hexdigest() != self.table_sha256:
            raise GrypeRuntimeError("identity_changed")
        for guard in self.guards:
            guard.check()
        for directory in self.directories:
            directory.check()
        if hasattr(self, "db_guards"):
            if self.directory(self.cache).names() != {"6"} or \
                    self.directory(self.cache / "6").names() != set(self.db_guards):
                raise GrypeRuntimeError("database")
            if self.database_status:
                validate_status(self.database_status, self.cache, self.fetched_at)
        if hasattr(self, "root"):
            if self.root.names() != {"home", "tmp", "cache", "database", "asset.tar.gz", "grype", "grype.json"}:
                raise GrypeRuntimeError("filesystem", filesystem_reason="root_unexpected")
            for name in ("home", "tmp", "cache"):
                if self.directory(self.path / name).names():
                    raise GrypeRuntimeError("filesystem", filesystem_reason={
                        "home": "home_nonempty", "tmp": "tmp_nonempty", "cache": "cache_unexpected",
                    }[name])

    def run_query(self, identifier, output):
        validate_identifier(identifier)
        if self.queries >= MAX_QUERIES:
            raise GrypeRuntimeError("query_budget")
        self.check_files()
        self.queries += 1
        output = Path(os.path.abspath(output))
        parent = Directory(output.parent)
        fd = None
        try:
            fd = parent.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            original = identity(os.fstat(fd))
            raw = self.command(["--platform", self.platform, "-o", "json", identifier], output_fd=fd)
            if identity(parent.entry(output.name)) != original:
                raise GrypeRuntimeError("identity_changed")
            output_guard = FileGuard(parent, output.name, limit=MAX_JSON, deadline=self.deadline)
            try:
                if output_guard.sha256 != hashlib.sha256(raw).hexdigest():
                    raise GrypeRuntimeError("identity_changed")
            finally:
                output_guard.close()
            report = decode_json(raw)
            descriptor = report.get("descriptor")
            if not isinstance(descriptor, dict) or descriptor.get("name") != "grype" or \
                    descriptor.get("version") != VERSION:
                raise GrypeRuntimeError("version")
            config = descriptor.get("configuration")
            validate_configuration(config, self.cache, self.platform)
            if self.configuration is not None and config != self.configuration:
                raise GrypeRuntimeError("config")
            db = descriptor.get("db")
            if not isinstance(db, dict) or db.get("status") != self.database_status or \
                    not isinstance(db.get("providers"), dict) or \
                    not db["providers"]:
                raise GrypeRuntimeError("database")
            self.check_files()
            self.configuration = json.loads(canonical(config))
            self.configuration_bytes = canonical(self.configuration)
            return report
        finally:
            if fd is not None:
                os.close(fd)
            parent.close()

    def assert_unchanged(self):
        self.check_files()
        if self.configuration is None:
            raise GrypeRuntimeError("configuration_unobserved")
        return {"tool": {"name": "grype", "version": VERSION, "release_commit": COMMIT,
                         "archive_sha256": self.archive_guard.sha256, "binary_sha256": self.binary_guard.sha256},
                "manifest_sha256": self.source_guards[0].sha256,
                "config_template_sha256": self.source_guards[1].sha256, "config_sha256": self.config_guard.sha256,
                "configuration": json.loads(canonical(self.configuration)),
                "database": {"status": json.loads(canonical(self.database_status)), "fetched_at": self.fetched_at,
                             "digest": self.table_sha256, "files": json.loads(canonical(self.file_table))},
                "runtime_module_sha256": self.source_guards[2].sha256}

    def cleanup(self):
        if self.closed:
            return
        failed = False
        for guard in self.guards:
            try:
                guard.close()
            except OSError:
                failed = True
        for parent, name, expected, directory in reversed(self.created):
            try:
                value = parent.entry(name)
                if identity(value) != expected:
                    failed = True
                    continue
                if not directory:
                    parent.chmod(name, 0o600)
                parent.remove(name, directory)
            except FileNotFoundError:
                pass
            except (OSError, GrypeRuntimeError):
                failed = True
        for directory in reversed(self.directories):
            try:
                directory.close()
            except OSError:
                failed = True
        self.closed = True
        if failed:
            raise GrypeRuntimeError("owned_cleanup_failed")


@contextmanager
def prepared_grype(*, scratch_parent: Path, manifest_path: Path, config_path: Path, platform: str):
    handle = Runtime(scratch_parent, manifest_path, config_path, platform)
    try:
        handle.prepare()
        yield handle
    except BaseException as primary:
        try:
            handle.cleanup()
        except GrypeRuntimeError:
            primary.add_note("owned_cleanup_failed")
        if isinstance(primary, (OSError, tarfile.TarError)):
            converted = GrypeRuntimeError("filesystem", filesystem_reason="syscall")
            converted.prepare_phase = handle.prepare_phase
            raise converted from None
        raise
    else:
        handle.cleanup()
