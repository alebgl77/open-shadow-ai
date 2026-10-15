"""Read-only, finite CI failure metadata; never a qualification acceptance proof."""

import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

from shadai.qualification.lab import DOCKER_FAILURE_CODES, FAILURE_STAGES
from shadai.qualification.schemas import SCENARIOS, canonical_bytes, validate_profile

# Reports contain private measurements. A larger legitimate report is deliberately
# unavailable: diagnostics may consume at most 2 MiB per input, before allocation.
MAX_METADATA_BYTES = 2 * 1048576
PROFILE = Path("deploy/qualification/profiles/lab-smoke.json")
COMPOSE = Path("deploy/qualification/compose.yaml")
FIELDS = ("state", "phase", "stage", "error_type", "code")
PHASES = {item: item for item in SCENARIOS | {"created", "starting", "initialized", "unknown"}}
STAGES = {item: item for item in FAILURE_STAGES | {"unknown"}}
ERROR_TYPES = {item: item for item in (
    "DockerOperationError", "QualificationError", "AssertionError", "ValueError", "TypeError", "KeyError",
    "JSONDecodeError", "PermissionError", "FileNotFoundError", "OSError", "RuntimeError", "KeyboardInterrupt",
    "SystemExit", "TimeoutExpired", "UnexpectedError",
)}
CODES = {item: item for item in DOCKER_FAILURE_CODES | {"qualification_error", "exception"}}
UNAVAILABLE = {
    "state": "unavailable", "phase": "unknown", "stage": "unknown",
    "error_type": "UnexpectedError", "code": "exception",
}


class _UnavailableError(ValueError):
    """An input cannot produce a diagnostic; exception text is never published."""


def _require(condition):
    if not condition:
        raise _UnavailableError


def _object(value):
    # Validate keys before any lookup/equality: foreign keys can run callbacks.
    _require(type(value) is dict)
    _require(all(type(key) is str for key in value))
    return value


def _text(value, pattern):
    _require(type(value) is str)
    _require(re.fullmatch(pattern, value) is not None)
    return value


def _choice(value, choices):
    _require(type(value) is str)
    _require(value in choices)
    # Return the source whitelist's literal, never the supplied object's value.
    return choices[value]


def project_failure(report, journal, source, *, revision, profile_sha256, config_sha256):
    """Project only closed values after binding all required private identities."""
    try:
        _text(revision, r"[0-9a-f]{40}")
        _text(profile_sha256, r"[0-9a-f]{64}")
        _text(config_sha256, r"[0-9a-f]{64}")
        _object(report)
        _object(journal)
        _require(type(report.get("schema")) is int and report["schema"] == 1)
        _require(type(journal.get("schema")) is int and journal["schema"] == 1)
        _require(type(report.get("scope")) is str and report["scope"] == "disposable_lab")
        _require(type(report.get("exit_code")) is int and report["exit_code"] in {1, 2})
        _require(_text(report.get("profile_sha256"), r"[0-9a-f]{64}") == profile_sha256)
        _require(_text(journal.get("profile_sha256"), r"[0-9a-f]{64}") == profile_sha256)
        _require(_text(journal.get("config_sha256"), r"[0-9a-f]{64}") == config_sha256)
        _require(type(journal.get("context")) is str and journal["context"] == "default")
        run_id = _text(journal.get("run_id"), r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
        evidence = _object(report.get("evidence"))
        _require(type(evidence.get("run_id")) is str and evidence["run_id"] == run_id)
        _require(type(evidence.get("installation")) is str
                 and evidence["installation"] == "q-" + run_id.replace("-", ""))
        for item in (source, evidence.get("source")):
            item = _object(item)
            _require(_text(item.get("revision"), r"[0-9a-f]{40}") == revision)
            environment = _object(item.get("environment"))
            _require(type(environment.get("docker_context")) is str and environment["docker_context"] == "default")
        failure = _object(evidence.get("failure"))
        return {
            "state": "available",
            "phase": _choice(failure.get("phase"), PHASES),
            "stage": _choice(failure.get("stage"), STAGES),
            "error_type": _choice(failure.get("error_type"), ERROR_TYPES),
            "code": _choice(failure.get("code"), CODES),
        }
    except _UnavailableError:
        return UNAVAILABLE.copy()


def render_metadata(value):
    """Independently close the output boundary, including direct Python callers."""
    try:
        _object(value)
        _require(value.keys() == set(FIELDS))
        state = _choice(value["state"], {"available": "available", "unavailable": "unavailable"})
        closed = {"state": state}
        for key, choices in (("phase", PHASES), ("stage", STAGES), ("error_type", ERROR_TYPES), ("code", CODES)):
            closed[key] = _choice(value[key], choices)
        if state == "unavailable":
            _require(closed == UNAVAILABLE)
    except _UnavailableError:
        closed = UNAVAILABLE
    return "".join(key + "=" + closed[key] + "\n" for key in FIELDS)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _file_stamp(info):
    return (*_identity(info), info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _not_link(info):
    _require(not stat.S_ISLNK(info.st_mode))
    _require(not getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _owned(info, *, private):
    if os.name == "posix":
        _require(info.st_uid == os.getuid())
        if private:
            _require(not info.st_mode & 0o077)


class _Snapshot:
    """Keep descriptors held and distinguish descriptor clocks from path clocks."""

    def __init__(self):
        self.stack = ExitStack()
        self.directories = {}
        self.files = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def directory(self, path, *, private=False):
        for ancestor in (*reversed(path.parents), path):
            info = ancestor.lstat()
            _not_link(info)
            _require(stat.S_ISDIR(info.st_mode))
            previous = self.directories.setdefault(ancestor, _identity(info))
            _require(_identity(info) == previous)
            if ancestor == path:
                _owned(info, private=private)

    def read(self, path, *, private=False, maximum=MAX_METADATA_BYTES):
        self.directory(path.parent, private=private)
        before = path.lstat()
        self._regular(before, private, maximum)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        self.stack.enter_context(stream)
        held = os.fstat(stream.fileno())
        self._regular(held, private, maximum)
        _require(_identity(before) == _identity(held) and before.st_size == held.st_size)
        # The two stat APIs can expose different clocks on Windows. Compare each
        # API to its own baseline while binding their common object identity.
        self.files.append((path, stream, _file_stamp(before), _file_stamp(held), private, maximum))
        self.verify()
        raw = stream.read(maximum + 1)
        _require(len(raw) <= maximum)
        self.verify()
        return raw

    @staticmethod
    def _regular(info, private, maximum):
        _not_link(info)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum)
        _owned(info, private=private)

    def verify(self):
        for path, identity in self.directories.items():
            info = path.lstat()
            _not_link(info)
            _require(_identity(info) == identity)
        for path, stream, path_stamp, fd_stamp, private, maximum in self.files:
            current_path, current_fd = path.lstat(), os.fstat(stream.fileno())
            self._regular(current_path, private, maximum)
            self._regular(current_fd, private, maximum)
            _require(_file_stamp(current_path) == path_stamp and _file_stamp(current_fd) == fd_stamp)


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    def finite(value):
        number = float(value)
        _require(math.isfinite(number))
        return number

    def reject(_):
        raise _UnavailableError

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject, parse_float=finite)


def _head_revision(repository):
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, capture_output=True, text=True, timeout=5)
    _require(type(result.returncode) is int and result.returncode == 0)
    _require(type(result.stdout) is str and len(result.stdout) <= 41)
    return _text(result.stdout.strip(), r"[0-9a-f]{40}")


def collect_metadata(repository, *, home, run_id, run_attempt, github_sha):
    """Read only the fixed current-attempt directory and checked-out public inputs."""
    try:
        _require(type(repository) is type(Path()))
        _require(type(home) is str)
        home_path = Path(home)
        _require(home_path.is_absolute() and ".." not in home_path.parts)
        _text(run_id, r"[1-9][0-9]{0,19}")
        _text(run_attempt, r"[1-9][0-9]{0,9}")
        _text(github_sha, r"[0-9a-f]{40}")
        _require(_head_revision(repository) == github_sha)
        run_path = home_path / ("shadai-qualification-" + run_id + "-" + run_attempt)
        with _Snapshot() as snapshot:
            snapshot.directory(run_path, private=True)
            profile = validate_profile(_json(snapshot.read(repository / PROFILE, maximum=65536)))
            _require(profile["scope"] == "disposable_lab")
            profile_bytes = canonical_bytes(profile)
            config = snapshot.read(repository / COMPOSE)
            result = project_failure(
                _json(snapshot.read(run_path / "report.json", private=True)),
                _json(snapshot.read(run_path / "journal.json", private=True)),
                _json(snapshot.read(run_path / "source.json", private=True)),
                revision=github_sha,
                profile_sha256=hashlib.sha256(profile_bytes).hexdigest(),
                config_sha256=hashlib.sha256(config + profile_bytes).hexdigest(),
            )
            snapshot.verify()
            _require(_head_revision(repository) == github_sha)
            return result
    except Exception:
        # No repr, str, traceback, path or captured command output crosses here.
        return UNAVAILABLE.copy()


def main(argv=None, *, repository=None):
    """Quiet fixed CLI protocol; even malformed arguments get the same fallback."""
    result = UNAVAILABLE
    try:
        values = sys.argv[1:] if argv is None else argv
        _require(type(values) is list and len(values) == 8 and all(type(item) is str for item in values))
        _require(values[::2] == ["--home", "--run-id", "--run-attempt", "--github-sha"])
        result = collect_metadata(
            Path(__file__).resolve().parents[3] if repository is None else repository,
            home=values[1], run_id=values[3], run_attempt=values[5], github_sha=values[7],
        )
    except Exception:
        pass
    sys.stdout.write(render_metadata(result))
    return 0
