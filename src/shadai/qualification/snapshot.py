"""Cold owned-volume archives: validate every path/link before importing."""

import builtins
import hashlib
import json
import os
import posixpath
import stat
import tarfile
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath

from shadai.qualification.schemas import QualificationError

EXPORT_STEPS = {
    "source_guard", "archive_open", "enumerate", "header", "metadata", "validate", "header_budget",
    "write", "file_close", "archive_close", "chmod", "reopen", "revalidate", "digest", "result", "cli_result",
    "unknown",
}
EXPORT_REASONS = {
    "operation_error", "source_guard", "file_budget", "path_guard", "metadata_guard", "object_guard",
    "metadata_duplicate_name", "metadata_mode", "metadata_uid", "metadata_gid", "metadata_size",
    "content_budget", "link_guard", "link_escape", "link_cycle", "hardlink_missing", "hardlink_nonregular",
    "header_budget", "diagnostic_unavailable",
}
EXPORT_DIAGNOSTIC_LIMIT = 768
_EXPORT_CONTEXT = ContextVar("qualification_export_diagnostic", default=None)


def closed_export_point(value):
    return (type(value) is dict and all(type(key) is str for key in value)
            and set(value) == {"step", "reason"} and type(value["step"]) is str
            and value["step"] in EXPORT_STEPS and type(value["reason"]) is str
            and value["reason"] in EXPORT_REASONS)


def closed_export_diagnostic(value):
    return (type(value) is dict and all(type(key) is str for key in value)
            and set(value) == {"schema", "status", "step", "reason", "secondary"}
            and type(value["schema"]) is int and value["schema"] == 1
            and type(value["status"]) is str and value["status"] == "not_evaluated"
            and closed_export_point({"step": value["step"], "reason": value["reason"]})
            and type(value["secondary"]) is list and len(value["secondary"]) <= 1
            and all(closed_export_point(item) for item in value["secondary"]))


def _unique_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def parse_export_diagnostic(raw):
    unavailable = {"schema": 1, "status": "not_evaluated", "step": "unknown",
                   "reason": "diagnostic_unavailable", "secondary": []}
    if type(raw) is not str or len(raw) > EXPORT_DIAGNOSTIC_LIMIT or not raw.isascii():
        return unavailable
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json)
        return value if closed_export_diagnostic(value) else unavailable
    except (ValueError, TypeError, UnicodeError):
        return unavailable


class ExportDiagnostic:
    """Scoped decision constants only; original exceptions never enter the envelope."""

    def __init__(self):
        self.step, self.reason = "cli_result", "operation_error"
        self.primary = self.secondary = self.exception = None

    def capture(self, exc):
        point = {"step": self.step, "reason": self.reason}
        if not closed_export_point(point):
            point = {"step": "unknown", "reason": "diagnostic_unavailable"}
        if self.primary is None:
            self.primary, self.exception = point, exc
        elif exc is not self.exception and self.secondary is None:
            self.secondary = point

    def envelope(self):
        primary = self.primary if closed_export_point(self.primary) else {
            "step": "cli_result", "reason": "operation_error"}
        secondary = [self.secondary] if closed_export_point(self.secondary) else []
        return {"schema": 1, "status": "not_evaluated", **primary, "secondary": secondary}

    def print(self, *args, **kwargs):
        # runpy injects this name into its private module namespace, never builtins.
        if len(args) == 1 and not kwargs and type(args[0]) is str and len(args[0]) <= EXPORT_DIAGNOSTIC_LIMIT:
            try:
                value = json.loads(args[0], object_pairs_hook=_unique_json)
                names = {"QualificationError", "AssertionError", "ValueError", "TypeError", "KeyError",
                         "JSONDecodeError", "PermissionError", "FileNotFoundError", "OSError", "RuntimeError"}
                if (type(value) is dict and all(type(key) is str for key in value)
                        and set(value) == {"schema", "status", "reason", "exit_code"}
                        and type(value["schema"]) is int and value["schema"] == 1
                        and type(value["status"]) is str and value["status"] == "not_evaluated"
                        and type(value["reason"]) is str and value["reason"] in names
                        and type(value["exit_code"]) is int and value["exit_code"] == 2):
                    envelope = self.envelope()
                    if not closed_export_diagnostic(envelope):
                        envelope = parse_export_diagnostic("")
                    raw = json.dumps(envelope, separators=(",", ":"), ensure_ascii=True)
                    if len(raw) + 1 <= EXPORT_DIAGNOSTIC_LIMIT:
                        try:
                            builtins.print(raw)
                        except Exception:
                            pass
                        return
            except Exception:
                pass
        return builtins.print(*args, **kwargs)


@contextmanager
def export_diagnostics():
    diagnostic = ExportDiagnostic()
    token = _EXPORT_CONTEXT.set(diagnostic)
    try:
        yield diagnostic
    finally:
        _EXPORT_CONTEXT.reset(token)


def export_checkpoint(step):
    diagnostic = _EXPORT_CONTEXT.get()
    if type(diagnostic) is ExportDiagnostic:
        diagnostic.step = step if type(step) is str and step in EXPORT_STEPS else "unknown"
        diagnostic.reason = "operation_error"


def export_refusal(reason):
    diagnostic = _EXPORT_CONTEXT.get()
    if type(diagnostic) is ExportDiagnostic:
        diagnostic.reason = reason if type(reason) is str and reason in EXPORT_REASONS else "diagnostic_unavailable"


@contextmanager
def export_capture(cleanup_step=None):
    try:
        yield
    except BaseException as exc:
        # Pure best-effort capture cannot replace the exception currently propagating.
        try:
            diagnostic = _EXPORT_CONTEXT.get()
            if type(diagnostic) is ExportDiagnostic:
                diagnostic.capture(exc)
        except BaseException:
            pass
        raise
    finally:
        if cleanup_step is not None:
            try:
                export_checkpoint(cleanup_step)
            except BaseException:
                pass


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as file, export_capture("file_close"):
        for block in iter(lambda: file.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\0" in name:
        export_refusal("path_guard")
        raise QualificationError("Archive path can escape the owned volume")
    return str(path)


def _allowed_archive_mode(item):
    mode = item.mode
    if type(mode) is not int or mode < 0 or mode > 0o3777:
        return False
    if mode <= 0o777:
        return True
    if type(item) is not tarfile.TarInfo:
        return False
    kind = item.type
    return type(kind) is bytes and kind == tarfile.DIRTYPE


def validate_members(members, max_bytes):
    if len(members) > 100000:
        export_refusal("file_budget")
        raise QualificationError("Archive exceeds file budget")
    total, names, links = 0, set(), {}
    for item in members:
        name = safe_name(item.name)
        if (
            (metadata_duplicate := name in names)
            or (metadata_mode := not _allowed_archive_mode(item))
            or (metadata_uid := (False if 0 <= item.uid < 2**32 - 1 else True))
            or (metadata_gid := (False if 0 <= item.gid < 2**32 - 1 else True))
            or item.size < 0
        ):
            export_refusal(
                "metadata_duplicate_name" if metadata_duplicate else
                "metadata_mode" if metadata_mode else
                "metadata_uid" if metadata_uid else
                "metadata_gid" if metadata_gid else "metadata_size"
            )
            raise QualificationError("Duplicate or unsafe archive metadata")
        names.add(name)
        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
            export_refusal("object_guard")
            raise QualificationError("Unsupported archive object")
        total += item.size
        if total > max_bytes:
            export_refusal("content_budget")
            raise QualificationError("Archive exceeds disk budget")
        if item.issym() or item.islnk():
            if not item.linkname or PurePosixPath(item.linkname).is_absolute() or "\\" in item.linkname:
                export_refusal("link_guard")
                raise QualificationError("Unsafe archive link")
            base = posixpath.dirname(name) if item.issym() else ""
            target = posixpath.normpath(posixpath.join(base, item.linkname))
            if target == ".." or target.startswith("../") or target.startswith("/"):
                export_refusal("link_escape")
                raise QualificationError("Archive link escapes the owned volume")
            links[name] = target

    # Resolve transitive links and links in parent directories, not only a link's
    # immediate lexical target. A ClickHouse data -> ../../store link is valid.
    def resolve(name, trail=()):
        if len(trail) > 100:
            export_refusal("link_cycle")
            raise QualificationError("Archive link cycle")
        parts = PurePosixPath(name).parts
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            if prefix in links:
                if prefix in trail:
                    export_refusal("link_cycle")
                    raise QualificationError("Archive link cycle")
                suffix = "/".join(parts[length:])
                return resolve(posixpath.normpath(posixpath.join(links[prefix], suffix)), (*trail, prefix))
        return name

    for item in members:
        resolved = resolve(safe_name(item.name))
        safe_name(resolved)
        if item.islnk() and resolve(links[item.name]) not in names:
            export_refusal("hardlink_missing")
            raise QualificationError("Archive hardlink target is absent")
        if item.islnk():
            target = next(entry for entry in members if safe_name(entry.name) == resolve(links[item.name]))
            if not target.isfile():
                export_refusal("hardlink_nonregular")
                raise QualificationError("Hardlinks must reference regular archive files")
    return total


def export_volume(source, archive, max_bytes):
    with export_capture():
        export_checkpoint("source_guard")
        root, archive = Path(source), Path(archive)
        if root.is_symlink() or not root.is_dir() or archive.exists():
            export_refusal("source_guard")
            raise QualificationError("Source must exist and archive must be new")
        export_checkpoint("archive_open")
        with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output, export_capture("archive_close"):
            export_checkpoint("enumerate")
            paths = [root]
            for directory, directories, files in os.walk(root, followlinks=False):
                paths.extend(Path(directory) / name for name in sorted([*directories, *files]))
            export_checkpoint("header")
            members = [
                output.gettarinfo(str(path), arcname=str(path.relative_to(root)).replace("\\", "/")) for path in paths
            ]
            export_checkpoint("metadata")
            for item in members:
                item.mode = stat.S_IMODE(item.mode)  # gettarinfo includes native file-type bits before serialization.
            export_checkpoint("validate")
            validate_members(members, max_bytes)
            export_checkpoint("header_budget")
            estimate = (
                sum(len(item.tobuf(format=tarfile.PAX_FORMAT)) + ((item.size + 511) // 512) * 512 for item in members)
                + 10240
            )
            if estimate > max_bytes + 10485760:
                export_refusal("header_budget")
                raise QualificationError("Archive metadata exceeds disk budget")
            for path, item in zip(paths, members, strict=True):
                export_checkpoint("write")
                if item.isfile():
                    with path.open("rb") as file, export_capture("file_close"):
                        output.addfile(item, file)
                else:
                    output.addfile(item)
        export_checkpoint("chmod")
        archive.chmod(0o600)
        export_checkpoint("reopen")
        with tarfile.open(archive, "r") as check, export_capture("archive_close"):
            export_checkpoint("revalidate")
            size = validate_members(check.getmembers(), max_bytes)
        export_checkpoint("digest")
        sha256 = digest_file(archive)
        export_checkpoint("result")
        result = {
            "schema": 1,
            "sha256": sha256,
            "bytes": archive.stat().st_size,
            "unpacked_bytes": size,
            "archive": archive.name,
        }
        export_checkpoint("cli_result")
        return result


def import_volume(archive, destination, expected_hash, max_bytes):
    root, archive = Path(destination), Path(archive)
    if root.is_symlink() or not root.is_dir() or any(root.iterdir()) or archive.stat().st_size > max_bytes + 10485760:
        raise QualificationError("Restore volume must be new and empty, archive bounded")
    if digest_file(archive) != expected_hash:
        raise QualificationError("Cold archive hash mismatch")
    with tarfile.open(archive, "r:") as source:
        members, total = [], 0
        for item in source:
            members.append(item)
            total += item.size
            if len(members) > 100000 or total > max_bytes:
                raise QualificationError("Archive header exceeds file/disk budget")
        validate_members(members, max_bytes)  # No destination writes before validation.
        # Extract with private root ownership first. Restore ownership/modes in
        # postorder; writing through a prematurely chowned 0700 directory is avoided.
        source.extractall(root, members=members, numeric_owner=False, filter=lambda item, _: root_owned(item))
        for item in sorted(members, key=lambda member: len(PurePosixPath(member.name).parts), reverse=True):
            path = root / item.name
            os.chown(path, item.uid, item.gid, follow_symlinks=False)
            if not item.issym():
                os.chmod(path, item.mode)


def root_owned(item):
    import copy

    result = copy.copy(item)
    result.uid, result.gid, result.uname, result.gname = None, None, None, None
    if not result.issym():
        result.mode = 0o700 if result.isdir() else 0o600
    return result
