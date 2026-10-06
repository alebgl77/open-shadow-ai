"""Cold owned-volume archives: validate every path/link before importing."""

import hashlib
import os
import posixpath
import stat
import tarfile
from pathlib import Path, PurePosixPath

from shadai.qualification.schemas import QualificationError


def digest_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as file:
        for block in iter(lambda: file.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or "\\" in name or "\0" in name:
        raise QualificationError("Archive path can escape the owned volume")
    return str(path)


def validate_members(members, max_bytes):
    if len(members) > 100000:
        raise QualificationError("Archive exceeds file budget")
    total, names, links = 0, set(), {}
    for item in members:
        name = safe_name(item.name)
        if (
            name in names
            or not 0 <= item.mode <= 0o777
            or not 0 <= item.uid < 2**32 - 1
            or not 0 <= item.gid < 2**32 - 1
            or item.size < 0
        ):
            raise QualificationError("Duplicate or unsafe archive metadata")
        names.add(name)
        if not (item.isfile() or item.isdir() or item.issym() or item.islnk()):
            raise QualificationError("Unsupported archive object")
        total += item.size
        if total > max_bytes:
            raise QualificationError("Archive exceeds disk budget")
        if item.issym() or item.islnk():
            if not item.linkname or PurePosixPath(item.linkname).is_absolute() or "\\" in item.linkname:
                raise QualificationError("Unsafe archive link")
            base = posixpath.dirname(name) if item.issym() else ""
            target = posixpath.normpath(posixpath.join(base, item.linkname))
            if target == ".." or target.startswith("../") or target.startswith("/"):
                raise QualificationError("Archive link escapes the owned volume")
            links[name] = target

    # Resolve transitive links and links in parent directories, not only a link's
    # immediate lexical target. A ClickHouse data -> ../../store link is valid.
    def resolve(name, trail=()):
        if len(trail) > 100:
            raise QualificationError("Archive link cycle")
        parts = PurePosixPath(name).parts
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            if prefix in links:
                if prefix in trail:
                    raise QualificationError("Archive link cycle")
                suffix = "/".join(parts[length:])
                return resolve(posixpath.normpath(posixpath.join(links[prefix], suffix)), (*trail, prefix))
        return name

    for item in members:
        resolved = resolve(safe_name(item.name))
        safe_name(resolved)
        if item.islnk() and resolve(links[item.name]) not in names:
            raise QualificationError("Archive hardlink target is absent")
        if item.islnk():
            target = next(entry for entry in members if safe_name(entry.name) == resolve(links[item.name]))
            if not target.isfile():
                raise QualificationError("Hardlinks must reference regular archive files")
    return total


def export_volume(source, archive, max_bytes):
    root, archive = Path(source), Path(archive)
    if root.is_symlink() or not root.is_dir() or archive.exists():
        raise QualificationError("Source must exist and archive must be new")
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
        paths = [root]
        for directory, directories, files in os.walk(root, followlinks=False):
            paths.extend(Path(directory) / name for name in sorted([*directories, *files]))
        members = [
            output.gettarinfo(str(path), arcname=str(path.relative_to(root)).replace("\\", "/")) for path in paths
        ]
        for item in members:
            item.mode = stat.S_IMODE(item.mode)  # gettarinfo includes native file-type bits before serialization.
        validate_members(members, max_bytes)
        estimate = (
            sum(len(item.tobuf(format=tarfile.PAX_FORMAT)) + ((item.size + 511) // 512) * 512 for item in members)
            + 10240
        )
        if estimate > max_bytes + 10485760:
            raise QualificationError("Archive metadata exceeds disk budget")
        for path, item in zip(paths, members, strict=True):
            if item.isfile():
                with path.open("rb") as file:
                    output.addfile(item, file)
            else:
                output.addfile(item)
    archive.chmod(0o600)
    with tarfile.open(archive, "r") as check:
        size = validate_members(check.getmembers(), max_bytes)
    return {
        "schema": 1,
        "sha256": digest_file(archive),
        "bytes": archive.stat().st_size,
        "unpacked_bytes": size,
        "archive": archive.name,
    }


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
