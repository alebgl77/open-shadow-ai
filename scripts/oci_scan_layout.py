"""Prepare an unchanged, verified OCI directory for Trivy's archive reader."""

import hashlib
import importlib.util
import json
import os
import re
import stat
import tarfile
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID, uuid4

CHUNK = 1024 * 1024
MAX_ARCHIVE = 4 * 1024**3
MAX_TOTAL = 4 * 1024**3
MAX_FILE = 2 * 1024**3
MAX_JSON = 128 * 1024**2
MAX_MEMBERS = 100_000
HEX = re.compile(r"[a-f0-9]{64}\Z")
ANCHORED = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)
BINARY = getattr(os, "O_BINARY", 0)


class CleanupError(ValueError):
    pass


def identity(value):
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def unchanged(before, after):
    return identity(before) == identity(after) and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def safe_stat(path):
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or getattr(path, "is_junction", lambda: False)():
        raise ValueError("OCI path contains a link or junction")
    return value


class Directory:
    """Keep each observed ancestor pinned; use dir_fd operations where available."""

    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.chain = []
        self.fd = None
        current = Path(self.path.anchor)
        try:
            for part in (None, *self.path.parts[1:]):
                parent_fd = self.fd
                if part is not None:
                    current = current / part
                before = safe_stat(current)
                if not stat.S_ISDIR(before.st_mode):
                    raise ValueError("OCI parent must be a directory")
                fd = None
                if ANCHORED:
                    fd = os.open(current if part is None else part,
                                 os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent_fd)
                    if identity(os.fstat(fd)) != identity(before):
                        os.close(fd)
                        raise ValueError("OCI directory changed while opening")
                self.chain.append((current, identity(before), fd))
                self.fd = fd
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for path, expected, fd in self.chain:
            if identity(safe_stat(path)) != expected or fd is not None and identity(os.fstat(fd)) != expected:
                raise ValueError("OCI directory identity changed")

    def entry_stat(self, name):
        self.check()
        if ANCHORED:
            value = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if stat.S_ISLNK(value.st_mode):
                raise ValueError("OCI entry is a link")
            return value
        return safe_stat(self.path / name)

    def open(self, name, flags, mode=0o600):
        self.check()
        fd = os.open(name if ANCHORED else self.path / name, flags | NOFOLLOW | NONBLOCK | BINARY, mode,
                     **({"dir_fd": self.fd} if ANCHORED else {}))
        try:
            value = os.fstat(fd)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or \
                    identity(value) != identity(self.entry_stat(name)):
                raise ValueError("OCI file must be an unchanged regular file")
            self.check()
            return fd
        except BaseException:
            os.close(fd)
            raise

    def mkdir(self, name):
        self.check()
        os.mkdir(name if ANCHORED else self.path / name, 0o700,
                 **({"dir_fd": self.fd} if ANCHORED else {}))
        return self.entry_stat(name)

    def remove(self, name, directory=False):
        self.check()
        function = os.rmdir if directory else os.unlink
        function(name if ANCHORED else self.path / name, **({"dir_fd": self.fd} if ANCHORED else {}))

    def names(self):
        self.check()
        return set(os.listdir(self.fd if ANCHORED else self.path))

    def close(self):
        for _, _, fd in reversed(self.chain):
            if fd is not None:
                os.close(fd)
        self.chain = []
        self.fd = None


def digest_fd(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("OCI file exceeds its byte budget")
    os.lseek(fd, 0, os.SEEK_SET)
    checksum, size = hashlib.sha256(), 0
    while chunk := os.read(fd, CHUNK):
        size += len(chunk)
        if size > limit:
            raise ValueError("OCI file exceeds its byte budget")
        checksum.update(chunk)
    if size != before.st_size or not unchanged(before, os.fstat(fd)):
        raise ValueError("OCI file changed while hashing")
    return checksum.hexdigest()


def verifier():
    path = Path(__file__).with_name("verify-oci-evidence.py")
    spec = importlib.util.spec_from_file_location("oci_layout_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def member_name(member):
    name = member.name
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    if name in {"blobs", "blobs/sha256"}:
        if not member.isdir():
            raise ValueError("OCI fixed directory must be a directory")
    elif name in {"index.json", "oci-layout"} or \
            name.startswith("blobs/sha256/") and HEX.fullmatch(name[13:]):
        if not member.isfile():
            raise ValueError("OCI member must be a regular file")
    else:
        raise ValueError("Noncanonical OCI archive member")
    if member.size < 0 or member.size > MAX_FILE or member.isdir() and member.size or \
            name in {"index.json", "oci-layout"} and member.size > MAX_JSON:
        raise ValueError("OCI member exceeds its byte budget")
    return name


class RegularTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        # Reject hidden GNU/PAX/link records before tarfile allocates their
        # payload or uses them to change the next visible member's identity.
        if self.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise ValueError("OCI member must be a regular file or fixed directory")
        member_name(self)
        return super()._proc_member(archive)


def archive_members(archive):
    members, total = {}, 0
    for member in archive:
        name = member_name(member)
        if name in members or len(members) >= MAX_MEMBERS:
            raise ValueError("Duplicate or excessive OCI archive members")
        total += member.size
        if total > MAX_TOTAL:
            raise ValueError("OCI materialization exceeds its byte budget")
        members[name] = member
    return members


class Layout:
    def __init__(self, archive, workspace, source, platform, component):
        self.archive = Path(os.path.abspath(archive))
        self.workspace = Path(os.path.abspath(workspace))
        self.snapshot = self.workspace / "snapshot.oci.tar"
        self.layout = self.workspace / "layout"
        self.expected_source = dict(source)
        self.platform = platform
        self.component = component
        self.directories = []
        self.created = []
        self.files = {}
        self.evidence = None
        self.closed = False
        self.cleanup_refused = False

    @property
    def layout_path(self):
        return self.layout

    container_input = "/input/layout"

    @property
    def selected_image_manifest(self):
        return self.evidence["image_manifests"][0]

    @property
    def file_map_sha256(self):
        return self.table_sha256

    def assert_unchanged(self):
        return check(self)

    def directory(self, path):
        value = Directory(path)
        self.directories.append(value)
        return value

    def create_dir(self, parent, name):
        value = parent.mkdir(name)
        self.created.append((parent, name, identity(value), True))
        if os.name == "posix" and stat.S_IMODE(value.st_mode) != 0o700:
            raise ValueError("OCI workspace directory is not private")
        return self.directory(parent.path / name)

    def create_file(self, parent, name, source, limit):
        fd = parent.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        value = os.fstat(fd)
        self.created.append((parent, name, identity(value), False))
        checksum, size = hashlib.sha256(), 0
        try:
            if os.name == "posix" and stat.S_IMODE(value.st_mode) != 0o600:
                raise ValueError("OCI workspace file is not private")
            while chunk := source.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise ValueError("OCI streamed file exceeds its byte budget")
                checksum.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(fd, view)
                    if not written:
                        raise ValueError("OCI short file write")
                    view = view[written:]
            os.fsync(fd)
            if identity(parent.entry_stat(name)) != identity(value):
                raise ValueError("OCI created file was replaced")
        finally:
            os.close(fd)
        return {"size": size, "sha256": checksum.hexdigest(), "identity": identity(value),
                "parent": parent, "name": name}


def read_document(handle, name):
    record = handle.files[name]
    fd = record["parent"].open(record["name"], os.O_RDONLY)
    try:
        if record["size"] > MAX_JSON or identity(os.fstat(fd)) != record["identity"]:
            raise ValueError("OCI JSON budget or identity mismatch")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(record["size"] + 1)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("OCI JSON bytes changed")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("OCI document must be an object")
        return value
    finally:
        os.close(fd)


def first_manifest(handle, module):
    """Match Trivy 0.75: recurse down index manifests[0], without filtering."""
    document, depth = read_document(handle, "index.json"), 0
    while True:
        depth += 1
        if depth > module.MAX_DEPTH + 1:
            raise ValueError("OCI first descriptor path exceeds graph depth")
        entries = document.get("manifests")
        if not isinstance(entries, list) or not entries:
            raise ValueError("OCI first descriptor path is empty")
        entry = entries[0]
        if entry["mediaType"] in module.MANIFEST_TYPES:
            return entry["digest"][7:]
        if entry["mediaType"] not in module.INDEX_TYPES:
            raise ValueError("OCI first descriptor path is not runnable")
        document = read_document(handle, "blobs/sha256/" + entry["digest"][7:])


def prepare(*, archive, workspace, expected_source, expected_platform, expected_component):
    if not isinstance(expected_source, dict) or set(expected_source) != {"commit", "repository"} or \
            not isinstance(expected_source["commit"], str) or \
            not re.fullmatch(r"[a-f0-9]{40}", expected_source["commit"]) or \
            not isinstance(expected_source["repository"], str) or not expected_source["repository"] or \
            expected_platform not in {"linux/amd64", "linux/arm64"} or \
            not isinstance(expected_component, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", expected_component):
        raise ValueError("Invalid OCI source, platform or component expectation")
    # The caller supplies an exclusive, UUID-named workspace outside uploaded proof.
    workspace = Path(workspace)
    try:
        suffix = re.search(r"(?:[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$", workspace.name)
        UUID(suffix[0] if suffix else "")
    except ValueError:
        raise ValueError("OCI workspace requires a UUID suffix") from None
    handle = Layout(archive, workspace, expected_source, expected_platform, expected_component)
    try:
        source_parent = handle.directory(handle.archive.parent)
        source_fd = source_parent.open(handle.archive.name, os.O_RDONLY)
        try:
            handle.source_identity = identity(os.fstat(source_fd))
            # Windows fstat exposes a different ctime definition than lstat.
            # Keep pathname metadata comparisons within the same stat API.
            handle.source_stat = source_parent.entry_stat(handle.archive.name)
            before = digest_fd(source_fd, MAX_ARCHIVE)
            workspace_parent = handle.directory(handle.workspace.parent)
            private = handle.create_dir(workspace_parent, handle.workspace.name)
            os.lseek(source_fd, 0, os.SEEK_SET)
            with os.fdopen(source_fd, "rb", closefd=False) as source:
                handle.snapshot_record = handle.create_file(private, handle.snapshot.name, source, MAX_ARCHIVE)
            if before != handle.snapshot_record["sha256"] or before != digest_fd(source_fd, MAX_ARCHIVE) or \
                    not unchanged(handle.source_stat, source_parent.entry_stat(handle.archive.name)):
                raise ValueError("OCI source changed during snapshot")
            handle.archive_sha256 = before
        finally:
            os.close(source_fd)
        snapshot_fd = private.open(handle.snapshot.name, os.O_RDONLY)
        try:
            handle.snapshot_stat = os.fstat(snapshot_fd)
            with os.fdopen(snapshot_fd, "rb", closefd=False) as source, \
                    tarfile.open(fileobj=source, mode="r:*", tarinfo=RegularTarInfo) as bundle:
                members = archive_members(bundle)
            module = verifier()
            handle.evidence = module.verify(handle.snapshot, platform=expected_platform, include_sbom=True)
            if handle.evidence["archive_sha256"] != before or len(handle.evidence["image_manifests"]) != 1:
                raise ValueError("OCI scan requires one unchanged native runnable manifest")
            layout = handle.create_dir(private, "layout")
            blobs = handle.create_dir(layout, "blobs")
            sha256 = handle.create_dir(blobs, "sha256")
            os.lseek(snapshot_fd, 0, os.SEEK_SET)
            with os.fdopen(snapshot_fd, "rb", closefd=False) as source, \
                    tarfile.open(fileobj=source, mode="r:*", tarinfo=RegularTarInfo) as bundle:
                for name, member in members.items():
                    if member.isdir():
                        continue
                    with bundle.extractfile(member) as entry:
                        parent = sha256 if name.startswith("blobs/") else layout
                        handle.files[name] = handle.create_file(parent, name.rsplit("/", 1)[-1], entry, member.size)
                    if handle.files[name]["size"] != member.size:
                        raise ValueError("OCI archive member was truncated")
                    if name.startswith("blobs/sha256/") and handle.files[name]["sha256"] != name[13:]:
                        raise ValueError("OCI materialized blob SHA256 mismatch")
            if not unchanged(handle.snapshot_stat, os.fstat(snapshot_fd)):
                raise ValueError("OCI snapshot changed during materialization")
            if first_manifest(handle, module) != handle.evidence["image_manifests"][0]:
                raise ValueError("Trivy first descriptor is not the unique verified runnable manifest")
        finally:
            os.close(snapshot_fd)
        helper = Path(__file__).absolute()
        helper_parent = handle.directory(helper.parent)
        handle.helper_record = (helper_parent, helper.name)
        helper_fd = helper_parent.open(helper.name, os.O_RDONLY)
        try:
            handle.helper_sha256 = digest_fd(helper_fd, MAX_JSON)
        finally:
            os.close(helper_fd)
        handle.table_sha256 = table_digest(handle)
        check(handle)
        return handle
    except BaseException as primary:
        cleanup_preserving(handle, primary)
        raise


def checked_digest(parent, name, expected, limit, reference=None):
    fd = parent.open(name, os.O_RDONLY)
    try:
        if identity(os.fstat(fd)) != expected:
            raise ValueError("OCI tracked file identity changed")
        if reference is not None and not unchanged(reference, os.fstat(fd)):
            raise ValueError("OCI snapshot metadata changed")
        result = digest_fd(fd, limit)
        if identity(parent.entry_stat(name)) != expected:
            raise ValueError("OCI tracked file was replaced while hashing")
        return result
    finally:
        os.close(fd)


def table_digest(handle):
    rows = []
    for name, record in sorted(handle.files.items()):
        digest = checked_digest(record["parent"], record["name"], record["identity"], MAX_FILE)
        if digest != record["sha256"] or record["parent"].entry_stat(record["name"]).st_size != record["size"]:
            raise ValueError("OCI materialized bytes changed")
        rows.append({"name": name, "size": record["size"], "sha256": digest})
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check(handle):
    if handle.closed:
        raise ValueError("OCI layout handle is closed")
    for directory in handle.directories:
        directory.check()
    expected_names = {}
    for parent, name, expected, _ in handle.created:
        if identity(parent.entry_stat(name)) != expected:
            raise ValueError("OCI tracked resource identity changed")
        expected_names.setdefault(parent.path, set()).add(name)
    for directory in handle.directories:
        if directory.path == handle.workspace or handle.workspace in directory.path.parents:
            if directory.names() != expected_names.get(directory.path, set()):
                raise ValueError("OCI workspace has unexpected entries")
    source_parent = handle.directories[0]
    if checked_digest(source_parent, handle.archive.name, handle.source_identity, MAX_ARCHIVE) != \
            handle.archive_sha256 or not unchanged(handle.source_stat, source_parent.entry_stat(handle.archive.name)):
        raise ValueError("OCI original archive changed")
    snapshot = handle.snapshot_record
    if checked_digest(snapshot["parent"], snapshot["name"], snapshot["identity"], MAX_ARCHIVE,
                      reference=handle.snapshot_stat) != \
            handle.archive_sha256:
        raise ValueError("OCI snapshot changed")
    helper_parent, helper_name = handle.helper_record
    fd = helper_parent.open(helper_name, os.O_RDONLY)
    try:
        if digest_fd(fd, MAX_JSON) != handle.helper_sha256:
            raise ValueError("OCI layout helper changed")
    finally:
        os.close(fd)
    if table_digest(handle) != handle.table_sha256:
        raise ValueError("OCI materialized file table changed")
    manifest = handle.evidence["image_manifests"][0]
    return {"archive_sha256": handle.archive_sha256, "layout_table_sha256": handle.table_sha256,
            "helper_sha256": handle.helper_sha256, "source": dict(handle.expected_source),
            "platform": handle.platform, "component": handle.component, "image_manifest": manifest,
            "image_config": handle.evidence["image_configs"][manifest]}


def cleanup(handle):
    """Remove only creations whose observed ancestry and inode are unchanged."""
    if handle.closed:
        return
    for parent, name, expected, directory in reversed(handle.created):
        try:
            if identity(parent.entry_stat(name)) == expected:
                parent.remove(name, directory)
            else:
                handle.cleanup_refused = True
        except (OSError, ValueError):
            # Preserve a collision/replacement and its parents. Never recursive-delete.
            handle.cleanup_refused = True
    for directory in reversed(handle.directories):
        directory.close()
    handle.closed = True
    if handle.cleanup_refused:
        raise CleanupError("owned_cleanup_failed")


def cleanup_preserving(handle, primary):
    try:
        cleanup(handle)
    except CleanupError:
        primary.add_note("owned_cleanup_failed")


@contextmanager
def prepared_layout(archive, *, platform, scratch_parent, expected_source, expected_component):
    handle = prepare(archive=archive, workspace=Path(scratch_parent) / ("oci-layout-" + uuid4().hex),
                     expected_source=expected_source, expected_platform=platform, expected_component=expected_component)
    try:
        yield handle
    except BaseException as primary:
        cleanup_preserving(handle, primary)
        raise
    else:
        cleanup(handle)
