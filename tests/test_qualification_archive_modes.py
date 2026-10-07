"""Directory-only SGID/sticky policy; native POSIX restoration uses owned quiet Temp."""

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

from shadai.qualification import snapshot
from shadai.qualification.schemas import QualificationError

KINDS = [tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE,
         tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, b"unknown"]
DIRECTORY_SPECIAL = [stat.S_ISGID, stat.S_ISVTX, stat.S_ISGID | stat.S_ISVTX]
SPECIAL = [bits << 9 for bits in range(1, 8)]
REFUSED_SPECIAL = [(kind, special) for kind in KINDS for special in SPECIAL
                   if kind != tarfile.DIRTYPE or special & stat.S_ISUID]
POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Actual mode/ownership restoration requires native POSIX")


def member(kind=tarfile.REGTYPE, mode=0o644, name="owned"):
    item = tarfile.TarInfo(name)
    item.type, item.mode = kind, mode
    item.uid = item.gid = 0
    if kind in {tarfile.LNKTYPE, tarfile.SYMTYPE}:
        item.linkname = "target"
    return item


@pytest.mark.parametrize("kind", KINDS)
def test_every_permission_and_special_bit_combination_has_only_the_directory_policy(kind):
    item = member(kind)
    for mode in range(0o10000):
        item.mode = mode
        expected = mode <= 0o777 or (kind == tarfile.DIRTYPE and mode <= 0o3777)
        assert snapshot._allowed_archive_mode(item) is expected
    for mode in (-1, 0o10000, 2**32):
        item.mode = mode
        assert snapshot._allowed_archive_mode(item) is False


@pytest.mark.parametrize("special", DIRECTORY_SPECIAL)
def test_exact_directory_special_mode_survives_pax_and_validation(special):
    item = member(tarfile.DIRTYPE, special | 0o750)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(item)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer, mode="r") as archive:
        restored = archive.getmembers()
    assert len(restored) == 1 and type(restored[0]) is tarfile.TarInfo
    assert type(restored[0].mode) is int and restored[0].mode == item.mode
    with snapshot.export_diagnostics() as diagnostic:
        snapshot.export_checkpoint("validate")
        assert snapshot.validate_members(restored, 0) == 0
        assert diagnostic.primary is diagnostic.secondary is None


@pytest.mark.parametrize("kind,special", REFUSED_SPECIAL)
def test_refused_special_archive_never_reaches_extraction_or_destination_writes(tmp_path, monkeypatch, kind, special):
    archive, destination = tmp_path / "refused.tar", tmp_path / "destination"
    destination.mkdir()
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
        output.addfile(member(kind, special | 0o750))
    calls = []
    monkeypatch.setattr(tarfile.TarFile, "extractall", lambda *args, **kwargs: calls.append("extractall"))
    with pytest.raises(QualificationError, match="Duplicate or unsafe archive metadata"):
        snapshot.import_volume(archive, destination, snapshot.digest_file(archive), 1024)
    assert calls == [] and list(destination.iterdir()) == []


def test_real_gettarinfo_producer_keeps_ordinary_modes_and_pax_archive_result(tmp_path, monkeypatch):
    source, archive = tmp_path / "source", tmp_path / "ordinary.tar"
    source.mkdir()
    (source / "event").write_bytes(b"owned bytes")
    called, original = [], tarfile.TarFile.gettarinfo

    def gettarinfo(*args, **kwargs):
        item = original(*args, **kwargs)
        assert type(item) is tarfile.TarInfo
        called.append(item.name)
        return item

    monkeypatch.setattr(tarfile.TarFile, "gettarinfo", gettarinfo)
    result = snapshot.export_volume(source, archive, 1024)
    assert called == [".", "event"]
    with tarfile.open(archive, "r") as contents:
        items = contents.getmembers()
        assert [item.name for item in items] == called
        assert all(type(item.mode) is int and 0 <= item.mode <= 0o777 for item in items)
        assert contents.extractfile("event").read() == b"owned bytes"
    assert result["sha256"] == snapshot.digest_file(archive)
    assert result["unpacked_bytes"] == len(b"owned bytes") and result["bytes"] == archive.stat().st_size


@pytest.mark.parametrize("special", DIRECTORY_SPECIAL)
def test_real_import_source_keeps_private_extraction_then_chown_chmod_postorder_model(tmp_path, monkeypatch, special):
    archive, destination = tmp_path / "owned.tar", tmp_path / "destination"
    destination.mkdir()
    items = [member(tarfile.DIRTYPE, special | 0o750, "."),
             member(tarfile.DIRTYPE, special | 0o750, "nested"), member(name="nested/event")]
    for item in items:
        item.uid, item.gid = 123, 456
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
        for item in items:
            output.addfile(item)
    calls = []

    def extractall(self, path, *, members, numeric_owner, filter):
        assert path == destination and numeric_owner is False
        for item in members:
            owned = filter(item, path)
            assert owned is not item
            assert (owned.uid, owned.gid, owned.uname, owned.gname) == (None, None, None, None)
            assert owned.mode == (0o700 if item.isdir() else 0o600)
            assert item.mode == next(original.mode for original in items if original.name == item.name)
        calls.append(("extractall",))

    def chown(path, uid, gid, **kwargs):
        calls.append(("chown", Path(path).relative_to(destination), uid, gid, kwargs))

    def chmod(path, mode):
        calls.append(("chmod", Path(path).relative_to(destination), mode))

    monkeypatch.setattr(tarfile.TarFile, "extractall", extractall)
    monkeypatch.setattr(snapshot.os, "chown", chown, raising=False)
    monkeypatch.setattr(snapshot.os, "chmod", chmod)
    snapshot.import_volume(archive, destination, snapshot.digest_file(archive), 1024)
    assert calls == [("extractall",),
                     ("chown", Path("nested/event"), 123, 456, {"follow_symlinks": False}),
                     ("chmod", Path("nested/event"), 0o644),
                     ("chown", Path("nested"), 123, 456, {"follow_symlinks": False}),
                     ("chmod", Path("nested"), special | 0o750),
                     ("chown", Path("."), 123, 456, {"follow_symlinks": False}),
                     ("chmod", Path("."), special | 0o750)]
    assert list(destination.iterdir()) == []  # This test models OS writes, not native POSIX restoration.


class NumericAlias:
    def __ge__(self, other):
        raise AssertionError("numeric comparison must not run")

    __le__ = __lt__ = __gt__ = __eq__ = __ge__

    def __bool__(self):
        raise AssertionError("numeric truth must not run")

    def __int__(self):
        raise AssertionError("numeric coercion must not run")


class IntAlias(int):
    def __lt__(self, other):
        raise AssertionError("int subclass comparison must not run")

    __le__ = __gt__ = __ge__ = __eq__ = __lt__


@pytest.mark.parametrize("mode", [False, True, 0.0, 511.0, float("nan"), float("inf"), IntAlias(0),
                                  IntAlias(0o2750), NumericAlias()])
def test_nonexact_mode_scalars_refuse_without_numeric_callbacks(mode):
    item = member(tarfile.DIRTYPE, mode)
    assert snapshot._allowed_archive_mode(item) is False
    with snapshot.export_diagnostics() as diagnostic:
        snapshot.export_checkpoint("validate")
        with pytest.raises(QualificationError):
            with snapshot.export_capture():
                snapshot.validate_members([item], 0)
        assert diagnostic.envelope()["reason"] == "metadata_mode"


class BytesAlias(bytes):
    def __eq__(self, other):
        raise AssertionError("kind comparison must not run")


class KindAlias:
    def __eq__(self, other):
        raise AssertionError("kind comparison must not run")


@pytest.mark.parametrize("kind", [BytesAlias(tarfile.DIRTYPE), KindAlias(), "5", 5, None])
def test_special_mode_requires_exact_directory_kind_bytes_without_callbacks(kind):
    item = member(mode=0o2750)
    item.type = kind
    assert snapshot._allowed_archive_mode(item) is False


def test_subclass_or_forged_directory_cannot_authorize_special_mode_or_read_kind():
    class PretendDirectory(tarfile.TarInfo):
        def __getattribute__(self, key):
            if key == "type":
                raise AssertionError("subclass directory kind must not be read")
            return super().__getattribute__(key)

    class ForgedDirectory:
        mode = 0o2750

        @property
        def __class__(self):
            return tarfile.TarInfo

        @property
        def type(self):
            raise AssertionError("forged directory kind must not be read")

    subclass = PretendDirectory("owned")
    subclass.mode = 0o2750
    assert snapshot._allowed_archive_mode(subclass) is False
    assert snapshot._allowed_archive_mode(ForgedDirectory()) is False


@POSIX_ONLY
@pytest.mark.parametrize("special", DIRECTORY_SPECIAL)
def test_real_owned_directory_export_import_preserves_mode_ownership_and_chown_before_chmod(
    tmp_path, monkeypatch, special
):
    source, destination, archive = tmp_path / "source", tmp_path / "restored", tmp_path / "owned.tar"
    source.mkdir()
    child = source / "nested"
    child.mkdir()
    file = child / "event"
    file.write_bytes(b"owned data")
    file.chmod(0o640)
    child.chmod(special | 0o750)
    source.chmod(special | 0o750)
    source_metadata = {str(path.relative_to(source)): path.stat() for path in (source, child, file)}
    result = snapshot.export_volume(source, archive, 1024)
    with tarfile.open(archive, "r") as contents:
        assert all(type(item) is tarfile.TarInfo for item in contents.getmembers())
        modes = {item.name: item.mode for item in contents.getmembers()}
    assert modes["."] == modes["nested"] == special | 0o750
    assert modes["nested/event"] == 0o640
    destination.mkdir(mode=0o700)
    calls, real_chown, real_chmod = [], os.chown, os.chmod

    def chown(path, uid, gid, **kwargs):
        if uid == gid == -1:
            return real_chown(path, uid, gid, **kwargs)
        kind = Path(path).is_dir()
        assert stat.S_IMODE(Path(path).stat().st_mode) == (0o700 if kind else 0o600)
        calls.append(("chown", Path(path).relative_to(destination), uid, gid, kwargs))
        return real_chown(path, uid, gid, **kwargs)

    def chmod(path, mode, **kwargs):
        calls.append(("chmod", Path(path).relative_to(destination), mode))
        return real_chmod(path, mode, **kwargs)

    monkeypatch.setattr(snapshot.os, "chown", chown)
    monkeypatch.setattr(snapshot.os, "chmod", chmod)
    snapshot.import_volume(archive, destination, result["sha256"], 1024)
    for relative, before in source_metadata.items():
        after = (destination / relative).stat()
        assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
        assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert (destination / "nested/event").read_bytes() == b"owned data"
    # tarfile first applies root_owned's private modes; final restore pairs follow.
    restore_calls = [call for call in calls if call[0] == "chown" or call[2] != 0o700]
    expected_paths = [Path("nested/event"), Path("nested"), Path(".")]
    assert [call[1] for call in calls if call[0] == "chown"] == expected_paths
    for path in expected_paths:
        ownership_index = next(index for index, call in enumerate(calls) if call[:2] == ("chown", path))
        assert calls[ownership_index + 1][:2] == ("chmod", path)
        assert calls[ownership_index][4] == {"follow_symlinks": False}
    assert restore_calls[-1][:2] == ("chmod", Path("."))
