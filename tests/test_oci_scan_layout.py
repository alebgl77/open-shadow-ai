"""An OCI scan directory preserves bytes and rejects ambiguous or raced input."""

import hashlib
import importlib.util
import io
import json
import os
import stat
import tarfile
from pathlib import Path
from uuid import uuid4

import pytest
from test_production_delivery import oci_archive

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("oci_scan_layout", ROOT / "scripts/oci_scan_layout.py")
LAYOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYOUT)
SOURCE = {"commit": "a" * 40, "repository": "example/repository"}


def prepare(archive, workspace):
    return LAYOUT.prepare(archive=archive, workspace=workspace, expected_source=SOURCE,
                          expected_platform="linux/amd64", expected_component="api")


@pytest.fixture
def inputs(tmp_path):
    archive = tmp_path / "runtime.oci.tar"
    oci_archive(archive, nested=True)
    return archive, tmp_path / ("oci-layout-" + uuid4().hex)


def entries(archive):
    with tarfile.open(archive) as source:
        return {member.name: source.extractfile(member).read() for member in source if member.isfile()}


def rewrite(archive, values, extra=()):
    with tarfile.open(archive, "w") as target:
        for name, value in values.items():
            member = tarfile.TarInfo(name)
            member.size = len(value)
            target.addfile(member, io.BytesIO(value))
        for member, value in extra:
            target.addfile(member, io.BytesIO(value) if value is not None else None)


@pytest.mark.parametrize("nested,legacy", [(False, False), (True, False), (False, True), (True, True)])
def test_layout_is_byte_identical_and_strict_evidence_unchanged(inputs, nested, legacy):
    archive, workspace = inputs
    oci_archive(archive, nested=nested, legacy=legacy)
    before = archive.read_bytes()
    handle = prepare(archive, workspace)
    try:
        expected = LAYOUT.verifier().verify(archive, platform="linux/amd64", include_sbom=True)
        assert handle.evidence == expected
        assert handle.selected_image_manifest == expected["image_manifests"][0]
        assert handle.container_input == "/input/layout"
        assert handle.layout_path == workspace / "layout"
        assert handle.snapshot.read_bytes() == before
        values = entries(archive)
        assert {path.relative_to(handle.layout).as_posix(): path.read_bytes()
                for path in handle.layout.rglob("*") if path.is_file()} == values
        metadata = handle.assert_unchanged()
        rows = [{"name": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                for name, value in sorted(values.items())]
        expected_map = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert metadata["layout_table_sha256"] == handle.file_map_sha256 == expected_map
        assert metadata["archive_sha256"] == hashlib.sha256(before).hexdigest()
        helper_sha = hashlib.sha256((ROOT / "scripts/oci_scan_layout.py").read_bytes()).hexdigest()
        assert metadata["helper_sha256"] == helper_sha
        assert metadata["source"] == SOURCE and metadata["component"] == "api"
        if os.name == "posix":
            assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
            assert all(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
                       for path in workspace.rglob("*"))
    finally:
        LAYOUT.cleanup(handle)
    assert archive.read_bytes() == before and not workspace.exists()
    LAYOUT.cleanup(handle)
    with pytest.raises(ValueError, match="closed"):
        handle.assert_unchanged()


def test_binary_crlf_and_ctrl_z_bytes_survive_source_snapshot_and_layout(inputs):
    archive, workspace = inputs
    values = entries(archive)
    payload = b"before\r\n\x1aafter\n\x00\xff" * 100
    blob = "blobs/sha256/" + hashlib.sha256(payload).hexdigest()
    values[blob] = payload
    rewrite(archive, values)
    original = archive.read_bytes()
    handle = prepare(archive, workspace)
    try:
        assert handle.snapshot.read_bytes() == original
        assert (handle.layout / blob).read_bytes() == payload
        assert handle.assert_unchanged()["archive_sha256"] == hashlib.sha256(original).hexdigest()
    finally:
        LAYOUT.cleanup(handle)
    assert archive.read_bytes() == original


def add_blob(values, document, media):
    data = json.dumps(document).encode()
    digest = hashlib.sha256(data).hexdigest()
    values["blobs/sha256/" + digest] = data
    return {"mediaType": media, "digest": "sha256:" + digest, "size": len(data)}


def test_attestation_first_is_rejected_even_when_strict_graph_passes(inputs):
    archive, workspace = inputs
    values = entries(archive)
    outer = json.loads(values["index.json"])
    inner = json.loads(values["blobs/sha256/" + outer["manifests"][0]["digest"][7:]])
    inner["manifests"].reverse()
    outer["manifests"][0] = add_blob(values, inner, "application/vnd.oci.image.index.v1+json")
    values["index.json"] = json.dumps(outer).encode()
    rewrite(archive, values)
    assert len(LAYOUT.verifier().verify(archive)["image_manifests"]) == 1
    with pytest.raises(ValueError, match="first descriptor"):
        prepare(archive, workspace)
    assert not workspace.exists()


def test_two_verified_native_manifests_are_rejected(inputs):
    archive, workspace = inputs
    values = entries(archive)
    outer = json.loads(values["index.json"])
    inner = json.loads(values["blobs/sha256/" + outer["manifests"][0]["digest"][7:]])
    image_entry, attestation_entry = inner["manifests"]
    image = json.loads(values["blobs/sha256/" + image_entry["digest"][7:]])
    image["annotations"] = {"synthetic": "second-runtime"}
    second = add_blob(values, image, image_entry["mediaType"])
    second["platform"] = image_entry["platform"]
    attestation = json.loads(values["blobs/sha256/" + attestation_entry["digest"][7:]])
    attestation["subject"] = {key: second[key] for key in ("mediaType", "digest", "size")}
    layers = []
    for layer in attestation["layers"]:
        statement = json.loads(values["blobs/sha256/" + layer["digest"][7:]])
        statement["subject"][0]["digest"]["sha256"] = second["digest"][7:]
        layers.append(add_blob(values, statement, layer["mediaType"]))
    attestation["layers"] = layers
    related = add_blob(values, attestation, attestation_entry["mediaType"])
    related.update({"platform": attestation_entry["platform"], "annotations": {
        "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": second["digest"]}})
    inner["manifests"].extend([second, related])
    outer["manifests"][0] = add_blob(values, inner, "application/vnd.oci.image.index.v1+json")
    values["index.json"] = json.dumps(outer).encode()
    rewrite(archive, values)
    assert len(LAYOUT.verifier().verify(archive)["image_manifests"]) == 2
    with pytest.raises(ValueError, match="one unchanged native"):
        prepare(archive, workspace)
    assert not workspace.exists()


@pytest.mark.parametrize("name", ["../escaped", "/escaped", "./index.json", "blobs//sha256/" + "a" * 64,
                                  "blobs/sha256/../escaped", "blobs\\sha256\\" + "a" * 64,
                                  "blobs/sha256/" + "A" * 64, "C:escaped", "other", "blobs/sha256/a"])
def test_noncanonical_member_cannot_escape_or_leave_workspace(inputs, name):
    archive, workspace = inputs
    member = tarfile.TarInfo(name)
    rewrite(archive, entries(archive), [(member, b"")])
    with pytest.raises(ValueError, match="Noncanonical"):
        prepare(archive, workspace)
    assert not workspace.exists()
    assert not (workspace.parent / "escaped").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                                  tarfile.BLKTYPE, tarfile.DIRTYPE])
def test_link_special_or_directory_blob_is_refused(inputs, kind):
    archive, workspace = inputs
    member = tarfile.TarInfo("blobs/sha256/" + "f" * 64)
    member.type = kind
    member.linkname = "../../foreign"
    rewrite(archive, entries(archive), [(member, None)])
    with pytest.raises(ValueError, match="regular file"):
        prepare(archive, workspace)
    assert not workspace.exists()


@pytest.mark.parametrize("kind", [tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                                  tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE])
def test_hidden_extended_or_sparse_header_is_refused_before_payload_allocation(inputs, kind):
    archive, workspace = inputs
    member = tarfile.TarInfo("index.json")
    member.type = kind
    rewrite(archive, entries(archive), [(member, None)])
    with pytest.raises(ValueError, match="regular file or fixed directory"):
        prepare(archive, workspace)
    assert not workspace.exists()


@pytest.mark.parametrize("name,directory", [("index.json", False), ("blobs", True)])
def test_duplicate_member_is_refused(inputs, name, directory):
    archive, workspace = inputs
    values = entries(archive)
    member = tarfile.TarInfo(name)
    if directory:
        member.type = tarfile.DIRTYPE
        extra = [(member, None), (member, None)]
    else:
        member.size = len(values[name])
        extra = [(member, values[name])]
    rewrite(archive, values, extra)
    with pytest.raises(ValueError, match="Duplicate"):
        prepare(archive, workspace)
    assert not workspace.exists()


@pytest.mark.parametrize("limit", ["MAX_ARCHIVE", "MAX_TOTAL", "MAX_FILE", "MAX_JSON", "MAX_MEMBERS"])
def test_limits_fail_before_scan_and_cleanup_owned_partial_state(inputs, monkeypatch, limit):
    archive, workspace = inputs
    monkeypatch.setattr(LAYOUT, limit, 1)
    with pytest.raises(ValueError):
        prepare(archive, workspace)
    assert not workspace.exists()


def test_exclusive_workspace_collision_preserves_foreign_content(inputs):
    archive, workspace = inputs
    workspace.mkdir()
    marker = workspace / "foreign"
    marker.write_bytes(b"untouched")
    with pytest.raises(FileExistsError):
        prepare(archive, workspace)
    assert marker.read_bytes() == b"untouched"
    assert workspace.exists()


@pytest.mark.parametrize("suffix", [uuid4().hex, str(uuid4())])
def test_uuid_workspace_accepts_hex_and_hyphenated_form(inputs, suffix):
    archive, workspace = inputs
    handle = prepare(archive, workspace.with_name("oci-layout-" + suffix))
    LAYOUT.cleanup(handle)


@pytest.mark.parametrize("source", [{"commit": "bad", "repository": "example/repository"},
                                    {"commit": "a" * 40}, {"commit": "a" * 40, "repository": ""}])
def test_invalid_source_expectation_creates_nothing(inputs, source):
    archive, workspace = inputs
    with pytest.raises(ValueError, match="expectation"):
        LAYOUT.prepare(archive=archive, workspace=workspace, expected_source=source,
                       expected_platform="linux/amd64", expected_component="api")
    assert not workspace.exists()


@pytest.mark.parametrize("options,platform", [({"config_arch": "arm64"}, "linux/amd64"), ({}, "linux/arm64"),
                                           ({"wrong_subject": True}, "linux/amd64"),
                                           ({"missing": "provenance"}, "linux/amd64")])
def test_platform_config_and_bound_evidence_gates_remain_strict(inputs, options, platform):
    archive, workspace = inputs
    oci_archive(archive, **options)
    with pytest.raises(ValueError):
        LAYOUT.prepare(archive=archive, workspace=workspace, expected_source=SOURCE,
                       expected_platform=platform, expected_component="api")
    assert not workspace.exists()


@pytest.mark.parametrize("replace", [False, True])
def test_source_mutation_during_snapshot_is_refused(inputs, monkeypatch, replace):
    archive, workspace = inputs
    original = LAYOUT.Layout.create_file
    before = archive.read_bytes()
    replace_reached, replace_denied = False, False

    def create_file(self, parent, name, source, limit):
        nonlocal replace_reached, replace_denied
        result = original(self, parent, name, source, limit)
        if name == "snapshot.oci.tar":
            if replace:
                replacement = archive.with_suffix(".replacement")
                replacement.write_bytes(archive.read_bytes())
                replace_reached = True
                try:
                    os.replace(replacement, archive)
                except PermissionError:
                    replace_denied = True
                    raise
            else:
                archive.write_bytes(archive.read_bytes() + b"changed")
        return result

    monkeypatch.setattr(LAYOUT.Layout, "create_file", create_file)
    error = PermissionError if replace and os.name == "nt" else ValueError
    with pytest.raises(error) as raised:
        prepare(archive, workspace)
    assert not workspace.exists()
    if replace:
        assert replace_reached
        if os.name == "nt":
            assert replace_denied
            assert raised.value.winerror == 5
            assert archive.read_bytes() == before
            assert archive.with_suffix(".replacement").read_bytes() == before
        else:
            assert not replace_denied and archive.read_bytes() == before


def test_snapshot_replacement_during_verification_is_preserved(inputs, monkeypatch):
    archive, workspace = inputs
    real = LAYOUT.verifier()
    before = archive.read_bytes()
    replace_reached, replace_denied = False, False

    class ReplacingVerifier:
        MAX_DEPTH, INDEX_TYPES, MANIFEST_TYPES = real.MAX_DEPTH, real.INDEX_TYPES, real.MANIFEST_TYPES

        @staticmethod
        def verify(path, **kwargs):
            nonlocal replace_reached, replace_denied
            result = real.verify(path, **kwargs)
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replace_reached = True
            try:
                os.replace(replacement, path)
            except PermissionError:
                replace_denied = True
                raise
            return result

    monkeypatch.setattr(LAYOUT, "verifier", lambda: ReplacingVerifier)
    error = PermissionError if os.name == "nt" else ValueError
    with pytest.raises(error) as raised:
        prepare(archive, workspace)
    assert replace_reached and archive.read_bytes() == before
    if os.name == "nt":
        assert replace_denied
        assert raised.value.winerror == 5
        assert not (workspace / "snapshot.oci.tar").exists()
        assert (workspace / "snapshot.oci.replacement").read_bytes() == before
    else:
        assert not replace_denied
        assert (workspace / "snapshot.oci.tar").read_bytes() == before
    assert not (workspace / "layout").exists()


def test_materialization_collision_is_not_deleted(inputs, monkeypatch):
    archive, workspace = inputs
    original = LAYOUT.Layout.create_dir

    def create_dir(self, parent, name):
        result = original(self, parent, name)
        if name == "layout":
            (result.path / "index.json").write_bytes(b"foreign")
        return result

    monkeypatch.setattr(LAYOUT.Layout, "create_dir", create_dir)
    with pytest.raises(FileExistsError):
        prepare(archive, workspace)
    assert (workspace / "layout/index.json").read_bytes() == b"foreign"
    assert not (workspace / "snapshot.oci.tar").exists()


def test_parent_replaced_during_materialization_cannot_receive_writes_or_cleanup(inputs, monkeypatch):
    archive, workspace = inputs
    original = LAYOUT.Layout.create_file
    moved = workspace / "layout-moved"
    replaced = False

    def create_file(self, parent, name, source, limit):
        nonlocal replaced
        result = original(self, parent, name, source, limit)
        if name == "index.json":
            parent.path.rename(moved)
            parent.path.mkdir()
            (parent.path / "foreign").write_bytes(b"foreign")
            replaced = True
        return result

    monkeypatch.setattr(LAYOUT.Layout, "create_file", create_file)
    with pytest.raises(ValueError, match="directory identity changed") as raised:
        prepare(archive, workspace)
    assert replaced and raised.value.__notes__ == ["owned_cleanup_failed"]
    assert {path.name for path in (workspace / "layout").iterdir()} == {"foreign"}
    assert (workspace / "layout/foreign").read_bytes() == b"foreign"
    assert (moved / "index.json").read_bytes() == entries(archive)["index.json"]
    assert not (workspace / "snapshot.oci.tar").exists()


def test_snapshot_layer_flip_then_restore_cannot_bypass_verified_blob_identity(inputs, monkeypatch):
    archive, workspace = inputs
    original = LAYOUT.Layout.create_file
    values = entries(archive)
    index = json.loads(values["index.json"])
    nested = json.loads(values["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
    image = json.loads(values["blobs/sha256/" + nested["manifests"][0]["digest"][7:]])
    layer_digest = image["layers"][0]["digest"][7:]
    flipped, copied_different_bytes, restored = False, False, False

    def create_file(self, parent, name, source, limit):
        nonlocal flipped, copied_different_bytes, restored
        if name != layer_digest:
            return original(self, parent, name, source, limit)
        with tarfile.open(self.snapshot) as bundle:
            member = bundle.getmember("blobs/sha256/" + layer_digest)
            offset = member.offset_data + member.size - 1
        with self.snapshot.open("r+b", buffering=0) as writer:
            writer.seek(offset)
            before = writer.read(1)
            writer.seek(offset)
            writer.write(bytes([before[0] ^ 1]))
            flipped = True
            try:
                result = original(self, parent, name, source, limit)
                copied_different_bytes = result["sha256"] != name
                return result
            finally:
                writer.seek(offset)
                writer.write(before)
                restored = True

    monkeypatch.setattr(LAYOUT.Layout, "create_file", create_file)
    handle = None
    try:
        with pytest.raises(ValueError, match="snapshot|blob"):
            handle = prepare(archive, workspace)
            # An unsafe success must prove the real mutated bytes reached the
            # layout while the snapshot bytes were already restored.
            assert flipped and copied_different_bytes and restored
            assert (handle.layout / ("blobs/sha256/" + layer_digest)).read_bytes() != \
                values["blobs/sha256/" + layer_digest]
            assert handle.snapshot.read_bytes() == archive.read_bytes()
    finally:
        if handle is not None:
            LAYOUT.cleanup(handle)
    assert flipped and copied_different_bytes and restored
    assert not workspace.exists()


def test_materialized_blob_must_match_its_filename_even_with_unchanged_snapshot(inputs, monkeypatch):
    archive, workspace = inputs
    original = LAYOUT.Layout.create_file
    values = entries(archive)
    index = json.loads(values["index.json"])
    nested = json.loads(values["blobs/sha256/" + index["manifests"][0]["digest"][7:]])
    image = json.loads(values["blobs/sha256/" + nested["manifests"][0]["digest"][7:]])
    layer_digest = image["layers"][0]["digest"][7:]
    archive_before = archive.read_bytes()
    copied_bad_blob = False

    def create_file(self, parent, name, source, limit):
        nonlocal copied_bad_blob
        if name == layer_digest:
            data = source.read()
            result = original(self, parent, name, io.BytesIO(data[:-1] + bytes([data[-1] ^ 1])), limit)
            copied_bad_blob = result["sha256"] != name
            assert self.snapshot.read_bytes() == archive_before
            return result
        return original(self, parent, name, source, limit)

    monkeypatch.setattr(LAYOUT.Layout, "create_file", create_file)
    with pytest.raises(ValueError, match="materialized blob SHA256 mismatch"):
        prepare(archive, workspace)
    assert copied_bad_blob and archive.read_bytes() == archive_before
    assert not workspace.exists()


def test_snapshot_reference_metadata_is_retained_across_post_scan_checks(inputs):
    archive, workspace = inputs
    handle = prepare(archive, workspace)
    try:
        before = handle.snapshot.read_bytes()
        initial = handle.snapshot_stat
        # A metadata change is independently rejected even if all final bytes
        # remain exactly the verified original archive.
        os.utime(handle.snapshot, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000))
        assert handle.snapshot.read_bytes() == before == archive.read_bytes()
        with pytest.raises(ValueError, match="snapshot metadata changed"):
            handle.assert_unchanged()
    finally:
        LAYOUT.cleanup(handle)
    assert not workspace.exists()


@pytest.mark.parametrize("target", ["source", "snapshot", "index", "blob", "extra", "replace"])
def test_post_scan_check_detects_every_input_or_file_table_drift(inputs, target):
    archive, workspace = inputs
    handle = prepare(archive, workspace)
    try:
        path = archive if target == "source" else handle.snapshot if target == "snapshot" else \
            next((handle.layout / "blobs/sha256").iterdir()) if target == "blob" else handle.layout / "index.json"
        if target == "extra":
            (handle.layout / "extra").write_bytes(b"foreign")
        elif target == "replace":
            replacement = workspace.parent / "replacement"
            replacement.write_bytes(path.read_bytes())
            os.replace(replacement, path)
        else:
            path.write_bytes(path.read_bytes() + b"changed")
        with pytest.raises(ValueError):
            handle.assert_unchanged()
    finally:
        if target in {"extra", "replace"}:
            with pytest.raises(LAYOUT.CleanupError, match="owned_cleanup_failed"):
                LAYOUT.cleanup(handle)
        else:
            LAYOUT.cleanup(handle)
    if target in {"extra", "replace"}:
        assert path.exists() if target == "replace" else (handle.layout / "extra").exists()
    else:
        assert not workspace.exists()


def test_replaced_workspace_parent_preserves_both_foreign_and_moved_owned_tree(inputs):
    archive, workspace = inputs
    handle = prepare(archive, workspace)
    moved = workspace.with_name(workspace.name + "-moved")
    # Windows cannot rename directories with open POSIX directory handles; its
    # fallback keeps none. The same replacement contract is exercised on both.
    workspace.rename(moved)
    workspace.mkdir()
    (workspace / "foreign").write_bytes(b"foreign")
    with pytest.raises(ValueError, match="directory identity changed"):
        handle.assert_unchanged()
    with pytest.raises(LAYOUT.CleanupError, match="owned_cleanup_failed"):
        LAYOUT.cleanup(handle)
    assert (workspace / "foreign").read_bytes() == b"foreign"
    assert (moved / "snapshot.oci.tar").exists()


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_context_cleans_owned_files_and_preserves_scan_failure(inputs, failure):
    archive, workspace = inputs
    with pytest.raises(failure, match="scan-primary"):
        with LAYOUT.prepared_layout(archive, platform="linux/amd64", scratch_parent=workspace.parent,
                                    expected_source=SOURCE, expected_component="api") as handle:
            actual_workspace = handle.workspace
            handle.assert_unchanged()
            raise failure("scan-primary")
    assert not actual_workspace.exists() and archive.exists()


def test_cleanup_refusal_cannot_mask_primary_error(inputs, monkeypatch):
    archive, workspace = inputs

    def refuse(*args, **kwargs):
        raise PermissionError("simulated cleanup denial")

    with pytest.raises(KeyboardInterrupt, match="scan-primary") as raised:
        with LAYOUT.prepared_layout(archive, platform="linux/amd64", scratch_parent=workspace.parent,
                                    expected_source=SOURCE, expected_component="api") as handle:
            monkeypatch.setattr(LAYOUT.Directory, "remove", refuse)
            raise KeyboardInterrupt("scan-primary")
    assert handle.closed and handle.snapshot.exists()
    assert handle.cleanup_refused
    assert raised.value.__notes__ == ["owned_cleanup_failed"]


def test_cleanup_refusal_on_success_is_an_error(inputs, monkeypatch):
    archive, workspace = inputs

    def refuse(*args, **kwargs):
        raise PermissionError("simulated cleanup denial")

    with pytest.raises(LAYOUT.CleanupError, match="owned_cleanup_failed"):
        with LAYOUT.prepared_layout(archive, platform="linux/amd64", scratch_parent=workspace.parent,
                                    expected_source=SOURCE, expected_component="api") as handle:
            handle.assert_unchanged()
            monkeypatch.setattr(LAYOUT.Directory, "remove", refuse)
    assert handle.closed and handle.cleanup_refused and handle.snapshot.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX nofollow/FIFO/dir_fd contract")
@pytest.mark.parametrize("kind", ["fifo", "symlink", "parent-symlink", "hardlink"])
def test_source_open_rejects_links_fifo_and_linked_parents_without_blocking(inputs, kind):
    archive, workspace = inputs
    if kind == "fifo":
        archive.unlink()
        os.mkfifo(archive)
    elif kind == "symlink":
        foreign = archive.with_suffix(".foreign")
        archive.rename(foreign)
        archive.symlink_to(foreign)
    elif kind == "hardlink":
        os.link(archive, archive.with_suffix(".foreign"))
    else:
        parent = archive.parent / "linked"
        parent.symlink_to(archive.parent, target_is_directory=True)
        archive = parent / archive.name
    with pytest.raises((ValueError, OSError)):
        prepare(archive, workspace)
    assert not workspace.exists()
