"""Synthetic security-boundary checks; actual Linux Grype/DB scans remain CI gates."""

import copy
import errno
import gc
import gzip
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import threading
import time
import weakref
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "grype_runtime.py"
SPEC = importlib.util.spec_from_file_location("isolated_grype_runtime_tests", SOURCE)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
QUERY = "pkg:golang/golang.org/x/sys@v0.1.0"
CPE = "cpe:2.3:a:redis:redis:7.4.11:*:*:*:*:*:*:*"


def asset_bytes(entries=None, *, format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=format) as archive:
        for name, kind, data in entries or [("LICENSE", tarfile.REGTYPE, b"license"),
                                           ("README.md", tarfile.REGTYPE, b"readme"),
                                           ("grype", tarfile.REGTYPE, b"synthetic\r\n\x1abinary")]:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.size = len(data) if kind in {tarfile.REGTYPE, tarfile.AREGTYPE} else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "outside"
            archive.addfile(member, io.BytesIO(data) if member.size else None)
    return output.getvalue()


def manifest():
    return {"schema": 1, "version": runtime.VERSION, "commit": runtime.COMMIT,
            "checksum_file_sha256": runtime.CHECKSUM_FILE,
            "archives": {name: {"url": f"https://github.com/anchore/grype/releases/download/v{runtime.VERSION}/"
                                f"grype_{runtime.VERSION}_linux_{name.split('/')[1]}.tar.gz",
                                "sha256": checksum, "bytes": size}
                         for name, (checksum, size) in runtime.PINS.items()}}


def configuration(cache, platform="linux/amd64"):
    result = copy.deepcopy(runtime.TEMPLATE)
    result["ignore-wontfix"] = result.pop("ignore-states")
    result.update({"distro": "", "output-template-file": "", "file": "", "platform": platform,
                   "from": None, "name": "", "output": ["json"], "show-suppressed": False,
                   "match": {"stock": {"using-cpes": True},
                             "golang": {"using-cpes": False, "always-use-cpe-for-stdlib": False,
                                        "allow-main-module-pseudo-version-comparison": False}},
                   "externalSources": {"enable": False}})
    result["db"].update({"cache-dir": str(cache), "max-allowed-built-age": 86400000000000, "ca-cert": ""})
    return result


def status(cache):
    return {"schemaVersion": "v6.1.10", "from": "https://grype.anchore.io/databases/v6/"
            "vulnerability-db_v6.1.10_2026-10-07T00:00:00Z.tar.zst?checksum=sha256%3A" + "a" * 64,
            "built": (datetime.now(UTC) - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "path": str(cache / "6" / "vulnerability.db"), "valid": True}


@pytest.fixture
def synthetic(tmp_path, monkeypatch):
    archive = asset_bytes()
    # The installer and all filesystem guards run. Only official network/tool
    # execution and the expected fixture asset pin are substituted.
    pins = {name: (hashlib.sha256(archive).hexdigest(), len(archive)) for name in runtime.PINS}
    monkeypatch.setattr(runtime, "PINS", pins)
    monkeypatch.setattr(runtime, "native_platform", lambda: "linux/amd64")
    files = tmp_path / "inputs"
    files.mkdir()
    manifest_path, config_path = files / "manifest.json", files / "config.yaml"
    manifest_path.write_bytes(runtime.canonical(manifest()))
    config_path.write_bytes(runtime.canonical(runtime.TEMPLATE))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = SimpleNamespace(archive=archive, calls=[], mutate=None, version=None, status=None, report=None,
                            update_fail=False, update_mutate=None)

    def fake_run(command, *, cwd, output_fd=None, **kwargs):
        state.calls.append(tuple(command))
        if command[0] == sys.executable:
            runtime.write_all(output_fd, state.archive)
            return b""
        cache = cwd / "database"
        if "version" in command:
            value = state.version or {"application": "grype", "version": runtime.VERSION,
                                      "gitCommit": runtime.COMMIT, "platform": "linux/amd64"}
        elif "update" in command:
            if state.update_fail:
                raise runtime.GrypeRuntimeError("nonzero")
            database = cache / "6"
            database.mkdir()
            value = state.status or status(cache)
            (database / "vulnerability.db").write_bytes(b"synthetic DB\r\n\x1a")
            (database / "import.json").write_bytes(runtime.canonical({"source": value["from"],
                "digest": "xxh64:" + "a" * 16, "client_version": "v6.1.10"}))
            (database / "last_update_check").write_text(datetime.now(UTC).isoformat())
            if state.update_mutate:
                state.update_mutate(database)
            state.actual_status = value
            return b"update complete"
        elif "status" in command:
            value = state.actual_status
        else:
            value = state.report or {"descriptor": {"name": "grype", "version": runtime.VERSION,
                    "configuration": configuration(cache), "db": {"status": state.actual_status,
                    "providers": {"nvd": {"captured": state.actual_status["built"], "input": "sha256:fixture"}}}},
                    "matches": [], "ignoredMatches": []}
            if state.mutate:
                state.mutate(cwd)
        raw = runtime.canonical(value)
        if output_fd is not None:
            runtime.write_all(output_fd, raw)
        return raw

    monkeypatch.setattr(runtime, "run", fake_run)
    state.args = {"scratch_parent": scratch, "manifest_path": manifest_path,
                  "config_path": config_path, "platform": "linux/amd64"}
    state.scratch = scratch
    return state


def test_valid_runtime_preserves_binary_db_and_raw_receipts_and_cleans(synthetic, tmp_path):
    output = tmp_path / "query.json"
    assert json.loads((SOURCE.parent.parent / "requirements/grype.yaml").read_bytes()) == runtime.TEMPLATE
    with runtime.prepared_grype(**synthetic.args) as handle:
        rendered = json.loads((handle.path / "grype.json").read_bytes())
        assert rendered["match-upstream-kernel-headers"] is True and rendered["ignore"] == []
        assert handle.configuration is None
        with pytest.raises(runtime.GrypeRuntimeError, match="configuration_unobserved"):
            handle.assert_unchanged()
        report = handle.run_query(QUERY, output)
        assert json.loads(output.read_bytes()) == report
        assert (handle.path / "grype").read_bytes() == b"synthetic\r\n\x1abinary"
        receipt = handle.assert_unchanged()
        assert receipt["configuration"]["match-upstream-kernel-headers"] is True
        assert receipt["database"]["status"] == handle.database_status
        assert set(receipt["database"]["files"]) == {"6/vulnerability.db", "6/import.json", "6/last_update_check"}
        table_sha = hashlib.sha256(runtime.canonical(receipt["database"]["files"])).hexdigest()
        assert receipt["database"]["digest"] == table_sha
        assert receipt["tool"]["binary_sha256"] == hashlib.sha256(b"synthetic\r\n\x1abinary").hexdigest()
    assert not list(synthetic.scratch.iterdir())
    assert output.is_file()
    assert sum("update" in command for command in synthetic.calls) == 1


@pytest.mark.parametrize("phase", sorted(runtime.PREPARE_PHASES))
def test_prepare_phase_diagnostic_preserves_same_fixed_exception_and_call_order(synthetic, monkeypatch, phase):
    error = runtime.GrypeRuntimeError("filesystem", filesystem_reason="syscall")
    previous_run, previous_create = runtime.run, runtime.Runtime.create
    previous_read = runtime.FileGuard.read_json

    def refuse(*args, **kwargs):
        raise error

    def running(command, **kwargs):
        wanted = {"download": command[0] == sys.executable, "version": "version" in command,
                  "update": "update" in command, "status": "status" in command}
        if wanted.get(phase, False):
            raise error
        return previous_run(command, **kwargs)

    def creating(handle, path):
        if phase == "config" and path.name == "grype.json":
            raise error
        return previous_create(handle, path)

    def reading(guard):
        if phase == "import_validation" and guard.name == "import.json":
            raise error
        return previous_read(guard)

    monkeypatch.setattr(runtime, "run", running)
    monkeypatch.setattr(runtime.Runtime, "create", creating)
    monkeypatch.setattr(runtime.FileGuard, "read_json", reading)
    if phase == "source_guard":
        monkeypatch.setattr(runtime, "native_platform", refuse)
    elif phase == "workspace":
        monkeypatch.setattr(runtime.Runtime, "mkdir", refuse)
    elif phase == "extract":
        monkeypatch.setattr(runtime.AssetTarInfo, "_proc_member", refuse)
    elif phase == "check_files":
        monkeypatch.setattr(runtime.Runtime, "check_files", refuse)
    elif phase == "adopt_database":
        monkeypatch.setattr(runtime.Runtime, "adopt_database", refuse)
    with pytest.raises(runtime.GrypeRuntimeError) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert raised.value is error and error.code == "filesystem" and error.args == ("filesystem",)
    assert error.prepare_phase == phase and error.filesystem_reason == "syscall"
    expected_calls = {"source_guard": 0, "workspace": 0, "download": 0, "extract": 1,
                      "config": 1, "version": 1, "check_files": 2, "update": 2,
                      "adopt_database": 3, "status": 3, "import_validation": 4}
    assert len(synthetic.calls) == expected_calls[phase]


@pytest.mark.parametrize("directory,reason", [("home", "home_nonempty"), ("tmp", "tmp_nonempty"),
                                              ("cache", "cache_unexpected"), ("", "root_unexpected")])
def test_actual_prepare_empty_directory_guard_identifies_reason_and_preserves_unknown(synthetic, monkeypatch,
                                                                                     directory, reason):
    previous = runtime.run
    paths = []

    def running(command, **kwargs):
        result = previous(command, **kwargs)
        if "version" in command:
            path = kwargs["cwd"] / directory / "unexpected"
            path.write_bytes(b"synthetic preserved bytes")
            paths.append(path)
        return result

    monkeypatch.setattr(runtime, "run", running)
    with pytest.raises(runtime.GrypeRuntimeError) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert raised.value.code == "filesystem" and raised.value.args == ("filesystem",)
    assert raised.value.prepare_phase == "check_files" and raised.value.filesystem_reason == reason
    assert raised.value.__notes__ == ["owned_cleanup_failed"]
    assert len(synthetic.calls) == 2 and paths[0].read_bytes() == b"synthetic preserved bytes"


@pytest.mark.parametrize("primary", [PermissionError("not-serialized"), KeyboardInterrupt("not-serialized"),
                                    SystemExit(7)])
def test_prepare_syscall_diagnostic_keeps_existing_conversion_and_cancel_identity(synthetic, monkeypatch, primary):
    previous = runtime.run

    def running(command, **kwargs):
        if "version" in command:
            raise primary
        return previous(command, **kwargs)

    monkeypatch.setattr(runtime, "run", running)
    expected = runtime.GrypeRuntimeError if isinstance(primary, OSError) else type(primary)
    with pytest.raises(expected) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    if isinstance(primary, OSError):
        assert raised.value.args == ("filesystem",) and raised.value.__cause__ is None
        assert raised.value.__suppress_context__ is True
        assert raised.value.prepare_phase == "version" and raised.value.filesystem_reason == "syscall"
    else:
        assert raised.value is primary and "prepare_phase" not in primary.__dict__
    assert not list(synthetic.scratch.iterdir())


def test_prepare_does_not_inspect_or_annotate_untrusted_exception_subclass(synthetic, monkeypatch):
    class PoisonError(runtime.GrypeRuntimeError):
        def __getattribute__(self, name):
            if name in {"code", "args", "__dict__", "prepare_phase", "filesystem_reason"}:
                raise AssertionError("untrusted exception inspected")
            return super().__getattribute__(name)

        def __setattr__(self, name, value):
            raise AssertionError("untrusted exception changed")

    error = PoisonError.__new__(PoisonError)
    ValueError.__init__(error, "not-serialized")

    def refusing(handle):
        handle.prepare_phase = "version"
        raise error

    monkeypatch.setattr(runtime.Runtime, "_prepare", refusing)
    with pytest.raises(PoisonError) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert raised.value is error and synthetic.calls == []


@pytest.mark.parametrize("defect,reason", [("nonregular", "file_not_regular"), ("hardlink", "hardlink"),
                                         ("identity", "identity_drift")])
def test_file_guard_diagnostic_does_not_relax_exact_original_refusal(tmp_path, monkeypatch, defect, reason):
    path = tmp_path / "ordinary"
    path.write_bytes(b"owned")
    parent = runtime.Directory(tmp_path)
    original = runtime.os.fstat

    def observing(fd):
        observed = original(fd)
        if stat.S_ISREG(observed.st_mode):
            values = {key: getattr(observed, key) for key in ("st_mode", "st_nlink", "st_dev", "st_ino")}
            if defect == "nonregular":
                values["st_mode"] = stat.S_IFIFO
            elif defect == "hardlink":
                values["st_nlink"] = 2
            else:
                values["st_ino"] += 1
            return SimpleNamespace(**values)
        return observed

    monkeypatch.setattr(runtime.os, "fstat", observing)
    try:
        with pytest.raises(runtime.GrypeRuntimeError) as raised:
            parent.open(path.name, os.O_RDONLY)
        assert raised.value.args == ("filesystem",) and raised.value.filesystem_reason == reason
        assert path.read_bytes() == b"owned"
    finally:
        parent.close()


def test_directory_and_tree_specific_diagnostics_preserve_refusal(synthetic, tmp_path, monkeypatch):
    leaf = tmp_path / "regular"
    leaf.write_bytes(b"file")
    with pytest.raises(runtime.GrypeRuntimeError) as raised:
        runtime.Directory(leaf)
    assert raised.value.filesystem_reason == "directory_not_safe"
    with runtime.prepared_grype(**synthetic.args) as handle:
        assert handle.prepare_phase is None
        with monkeypatch.context() as scoped:
            previous = runtime.Directory.entry

            def observing(directory, name):
                value = previous(directory, name)
                return SimpleNamespace(st_mode=stat.S_IFIFO) if name == "grype" else value
            scoped.setattr(runtime.Directory, "entry", observing)
            with pytest.raises(runtime.GrypeRuntimeError) as raised:
                handle.budget_tree()
            assert raised.value.filesystem_reason == "tree_nonregular"
            assert raised.value.prepare_phase is None


@pytest.mark.parametrize("mode,links,size,reason", [
    (stat.S_IFIFO, 1, 0, "tree_nonregular"),
    (stat.S_IFREG, 0, 1, "tree_unlinked"),
    (stat.S_IFREG, 2, 1, "tree_hardlink"),
    (stat.S_IFREG, 1, runtime.MAX_DB_FILE + 1, "tree_file_oversize"),
])
def test_update_tree_refusal_identifies_exact_stat_branch_and_preserves_primary(
        synthetic, monkeypatch, mode, links, size, reason):
    previous = runtime.run
    errors = []

    def running(command, **kwargs):
        if "update" not in command:
            return previous(command, **kwargs)
        with monkeypatch.context() as scoped:
            entry = runtime.Directory.entry

            def observing(directory, name):
                value = entry(directory, name)
                if directory.path == kwargs["cwd"] and name == "grype":
                    return SimpleNamespace(st_mode=mode, st_nlink=links, st_size=size)
                return value

            scoped.setattr(runtime.Directory, "entry", observing)
            try:
                kwargs["monitor"]()
            except runtime.GrypeRuntimeError as error:
                errors.append(error)
                raise
        pytest.fail("unsafe tree must refuse before update completes")

    monkeypatch.setattr(runtime, "run", running)
    with pytest.raises(runtime.GrypeRuntimeError) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert raised.value is errors[0]
    assert raised.value.args == ("filesystem",) and raised.value.__cause__ is None
    assert raised.value.prepare_phase == "update" and raised.value.filesystem_reason == reason
    assert len(synthetic.calls) == 2 and not list(synthetic.scratch.iterdir())


def test_tree_regular_file_at_exact_size_limit_remains_accepted(synthetic, monkeypatch):
    with runtime.prepared_grype(**synthetic.args) as handle:
        with monkeypatch.context() as scoped:
            entry = runtime.Directory.entry

            def observing(directory, name):
                value = entry(directory, name)
                if directory.path == handle.path and name == "grype":
                    return SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_size=runtime.MAX_DB_FILE)
                return value

            scoped.setattr(runtime.Directory, "entry", observing)
            handle.budget_tree()
        handle.check_files()
    assert not list(synthetic.scratch.iterdir())


@contextmanager
def reported_tree_stats(monkeypatch, changes):
    previous = runtime.Directory.entry

    def observing(directory, name):
        value = previous(directory, name)
        change = changes.get(directory.path / name)
        if change is None:
            return value
        fields = {key: getattr(value, key) for key in dir(value) if key.startswith("st_")}
        fields.update(change)
        return SimpleNamespace(**fields)

    with monkeypatch.context() as scoped:
        scoped.setattr(runtime.Directory, "entry", observing)
        yield


@pytest.mark.parametrize("location", ["", "home", "tmp", "cache", "database", "database/6"])
def test_sqlite_tree_cap_uses_only_private_basename_and_final_shape_still_refuses(synthetic, monkeypatch, location):
    with runtime.prepared_grype(**synthetic.args) as handle:
        path = handle.path / location / "vulnerability.db"
        created = not path.exists()
        if created:
            path.write_bytes(b"owned test bytes")
        original = path.read_bytes()
        try:
            with reported_tree_stats(monkeypatch, {path: {"st_size": 3 * 1024 * runtime.CHUNK}}):
                handle.budget_tree()
            if created:
                with pytest.raises(runtime.GrypeRuntimeError) as raised:
                    handle.check_files()
                assert raised.value.code in {"filesystem", "database"}
                assert path.read_bytes() == original
            else:
                handle.check_files()
        finally:
            if created:
                path.unlink()  # The test disposes only the file it created, not runtime cleanup.
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("relative", ["grype", "asset.tar.gz", "grype.json", "database/6/import.json"])
def test_other_tree_files_keep_two_gib_cap(synthetic, monkeypatch, relative):
    with runtime.prepared_grype(**synthetic.args) as handle:
        path = handle.path / relative
        with reported_tree_stats(monkeypatch, {path: {"st_size": 3 * 1024 * runtime.CHUNK}}):
            with pytest.raises(runtime.GrypeRuntimeError) as raised:
                handle.budget_tree()
            assert raised.value.args == ("filesystem",)
            assert raised.value.filesystem_reason == "tree_file_oversize"
        handle.check_files()


@pytest.mark.parametrize("sqlite_bytes,asset_bytes,error", [
    (runtime.MAX_WORKSPACE, 0, None),
    (runtime.MAX_WORKSPACE + 1, 0, "filesystem"),
    (3 * 1024 * runtime.CHUNK, 1024 * runtime.CHUNK, None),
    (3 * 1024 * runtime.CHUNK, 1024 * runtime.CHUNK + 1, "byte_budget"),
])
def test_sqlite_tree_cap_preserves_exact_per_file_and_aggregate_bounds(
        synthetic, monkeypatch, sqlite_bytes, asset_bytes, error):
    assert runtime.MAX_SQLITE_DB_FILE == runtime.MAX_WORKSPACE == 4 * 1024 * runtime.CHUNK
    assert runtime.MAX_DB_FILE == 2 * 1024 * runtime.CHUNK
    with runtime.prepared_grype(**synthetic.args) as handle:
        # Report sizes only: no multi-GiB files or allocations are created.
        changes = {path: {"st_size": 0} for path in handle.path.rglob("*") if path.is_file()}
        changes[handle.cache / "6" / "vulnerability.db"] = {"st_size": sqlite_bytes}
        changes[handle.path / "asset.tar.gz"] = {"st_size": asset_bytes}
        with reported_tree_stats(monkeypatch, changes):
            if error is None:
                handle.budget_tree()
            else:
                with pytest.raises(runtime.GrypeRuntimeError) as raised:
                    handle.budget_tree()
                assert raised.value.args == (error,)
                if error == "filesystem":
                    assert raised.value.filesystem_reason == "tree_file_oversize"
        handle.check_files()


@pytest.mark.parametrize("mode,links,reason", [(stat.S_IFIFO, 1, "tree_nonregular"),
                                             (stat.S_IFREG, 0, "tree_unlinked"),
                                             (stat.S_IFREG, 2, "tree_hardlink")])
def test_sqlite_cap_never_relaxes_type_or_link_guards(synthetic, monkeypatch, mode, links, reason):
    with runtime.prepared_grype(**synthetic.args) as handle:
        path = handle.cache / "6" / "vulnerability.db"
        with reported_tree_stats(monkeypatch, {path: {"st_mode": mode, "st_nlink": links}}):
            with pytest.raises(runtime.GrypeRuntimeError) as raised:
                handle.budget_tree()
            assert raised.value.args == ("filesystem",) and raised.value.filesystem_reason == reason
        handle.check_files()


def test_sqlite_update_adoption_and_file_guard_use_same_cap_without_new_commands(synthetic, tmp_path, monkeypatch):
    previous_run, previous_adopt = runtime.run, runtime.Runtime.adopt_database

    def running(command, **kwargs):
        result = previous_run(command, **kwargs)
        if "update" in command:
            path = kwargs["cwd"] / "database" / "6" / "vulnerability.db"
            with reported_tree_stats(monkeypatch, {path: {"st_size": 3 * 1024 * runtime.CHUNK}}):
                kwargs["monitor"]()
        return result

    def adopting(handle):
        path = handle.cache / "6" / "vulnerability.db"
        with reported_tree_stats(monkeypatch, {path: {"st_size": 3 * 1024 * runtime.CHUNK}}):
            previous_adopt(handle)

    monkeypatch.setattr(runtime, "run", running)
    monkeypatch.setattr(runtime.Runtime, "adopt_database", adopting)
    with runtime.prepared_grype(**synthetic.args) as handle:
        assert handle.db_guards["vulnerability.db"].limit == runtime.MAX_SQLITE_DB_FILE
        assert all(guard.limit == runtime.MAX_DB_FILE for name, guard in handle.db_guards.items()
                   if name != "vulnerability.db")
        assert handle.binary_guard.limit == runtime.MAX_BINARY
        assert handle.archive_guard.limit == len(synthetic.archive)
        assert handle.config_guard.limit == runtime.CHUNK
        handle.run_query(QUERY, tmp_path / "bounded-query.json")
        handle.assert_unchanged()
        assert [call[3:] for call in synthetic.calls[1:]] == [
            ("version", "-o", "json"), ("db", "update"), ("db", "status", "-o", "json"),
            ("--platform", "linux/amd64", "-o", "json", QUERY),
        ]
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("name,size", [("vulnerability.db", runtime.MAX_WORKSPACE + 1),
                                      ("import.json", 3 * 1024 * runtime.CHUNK),
                                      ("last_update_check", 3 * 1024 * runtime.CHUNK)])
def test_sqlite_adoption_refuses_oversize_without_adopting_or_deleting_unknown(synthetic, monkeypatch, name, size):
    previous = runtime.Runtime.adopt_database
    errors, rejected = [], []

    def adopting(handle):
        path = handle.cache / "6" / name
        rejected.append((path, path.read_bytes()))
        with reported_tree_stats(monkeypatch, {path: {"st_size": size}}):
            try:
                previous(handle)
            except runtime.GrypeRuntimeError as error:
                errors.append(error)
                raise

    monkeypatch.setattr(runtime.Runtime, "adopt_database", adopting)
    with pytest.raises(runtime.GrypeRuntimeError) as raised:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("oversize adoption must not yield")
    assert raised.value is errors[0] and raised.value.args == ("database",)
    assert raised.value.prepare_phase == "adopt_database"
    assert raised.value.__notes__ == ["owned_cleanup_failed"]
    assert rejected[0][0].read_bytes() == rejected[0][1]


def test_sqlite_cap_preserves_tree_entry_count_and_deadline(synthetic, monkeypatch):
    assert runtime.MAX_ENTRIES == 128 and runtime.WALL_SECONDS == 600 and runtime.MAX_QUERIES == 32
    with runtime.prepared_grype(**synthetic.args) as handle:
        files = []
        try:
            for ordinal in range(runtime.MAX_ENTRIES):
                path = handle.path / "tmp" / str(ordinal)
                path.write_bytes(b"")
                files.append(path)
            with pytest.raises(runtime.GrypeRuntimeError, match="byte_budget"):
                handle.budget_tree()
        finally:
            for path in files:
                path.unlink()
        with monkeypatch.context() as scoped:
            scoped.setattr(handle, "deadline", time.monotonic() - 1)
            with pytest.raises(runtime.GrypeRuntimeError, match="deadline"):
                handle.budget_tree()
        handle.check_files()


@pytest.mark.parametrize("mutation", ["platform", "url", "hash", "bytes", "version", "commit", "checksum", "schema"])
def test_manifest_exact_pins_refuse_adversarial_input(mutation):
    value = manifest()
    if mutation == "platform":
        platform = "windows/amd64"
    else:
        platform = "linux/amd64"
        if mutation in {"url", "hash", "bytes"}:
            key = {"hash": "sha256"}.get(mutation, mutation)
            value["archives"][platform][key] = {"url": "https://evil.invalid/tool", "hash": "0" * 64,
                                                "bytes": 1}[mutation]
        elif mutation == "schema":
            value[mutation] = True
        else:
            value[{"checksum": "checksum_file_sha256"}.get(mutation, mutation)] = "wrong"
    with pytest.raises(runtime.GrypeRuntimeError, match="manifest"):
        runtime.validate_manifest(value, platform)


def test_official_asset_literal_pins_and_native_platform():
    assert runtime.PINS["linux/amd64"] == (
        "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d", 32270829)
    assert runtime.PINS["linux/arm64"] == (
        "29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514", 29446856)
    if sys.platform != "linux":
        with pytest.raises(runtime.GrypeRuntimeError, match="platform"):
            runtime.native_platform()


def test_bad_download_hash_refuses_before_executable(synthetic):
    synthetic.archive = synthetic.archive[:-1] + bytes([synthetic.archive[-1] ^ 1])
    with pytest.raises(runtime.GrypeRuntimeError, match="download"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert len(synthetic.calls) == 1
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("kind,name", [(tarfile.SYMTYPE, "grype"), (tarfile.LNKTYPE, "grype"),
    (tarfile.FIFOTYPE, "grype"), (tarfile.DIRTYPE, "grype"), (tarfile.REGTYPE, "../grype"),
    (tarfile.REGTYPE, "/grype"), (tarfile.REGTYPE, "other"), (tarfile.REGTYPE, "grype/child")])
def test_tar_member_types_and_names_fail_before_extraction(kind, name):
    data = asset_bytes([(name, kind, b"payload")])
    with pytest.raises(runtime.GrypeRuntimeError):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz", tarinfo=runtime.AssetTarInfo) as archive:
            list(archive)


@pytest.mark.parametrize("format", [tarfile.PAX_FORMAT, tarfile.GNU_FORMAT])
def test_extended_headers_refused_before_hidden_payload_allocation(format):
    data = asset_bytes([("x" * 200, tarfile.REGTYPE, b"payload")], format=format)
    with pytest.raises(runtime.GrypeRuntimeError, match="archive"):
        tarfile.open(fileobj=io.BytesIO(data), mode="r|gz", tarinfo=runtime.AssetTarInfo)


def test_official_four_regular_member_layout_extracts_only_binary(synthetic, monkeypatch):
    entries = [("CHANGELOG.md", tarfile.REGTYPE, b"changelog"), ("LICENSE", tarfile.REGTYPE, b"license"),
               ("README.md", tarfile.REGTYPE, b"readme"), ("grype", tarfile.REGTYPE, b"synthetic binary")]
    synthetic.archive = asset_bytes(entries)
    monkeypatch.setattr(runtime, "PINS", {name: (hashlib.sha256(synthetic.archive).hexdigest(), len(synthetic.archive))
                                         for name in runtime.PINS})
    synthetic.args["manifest_path"].write_bytes(runtime.canonical(manifest()))
    with runtime.prepared_grype(**synthetic.args) as handle:
        assert (handle.path / "grype").read_bytes() == b"synthetic binary"
        assert not any((handle.path / name).exists() for name in ("CHANGELOG.md", "LICENSE", "README.md"))
        assert runtime.ASSET_MEMBERS == {name for name, _, _ in entries}
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE,
                                 tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                                 tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE])
def test_changelog_nonregular_and_extended_headers_refused_before_processing(kind, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("extended member handler must never run")
    monkeypatch.setattr(tarfile.TarInfo, "_proc_pax", forbidden)
    monkeypatch.setattr(tarfile.TarInfo, "_proc_gnulong", forbidden)
    monkeypatch.setattr(tarfile.TarInfo, "_proc_sparse", forbidden)
    data = asset_bytes([("CHANGELOG.md", kind, b"payload")])
    with pytest.raises(runtime.GrypeRuntimeError, match="archive"):
        tarfile.open(fileobj=io.BytesIO(data), mode="r|gz", tarinfo=runtime.AssetTarInfo)


@pytest.mark.parametrize("name", ["../CHANGELOG.md", "/CHANGELOG.md", "sub/CHANGELOG.md", "CHANGELOG.md/child",
                                 "Changelog.md", "OTHER.md"])
def test_changelog_allowlist_does_not_accept_other_paths_or_names(name):
    data = asset_bytes([(name, tarfile.REGTYPE, b"payload")])
    with pytest.raises(runtime.GrypeRuntimeError, match="archive"):
        tarfile.open(fileobj=io.BytesIO(data), mode="r|gz", tarinfo=runtime.AssetTarInfo)


def test_changelog_size_guard_refuses_header_before_reading_body():
    header = tarfile.TarInfo("CHANGELOG.md")
    header.size = runtime.CHUNK + 1
    data = gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024)
    with pytest.raises(runtime.GrypeRuntimeError, match="byte_budget"):
        tarfile.open(fileobj=io.BytesIO(data), mode="r|gz", tarinfo=runtime.AssetTarInfo)


@pytest.mark.parametrize("fifth", ["CHANGELOG.md", "grype", "unexpected.md"])
def test_fifth_or_duplicate_changelog_refuses_before_execution_and_cleans(synthetic, monkeypatch, fifth):
    names = ["CHANGELOG.md", "LICENSE", "README.md", "grype", fifth]
    synthetic.archive = asset_bytes([(name, tarfile.REGTYPE, b"payload") for name in names])
    monkeypatch.setattr(runtime, "PINS", {name: (hashlib.sha256(synthetic.archive).hexdigest(), len(synthetic.archive))
                                         for name in runtime.PINS})
    synthetic.args["manifest_path"].write_bytes(runtime.canonical(manifest()))
    with pytest.raises(runtime.GrypeRuntimeError, match="archive"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert len(synthetic.calls) == 1 and not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("entries", [[("grype", tarfile.REGTYPE, b"one"), ("grype", tarfile.REGTYPE, b"two")],
                                    [("LICENSE", tarfile.REGTYPE, b"license")]])
def test_duplicate_or_missing_binary_refused(synthetic, monkeypatch, entries):
    synthetic.archive = asset_bytes(entries)
    pins = {name: (hashlib.sha256(synthetic.archive).hexdigest(), len(synthetic.archive)) for name in runtime.PINS}
    monkeypatch.setattr(runtime, "PINS", pins)
    synthetic.args["manifest_path"].write_bytes(runtime.canonical(manifest()))
    with pytest.raises(runtime.GrypeRuntimeError, match="archive"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("key", ["version", "gitCommit", "platform", "application"])
def test_actual_version_fields_required(synthetic, key):
    synthetic.version = {"application": "grype", "version": runtime.VERSION,
                         "gitCommit": runtime.COMMIT, "platform": "linux/amd64"}
    synthetic.version[key] = "wrong"
    with pytest.raises(runtime.GrypeRuntimeError, match="version"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("key,value", [("valid", False), ("valid", 1), ("error", "secret-canary"),
    ("error", {}), ("schemaVersion", 6), ("schemaVersion", "5.1.0"), ("path", "/foreign/db"),
    ("from", "https://evil.invalid/archive.tar.zst"), ("from", "https://grype.anchore.io/databases/v6/a.tar.zst"),
    ("built", "yesterday"), ("built", "2000-01-01T00:00:00Z")])
def test_database_status_must_be_real_official_valid_current_and_owned(tmp_path, key, value):
    cache = tmp_path / "database"
    state = status(cache)
    state[key] = value
    with pytest.raises(runtime.GrypeRuntimeError, match="database") as caught:
        runtime.validate_status(state, cache, datetime.now(UTC).isoformat())
    assert "secret-canary" not in str(caught.value)


def test_database_future_status_and_fetched_time_refused(tmp_path):
    cache = tmp_path / "database"
    value = status(cache)
    value["built"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    with pytest.raises(runtime.GrypeRuntimeError, match="database"):
        runtime.validate_status(value, cache, datetime.now(UTC).isoformat())
    value = status(cache)
    with pytest.raises(runtime.GrypeRuntimeError, match="database"):
        runtime.validate_status(value, cache, (datetime.now(UTC) + timedelta(seconds=1)).isoformat())


def test_official_v6_pair_preserves_raw_status_import_and_command_trace(synthetic):
    # Pinned producer: SchemaVer.String and writeImportMetadata both retain "v".
    with runtime.prepared_grype(**synthetic.args) as handle:
        observed = status(handle.cache)
        observed["built"] = handle.database_status["built"]
        assert handle.database_status == observed
        assert handle.status_bytes == runtime.canonical(observed)
        imported = handle.db_guards["import.json"].read_json()
        assert imported == {"source": observed["from"], "digest": "xxh64:" + "a" * 16,
                            "client_version": "v6.1.10"}
        assert handle.db_guards["import.json"].sha256 == hashlib.sha256(
            runtime.canonical(imported)).hexdigest()
        operations = ["download" if command[0] == sys.executable else
                      next(operation for operation in ("version", "update", "status")
                           if operation in command) for command in synthetic.calls]
        assert operations == ["download", "version", "update", "status"]
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("value", ["6.1.10", "v5.1.10", "v7.1.10", "v6.1", "v6.1.10.0",
                                  "v6.1.1000", " v6.1.10", "v6.1.10\n", True, 6, 6.1, None, {}, []])
def test_official_schema_representation_refuses_aliases_without_normalization(tmp_path, value):
    cache = tmp_path / "database"
    observed = status(cache)
    observed["schemaVersion"] = value
    before = runtime.canonical(observed)
    with pytest.raises(runtime.GrypeRuntimeError, match="database"):
        runtime.validate_status(observed, cache, datetime.now(UTC).isoformat())
    assert runtime.canonical(observed) == before


@pytest.mark.parametrize("field,phase", [("schemaVersion", "status"),
                                        ("client_version", "import_validation")])
def test_unprefixed_producer_field_refuses_before_yield_with_complete_cleanup(
        synthetic, monkeypatch, field, phase):
    original_run = runtime.run

    def run(command, **kwargs):
        raw = original_run(command, **kwargs)
        if field == "schemaVersion" and "status" in command:
            observed = runtime.decode_json(raw)
            observed[field] = "6.1.10"
            return runtime.canonical(observed)
        return raw

    def mutate(database):
        path = database / "import.json"
        observed = json.loads(path.read_bytes())
        observed[field] = "6.1.10"
        path.write_bytes(runtime.canonical(observed))

    monkeypatch.setattr(runtime, "run", run)
    if field == "client_version":
        synthetic.update_mutate = mutate
    with pytest.raises(runtime.GrypeRuntimeError, match="database") as caught:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert caught.value.prepare_phase == phase
    assert len(synthetic.calls) == 4
    assert not list(synthetic.scratch.iterdir())
    assert not getattr(caught.value, "__notes__", [])


def test_database_update_failure_no_fallback(synthetic):
    synthetic.update_fail = True
    with pytest.raises(runtime.GrypeRuntimeError, match="nonzero"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert not any("status" in command for command in synthetic.calls)
    assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("key,value", [("only-fixed", True), ("only-notfixed", True), ("ignore-wontfix", "wont-fix"),
    ("ignore", [{"vulnerability": "CVE-canary"}]), ("exclude", ["/**"]), ("vex-documents", ["secret"]),
    ("vex-add", ["not_affected"]), ("include-matcher-suppressions", False), ("add-cpes-if-none", True),
    ("fail-on-severity", "high"), ("distro", "alpine:fake"), ("file", "/foreign/output"),
    ("platform", "windows/amd64"), ("new-filter", {"ignore": ["secret"]})])
def test_effective_configuration_filters_refused(tmp_path, key, value):
    cache = tmp_path / "database"
    config = configuration(cache)
    config[key] = value
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(config, cache, "linux/amd64")


@pytest.mark.parametrize("enabled", [False, True])
def test_pinned_producer_kernel_header_suppression_branch_keeps_empty_ignore_required(tmp_path, enabled):
    # Grype 6f8d854 cmd/grype/cli/commands/root.go:114-118,146-147;
    # these are producer rules, not permission to accept ignored findings.
    rules = [{"vulnerability": "", "include-aliases": False, "reason": "", "namespace": "",
              "fix-state": "", "package": {"name": name, "version": "", "language": "", "type": kind,
                                            "location": "", "upstream-name": upstream},
              "vex-status": "", "vex-justification": "", "match-type": "exact-indirect-match"}
             for name, upstream, kind in [("kernel-headers", "kernel", "rpm"),
                                          ("linux(-.*)?-headers-.*", "linux.*", "deb"),
                                          ("linux-libc-dev", "linux", "deb"),
                                          ("linux-kbuild-.*", "linux.*", "deb")]]
    cache = tmp_path / "database"
    config = configuration(cache)
    config["match-upstream-kernel-headers"] = enabled
    if not enabled:
        config["ignore"].extend(rules)
    before = runtime.canonical(config)
    assert len(config["ignore"]) == (0 if enabled else 4)
    if enabled:
        runtime.validate_configuration(config, cache, "linux/amd64")
    else:
        with pytest.raises(runtime.GrypeRuntimeError, match="config"):
            runtime.validate_configuration(config, cache, "linux/amd64")
        config["match-upstream-kernel-headers"] = True
        with pytest.raises(runtime.GrypeRuntimeError, match="config"):
            runtime.validate_configuration(config, cache, "linux/amd64")
        config["match-upstream-kernel-headers"] = enabled
    assert runtime.canonical(config) == before


@pytest.mark.parametrize("mutation", ["absent", "false", "zero", "one", "string", "integer_subclass"])
def test_kernel_header_matching_requires_present_exact_true_boolean(tmp_path, mutation):
    class IntegerAlias(int):
        pass

    cache = tmp_path / "database"
    config = configuration(cache)
    if mutation == "absent":
        config.pop("match-upstream-kernel-headers")
    else:
        config["match-upstream-kernel-headers"] = {
            "false": False, "zero": 0, "one": 1, "string": "true", "integer_subclass": IntegerAlias(1),
        }[mutation]
    before = runtime.canonical(config)
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(config, cache, "linux/amd64")
    assert runtime.canonical(config) == before


@pytest.mark.parametrize("key,value", [("cache-dir", "/foreign/db"), ("auto-update", True),
    ("validate-age", False), ("validate-by-hash-on-start", False), ("require-update-check", False),
    ("update-url", "https://evil.invalid"), ("max-allowed-built-age", "120h"), ("ca-cert", "/foreign/ca")])
def test_effective_database_config_paths_and_security_policy_refused(tmp_path, key, value):
    cache = tmp_path / "database"
    config = configuration(cache)
    config["db"][key] = value
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(config, cache, "linux/amd64")


def test_signing_pure_configuration_validator_uses_captured_defaults():
    cache = PurePosixPath("/home/runner/private/grype-" + "a" * 32 + "/database")
    value = configuration(cache)
    runtime.validate_configuration(value)
    value["db"]["cache-dir"] = "/home/runner/../foreign/database"
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(value)


@pytest.mark.parametrize("identifier", ["", "--version", "https://evil.invalid", "pkg:golang/golang.org/x/sys",
    "pkg:golang/../x@v1.2.3", "pkg:golang/x@v1.2.3?secret=x", "pkg:golang/x@v1.2.3\n--flag",
    "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "cpe:2.3:a:redis:redis:-:*:*:*:*:*:*:*", "x" * 2049])
def test_identifier_is_bounded_literal_versioned_not_url_or_option(identifier):
    with pytest.raises(runtime.GrypeRuntimeError, match="identifier"):
        runtime.validate_identifier(identifier)


@pytest.mark.parametrize("identifier", [QUERY, CPE, "pkg:golang/github.com/tianon/gosu@v1.21.0",
                                        "pkg:golang/github.com/tianon/gosu@1.19"])
def test_source_verified_identifier_forms_supported(identifier):
    runtime.validate_identifier(identifier)


@pytest.mark.parametrize("name", ["grype", "grype.json", "asset.tar.gz", "database/6/vulnerability.db",
                                "database/6/import.json", "database/6/last_update_check"])
def test_prequery_file_drift_refuses_and_cleans_owned(synthetic, tmp_path, name):
    with runtime.prepared_grype(**synthetic.args) as handle:
        target = handle.path / name
        os.chmod(target, 0o600)
        target.write_bytes(target.read_bytes() + b"changed")
        before = len(synthetic.calls)
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            handle.run_query(QUERY, tmp_path / "query.json")
        assert len(synthetic.calls) == before
    assert not list(synthetic.scratch.iterdir())


def test_inplace_database_flip_restore_after_query_detected_by_stat(synthetic, tmp_path):
    def mutate(workspace):
        path = workspace / "database/6/vulnerability.db"
        original = path.read_bytes()
        os.chmod(path, 0o600)
        with path.open("r+b") as file:
            file.write(b"changed")
            file.flush()
            file.seek(0)
            file.write(original)
            file.truncate()
        assert path.read_bytes() == original
    synthetic.mutate = mutate
    with runtime.prepared_grype(**synthetic.args) as handle:
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            handle.run_query(QUERY, tmp_path / "query.json")
    assert not list(synthetic.scratch.iterdir())


def test_query_count_and_global_budget_refused_before_execution(synthetic, tmp_path):
    with runtime.prepared_grype(**synthetic.args) as handle:
        handle.queries = runtime.MAX_QUERIES
        with pytest.raises(runtime.GrypeRuntimeError, match="query_budget"):
            handle.run_query(QUERY, tmp_path / "query.json")
        handle.queries = 0
        handle.deadline = time.monotonic() - 1
        with pytest.raises(runtime.GrypeRuntimeError, match="deadline"):
            handle.run_query(QUERY, tmp_path / "query.json")
    assert not list(synthetic.scratch.iterdir())


def test_output_collision_preserved(synthetic, tmp_path):
    output = tmp_path / "query.json"
    output.write_bytes(b"foreign")
    with runtime.prepared_grype(**synthetic.args) as handle:
        with pytest.raises(FileExistsError):
            handle.run_query(QUERY, output)
    assert output.read_bytes() == b"foreign"
    assert not list(synthetic.scratch.iterdir())


def test_uuid_collision_fails_without_cleanup_of_foreign_directory(synthetic, monkeypatch):
    monkeypatch.setattr(runtime, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    collision = synthetic.scratch / ("grype-" + "a" * 32)
    collision.mkdir()
    (collision / "foreign").write_bytes(b"foreign")
    with pytest.raises(runtime.GrypeRuntimeError, match="filesystem"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert (collision / "foreign").read_bytes() == b"foreign"


@pytest.mark.parametrize("primary", [RuntimeError("primary-canary"), KeyboardInterrupt(), SystemExit(7)])
def test_cleanup_refusal_preserves_primary_cancel_and_foreign_files(synthetic, primary):
    with pytest.raises(type(primary)) as caught:
        with runtime.prepared_grype(**synthetic.args) as handle:
            unknown = handle.path / "foreign"
            unknown.write_bytes(b"foreign")
            raise primary
    assert caught.value is primary
    assert "owned_cleanup_failed" in caught.value.__notes__
    assert unknown.read_bytes() == b"foreign"
    assert not (unknown.parent / "grype").exists()
    unknown.unlink()
    unknown.parent.rmdir()


def test_success_cleanup_refusal_never_announces_success(synthetic):
    with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
        with runtime.prepared_grype(**synthetic.args) as handle:
            unknown = handle.path / "foreign"
            unknown.write_bytes(b"foreign")
    assert unknown.read_bytes() == b"foreign"
    unknown.unlink()
    unknown.parent.rmdir()


def test_clean_room_environment_discards_proxy_config_cache_credentials(synthetic, monkeypatch):
    for key in ("GRYPE_IGNORE", "SYFT_CONFIG", "HTTP_PROXY", "https_proxy", "NO_PROXY", "SSL_CERT_FILE",
                "AWS_SECRET_ACCESS_KEY", "DOCKER_CONFIG", "PYTHONPATH"):
        monkeypatch.setenv(key, "secret-canary")
    result = runtime.clean_environment(synthetic.scratch)
    assert "secret-canary" not in repr(result)
    assert result["HOME"] == str(synthetic.scratch / "home")
    assert not any(key.lower().startswith(("grype_", "syft_")) or "proxy" in key.lower() for key in result)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'[]', b'\xff', b'secret-canary'])
def test_json_duplicates_constants_nonobject_and_untrusted_text_refused(raw):
    with pytest.raises(runtime.GrypeRuntimeError) as caught:
        runtime.decode_json(raw)
    assert "secret-canary" not in str(caught.value)


def test_json_output_bounded_before_parse():
    with pytest.raises(runtime.GrypeRuntimeError, match="output_budget"):
        runtime.decode_json(b" " * 17, limit=16)


def test_real_subprocess_stdout_bound_stderr_suppressed_and_reaped(tmp_path):
    with pytest.raises(runtime.GrypeRuntimeError, match="output_budget") as caught:
        runtime.run([sys.executable, "-I", "-B", "-c",
                     "import sys;sys.stderr.write('secret-canary');sys.stdout.write('x'*65536)"],
                    environment=runtime.clean_environment(tmp_path), cwd=tmp_path,
                    deadline=time.monotonic() + 5, limit=4096)
    assert "secret-canary" not in str(caught.value)


def test_real_subprocess_timeout_and_nonzero_are_bounded(tmp_path):
    for program, expected, timeout in [("import time;time.sleep(60)", "timeout", 0.15),
                                       ("raise SystemExit(23)", "nonzero", 2)]:
        started = time.monotonic()
        with pytest.raises(runtime.GrypeRuntimeError, match=expected):
            runtime.run([sys.executable, "-I", "-B", "-c", program],
                        environment=runtime.clean_environment(tmp_path), cwd=tmp_path,
                        deadline=time.monotonic() + 5, timeout=timeout, limit=4096)
        assert time.monotonic() - started < 5


@pytest.mark.skipif(os.name != "posix", reason="real owned descendant process-group proof requires POSIX")
def test_real_subprocess_descendants_cannot_keep_pipe_alive_after_timeout(tmp_path):
    started = time.monotonic()
    program = ("import subprocess,sys,time;"
               "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)")
    with pytest.raises(runtime.GrypeRuntimeError, match="timeout"):
        runtime.run([sys.executable, "-I", "-B", "-c", program],
                    environment=runtime.clean_environment(tmp_path), cwd=tmp_path,
                    deadline=time.monotonic() + 5, timeout=0.2, limit=4096)
    assert time.monotonic() - started < 3


def test_source_guard_handles_actual_binary_bytes_and_refuses_changes(tmp_path):
    file = tmp_path / "bytes"
    original = b"prefix\r\n\x1asuffix\x00"
    file.write_bytes(original)
    parent = runtime.Directory(tmp_path)
    guard = runtime.FileGuard(parent, file.name, limit=4096, deadline=time.monotonic() + 5)
    try:
        assert guard.sha256 == hashlib.sha256(original).hexdigest()
        guard.check()
        file.write_bytes(original + b"changed")
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            guard.check()
    finally:
        guard.close()
        parent.close()


def test_source_symlink_or_hardlink_refused(tmp_path):
    target = tmp_path / "original"
    target.write_bytes(b"owned bytes")
    linked = tmp_path / "linked"
    os.link(target, linked)
    parent = runtime.Directory(tmp_path)
    try:
        with pytest.raises(runtime.GrypeRuntimeError, match="filesystem"):
            runtime.FileGuard(parent, linked.name, limit=4096, deadline=time.monotonic() + 5)
    finally:
        parent.close()


def test_workspace_budget_checks_before_tool_can_proceed(synthetic, monkeypatch):
    with runtime.prepared_grype(**synthetic.args) as handle:
        monkeypatch.setattr(runtime, "MAX_WORKSPACE", 1)
        with pytest.raises(runtime.GrypeRuntimeError, match="byte_budget"):
            handle.budget_tree()


@pytest.mark.parametrize("name", ["import.json", "vulnerability.db"])
def test_missing_database_file_refuses_and_cleans_recognized_owned_files(synthetic, name):
    synthetic.update_mutate = lambda database: (database / name).unlink()
    with pytest.raises(runtime.GrypeRuntimeError, match="database"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert not list(synthetic.scratch.iterdir())


def test_extra_database_file_refuses_and_preserves_unknown(synthetic):
    unknowns = []

    def mutate(database):
        unknown = database / "foreign"
        unknown.write_bytes(b"foreign")
        unknowns.append(unknown)
    synthetic.update_mutate = mutate
    with pytest.raises(runtime.GrypeRuntimeError, match="database") as caught:
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert "owned_cleanup_failed" in caught.value.__notes__
    assert unknowns[0].read_bytes() == b"foreign"
    assert not (unknowns[0].parent / "vulnerability.db").exists()


@pytest.mark.parametrize("field,value", [("digest", "sha256:wrong"), ("source", "https://evil.invalid"),
                                      ("client_version", "6.1.10"), ("client_version", "v6.0.0"),
                                      ("client_version", "v5.1.10"), ("client_version", "v7.1.10"),
                                      ("client_version", "v6.1.10\n"), ("client_version", True),
                                      ("client_version", 6), ("client_version", None)])
def test_import_metadata_integrity_contract_is_not_invented_or_ignored(synthetic, field, value):
    def mutate(database):
        path = database / "import.json"
        metadata = json.loads(path.read_bytes())
        metadata[field] = value
        path.write_bytes(runtime.canonical(metadata))
    synthetic.update_mutate = mutate
    with pytest.raises(runtime.GrypeRuntimeError, match="database"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert not list(synthetic.scratch.iterdir())


def test_source_replacement_is_refused_or_natively_denied_and_foreign_preserved(synthetic):
    original = synthetic.args["manifest_path"]
    before = original.read_bytes()
    replacement = original.with_name("replacement")
    replacement.write_bytes(b"foreign")
    reached = False
    with runtime.prepared_grype(**synthetic.args) as handle:
        try:
            reached = True
            os.replace(replacement, original)
        except PermissionError:
            assert os.name == "nt" and reached
            assert original.read_bytes() == before
            assert replacement.read_bytes() == b"foreign"
            handle.check_files()
        else:
            with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
                handle.check_files()
            assert original.read_bytes() == b"foreign"
    assert reached and not list(synthetic.scratch.iterdir())


def test_owned_binary_replacement_never_deletes_foreign_target(synthetic):
    expected = pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed") if os.name == "posix" \
        else nullcontext()
    with expected:
        with runtime.prepared_grype(**synthetic.args) as handle:
            original = handle.path / "grype"
            before = original.read_bytes()
            replacement = handle.path / "replacement"
            replacement.write_bytes(b"foreign")
            try:
                os.replace(replacement, original)
            except PermissionError:
                assert os.name == "nt"
                assert original.read_bytes() == before
                assert replacement.read_bytes() == b"foreign"
                replacement.unlink()
                handle.check_files()
            else:
                with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
                    handle.check_files()
    if os.name == "posix":
        assert original.read_bytes() == b"foreign"
    else:
        assert not list(synthetic.scratch.iterdir())


@pytest.mark.parametrize("primary", [KeyboardInterrupt(), SystemExit(9)])
def test_query_cancel_preserves_primary_and_cleans_all_owned(synthetic, tmp_path, primary):
    def mutate(_):
        raise primary
    synthetic.mutate = mutate
    with pytest.raises(type(primary)) as caught:
        with runtime.prepared_grype(**synthetic.args) as handle:
            handle.run_query(QUERY, tmp_path / "cancel.json")
    assert caught.value is primary
    assert not list(synthetic.scratch.iterdir())
    assert (tmp_path / "cancel.json").is_file()


def test_all_32_queries_reuse_one_db_without_descriptor_or_fd_growth(synthetic, tmp_path):
    with runtime.prepared_grype(**synthetic.args) as handle:
        count = None
        for index in range(runtime.MAX_QUERIES):
            handle.run_query(QUERY, tmp_path / f"query-{index}.json")
            if count is None:
                count = len(handle.directories)
            assert len(handle.directories) == count
        handle.assert_unchanged()
        with pytest.raises(runtime.GrypeRuntimeError, match="query_budget"):
            handle.run_query(QUERY, tmp_path / "query-extra.json")
    assert sum("update" in command for command in synthetic.calls) == 1


def test_configuration_database_and_file_table_public_mutation_refused(synthetic, tmp_path):
    with runtime.prepared_grype(**synthetic.args) as handle:
        handle.run_query(QUERY, tmp_path / "query.json")
        saved = copy.deepcopy(handle.configuration)
        handle.configuration["only-fixed"] = True
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            handle.assert_unchanged()
        handle.configuration = saved
        handle.database_status["valid"] = False
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            handle.assert_unchanged()
        handle.database_status["valid"] = True
        handle.file_table["6/vulnerability.db"] = "0" * 64
        with pytest.raises(runtime.GrypeRuntimeError, match="identity_changed"):
            handle.assert_unchanged()


def test_configuration_changes_between_genuine_queries_refused(synthetic, tmp_path):
    with runtime.prepared_grype(**synthetic.args) as handle:
        report = handle.run_query(QUERY, tmp_path / "query.json")
        synthetic.report = copy.deepcopy(report)
        synthetic.report["descriptor"]["configuration"]["unrelated-default"] = "changed"
        with pytest.raises(runtime.GrypeRuntimeError, match="config"):
            handle.run_query(CPE, tmp_path / "query-second.json")
    assert not list(synthetic.scratch.iterdir())


def test_effective_default_expanded_config_not_required_to_equal_template(tmp_path):
    cache = tmp_path / "database"
    value = configuration(cache)
    assert value != runtime.TEMPLATE
    runtime.validate_configuration(value, cache, "linux/amd64")
    value["db"]["max-allowed-built-age"] = float(86400000000000)
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(value, cache, "linux/amd64")


def test_process_cleanup_failure_preserves_primary_and_marks_constant_secondary(monkeypatch):
    child = SimpleNamespace(pid=123, stdout=open(os.devnull, "rb", buffering=0), poll=lambda: 23,
                            returncode=23)
    monkeypatch.setattr(runtime, "OwnedPopen", lambda *_, **__: child)
    monkeypatch.setattr(runtime, "peek_owned_returncode", lambda owned: 23)
    monkeypatch.setattr(runtime.os, "read", lambda *_, **__: b"")
    monkeypatch.setattr(runtime, "cleanup_process", lambda *_, **__: (_ for _ in ()).throw(
        runtime.GrypeRuntimeError("owned_cleanup_failed")))
    with pytest.raises(runtime.GrypeRuntimeError, match="nonzero") as caught:
        runtime.run(["fixed"], environment={}, cwd=Path.cwd(), deadline=time.monotonic() + 5, limit=32)
    assert caught.value.__notes__ == ["owned_cleanup_failed"]
    child.stdout.close()


@pytest.mark.skipif(os.name != "posix", reason="real owned descendant process-group proof requires POSIX")
def test_descendants_cleaned_even_when_direct_parent_succeeds(tmp_path):
    witness = run_owned_descendant(tmp_path, seconds=60)
    assert_owned_descendant_stopped(witness)


def descendant_witness(raw):
    value = runtime.decode_json(raw, 4096)
    assert set(value) == {"pid", "startticks"}
    assert all(type(value[key]) is int and value[key] > 0 for key in value)
    return value


def descendant_stat(raw, pid):
    assert type(raw) is bytes and len(raw) <= 4096
    prefix, closing, tail = raw.rpartition(b")")
    identity, opening, _ = prefix.partition(b" (")
    fields = tail.split()
    assert opening and closing and identity.isdigit() and int(identity) == pid
    assert len(fields) >= 20 and fields[0] in {bytes([state]) for state in b"RSDZTWtXxKWPI"}
    assert fields[19].isdigit() and int(fields[19]) > 0
    return fields[0], int(fields[19])


def read_descendant_stat(pid):
    with Path(f"/proc/{pid}/stat").open("rb") as stream:
        return stream.read(4097)


def assert_owned_descendant_stopped(witness, *, timeout=2, read=read_descendant_stat,
                                    clock=time.monotonic, pause=time.sleep):
    assert set(witness) == {"pid", "startticks"}
    assert all(type(value) is int and value > 0 for value in witness.values())
    assert type(timeout) in {int, float} and 0 < timeout <= 5
    deadline = clock() + timeout
    while True:
        assert clock() < deadline, "owned descendant still live at deadline"
        try:
            state, startticks = descendant_stat(read(witness["pid"]), witness["pid"])
        except OSError as error:
            if error.errno in {errno.ENOENT, errno.ESRCH}:
                assert clock() < deadline, "owned descendant still live at deadline"
                return
            raise
        assert clock() < deadline, "owned descendant still live at deadline"
        if startticks != witness["startticks"] or state == b"Z":
            return
        remaining = deadline - clock()
        assert remaining > 0, "owned descendant still live at deadline"
        pause(min(0.01, remaining))


def run_owned_descendant(tmp_path, *, seconds):
    program = (
        "import json,subprocess,sys;from pathlib import Path;"
        f"p=subprocess.Popen([sys.executable,'-c','import time;time.sleep({seconds})'],stdout=subprocess.DEVNULL);"
        "stat=Path('/proc/'+str(p.pid)+'/stat').open('rb');raw=stat.read(4097);stat.close();assert len(raw)<=4096;"
        "fields=raw.rsplit(b')',1)[1].split();assert fields[19].isdigit() and int(fields[19])>0;"
        "print(json.dumps({'pid':p.pid,'startticks':int(fields[19])}),flush=True)"
    )
    raw = runtime.run([sys.executable, "-I", "-B", "-c", program],
                      environment=runtime.clean_environment(tmp_path), cwd=tmp_path,
                      deadline=time.monotonic() + 5, limit=4096)
    return descendant_witness(raw)


@pytest.mark.skipif(os.name != "posix", reason="real group-signal suppression and automatic descendant exit need POSIX")
def test_descendant_wait_refuses_real_suppressed_group_signal_then_observes_automatic_exit(tmp_path, monkeypatch):
    children, requests = [], []
    real_child = runtime.OwnedPopen

    class Child(real_child):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            children.append(self)

    def suppressed(pid, signum):
        assert len(children) == 1 and pid == children[0].pid and signum == runtime.signal.SIGKILL
        assert runtime.peek_owned_returncode(children[0]) == 0  # The owned leader remains unreaped here.
        requests.append((pid, signum))

    with monkeypatch.context() as boundary:
        boundary.setattr(runtime, "OwnedPopen", Child)
        boundary.setattr(runtime.os, "killpg", suppressed)
        witness = run_owned_descendant(tmp_path, seconds=5)
    assert children[0].returncode == 0 and requests == [(children[0].pid, runtime.signal.SIGKILL)]
    try:
        with pytest.raises(AssertionError, match="owned descendant still live at deadline"):
            assert_owned_descendant_stopped(witness)
    finally:
        # The bounded control exits by itself; no PID/group signal or reap after the leader was released.
        assert_owned_descendant_stopped(witness, timeout=5)


def synthetic_descendant_stat(*, pid=123, state=b"R", startticks=b"456", command=b"python) owned"):
    return str(pid).encode() + b" (" + command + b") " + b" ".join([state] + [b"0"] * 18 + [startticks])


@pytest.mark.parametrize("state", [b"R", b"S", b"D", b"T", b"X"])
def test_descendant_wait_refuses_same_birth_live_states_with_bounded_readonly_poll(state):
    now, reads = [0.0], []

    def read(pid):
        reads.append(pid)
        return synthetic_descendant_stat(state=state)

    with pytest.raises(AssertionError, match="owned descendant still live at deadline"):
        assert_owned_descendant_stopped({"pid": 123, "startticks": 456}, read=read,
                                        clock=lambda: now[0],
                                        pause=lambda duration: now.__setitem__(0, now[0] + duration))
    assert 2 <= now[0] <= 2.000001 and reads and set(reads) == {123}


@pytest.mark.parametrize("terminal", ["zombie", "changed_birth", "absent", "lookup"])
def test_descendant_wait_only_accepts_terminal_or_original_birth_absent(terminal):
    def read(pid):
        assert pid == 123
        if terminal in {"absent", "lookup"}:
            raise OSError(errno.ENOENT if terminal == "absent" else errno.ESRCH, "fixed process gone")
        return synthetic_descendant_stat(state=b"Z" if terminal == "zombie" else b"R",
                                         startticks=b"456" if terminal == "zombie" else b"457")

    assert_owned_descendant_stopped({"pid": 123, "startticks": 456}, read=read)


@pytest.mark.parametrize("raw", [b"", b"x" * 4097, synthetic_descendant_stat(pid=124),
                                  b"123 (python) R 0 0", synthetic_descendant_stat(startticks=b"\xff"),
                                  synthetic_descendant_stat(state=b"N", startticks=b"457"),
                                  synthetic_descendant_stat(state=b"?"), synthetic_descendant_stat(startticks=b"0"),
                                  synthetic_descendant_stat(startticks=b"-1"),
                                  synthetic_descendant_stat(startticks=b"True")])
def test_descendant_wait_refuses_malformed_identity_or_stat(raw):
    with pytest.raises(AssertionError):
        assert_owned_descendant_stopped({"pid": 123, "startticks": 456}, read=lambda pid: raw)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EIO, errno.ENOTDIR, None])
def test_descendant_wait_refuses_other_io_errors(code):
    def read(pid):
        raise OSError(code, "fixed IO refusal")

    with pytest.raises(OSError) as raised:
        assert_owned_descendant_stopped({"pid": 123, "startticks": 456}, read=read)
    assert raised.value.errno == code


@pytest.mark.parametrize("terminal", ["zombie", "changed_birth", "absent"])
def test_descendant_wait_refuses_terminal_observations_after_deadline(terminal):
    now = [0.0]

    def read(pid):
        now[0] = 2.1
        if terminal == "absent":
            raise FileNotFoundError(errno.ENOENT, "fixed late disappearance")
        return synthetic_descendant_stat(state=b"Z" if terminal == "zombie" else b"R",
                                         startticks=b"456" if terminal == "zombie" else b"457")

    with pytest.raises(AssertionError, match="owned descendant still live at deadline"):
        assert_owned_descendant_stopped({"pid": 123, "startticks": 456}, read=read, clock=lambda: now[0])


@pytest.mark.parametrize("value", [{"pid": True, "startticks": 456}, {"pid": 123, "startticks": False},
                                    {"pid": 0, "startticks": 456}, {"pid": 123, "startticks": -1},
                                    {"pid": "123", "startticks": 456}, {"pid": 123, "startticks": 456, "extra": 1}])
def test_descendant_witness_refuses_unbound_or_nonpositive_identity(value):
    with pytest.raises(AssertionError):
        descendant_witness(json.dumps(value).encode())


def test_external_sources_cannot_enable_network_enrichment(tmp_path):
    value = configuration(tmp_path / "database")
    value["externalSources"]["enable"] = True
    with pytest.raises(runtime.GrypeRuntimeError, match="config"):
        runtime.validate_configuration(value, tmp_path / "database", "linux/amd64")


@pytest.mark.parametrize("outcome", ["success", "nonzero", "signal", "dumped", "timeout", "cancel"])
def test_posix_owned_leader_remains_unreaped_until_group_termination(monkeypatch, tmp_path, outcome):
    events = []
    state = SimpleNamespace(killed=False, code=0)
    child = SimpleNamespace(pid=123, stdout=open(os.devnull, "rb", buffering=0))

    def forbidden_poll():
        events.append("reaped_before_kill")
        raise AssertionError("leader must remain unreaped")

    def wait(timeout):
        assert state.killed
        events.append("reap")
        return state.code

    def peek(kind, pid, flags):
        assert (kind, pid, flags) == (1, 123, 14)
        events.append("peek")
        if outcome in {"timeout", "cancel"}:
            return None
        return SimpleNamespace(si_pid=123, si_code=3 if outcome == "dumped" else 2 if outcome == "signal" else 1,
                               si_status=9 if outcome in {"signal", "dumped"} else 23 if outcome == "nonzero" else 0)

    def kill_group(pid, sig):
        assert pid == 123 and sig == 9
        events.append("kill_group")
        state.killed = True

    child.poll, child.wait = forbidden_poll, wait
    posix = SimpleNamespace(name="posix", read=lambda *args: b"", waitid=peek, P_PID=1,
                            WEXITED=2, WNOHANG=4, WNOWAIT=8, CLD_EXITED=1, CLD_KILLED=2,
                            CLD_DUMPED=3, killpg=kill_group, dup=os.dup, close=os.close,
                            set_blocking=lambda *args: None)
    monkeypatch.setattr(runtime, "os", posix)
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGKILL=9, SIGCHLD=17, SIG_DFL=0, NSIG=65,
                                                          getsignal=lambda sig: 0))
    monkeypatch.setattr(runtime, "OwnedPopen", lambda *args, **kwargs: child)
    def monitor():
        if outcome == "cancel":
            raise KeyboardInterrupt("canary-secret")
    kwargs = {"environment": {}, "cwd": tmp_path, "deadline": time.monotonic() + 5,
              "limit": 32, "timeout": 0.1 if outcome == "timeout" else 5, "monitor": monitor}
    if outcome == "success":
        assert runtime.run(["fixed"], **kwargs) == b""
    else:
        expected = KeyboardInterrupt if outcome == "cancel" else runtime.GrypeRuntimeError
        with pytest.raises(expected) as caught:
            runtime.run(["fixed"], **kwargs)
        if outcome != "cancel":
            assert caught.value.code == ("timeout" if outcome == "timeout" else "nonzero")
    assert "reaped_before_kill" not in events
    assert events.count("kill_group") == events.count("reap") == 1
    assert events.index("kill_group") < events.index("reap")
    assert events[events.index("kill_group") - 1] == "peek"


@pytest.mark.parametrize("identifier", ["pkg:golang/github.com/tianon/gosu@v1.19",
    "pkg:golang/github.com/tianon/gosu@1.20", "pkg:golang/github.com/foreign/gosu@1.19",
    "pkg:golang/github.com/tianon/gosu@1.19?x=canary", "pkg:golang/github.com/tianon/gosu@1.19\n",
    "pkg:golang/github.com/tianon/gosu@1.19;--config", "pkg:golang/github.com/tianon/gosu@1.19#canary"])
def test_gosu_two_component_exception_is_exact_publisher_literal(identifier):
    with pytest.raises(runtime.GrypeRuntimeError, match="identifier"):
        runtime.validate_identifier(identifier)


@pytest.mark.parametrize("missing", ["waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",
                                     "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "SIG_IGN", "handler"])
def test_posix_without_owned_waitid_or_default_sigchld_refuses_before_launch(monkeypatch, tmp_path, missing):
    posix = SimpleNamespace(name="posix", waitid=lambda *args: None, P_PID=1, WEXITED=2,
                            WNOHANG=4, WNOWAIT=8, CLD_EXITED=1, CLD_KILLED=2, CLD_DUMPED=3)
    disposition = 1 if missing == "SIG_IGN" else (lambda *args: None) if missing == "handler" else 0
    if hasattr(posix, missing):
        delattr(posix, missing)
    monkeypatch.setattr(runtime, "os", posix)
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGCHLD=17, SIG_DFL=0,
                                                          getsignal=lambda sig: disposition))
    monkeypatch.setattr(runtime, "OwnedPopen", lambda *args, **kwargs: pytest.fail("must not launch"))
    with pytest.raises(runtime.GrypeRuntimeError, match="platform"):
        runtime.run(["fixed"], environment={}, cwd=tmp_path, deadline=time.monotonic() + 5, limit=32)


@pytest.mark.parametrize("bad", ["echild", "wrong_pid", "wrong_code", "wrong_status", "boolean_status",
                                 "signal_zero", "signal_outside_range", "missing_fields", "sigchld_changed"])
def test_posix_lost_ownership_never_signals_or_reaps_numeric_pid(monkeypatch, bad):
    observed = SimpleNamespace(si_pid=123, si_code=1, si_status=0)
    if bad == "wrong_pid":
        observed.si_pid = 456
    elif bad == "wrong_code":
        observed.si_code = 8
    elif bad == "wrong_status":
        observed.si_status = -1
    elif bad == "boolean_status":
        observed.si_status = False
    elif bad in {"signal_zero", "signal_outside_range"}:
        observed.si_code, observed.si_status = 2, 0 if bad == "signal_zero" else 65
    elif bad == "missing_fields":
        observed = {}
    def peek(*args):
        if bad == "echild":
            raise ChildProcessError("canary-untrusted-message")
        return observed
    posix = SimpleNamespace(name="posix", waitid=peek, P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8,
        CLD_EXITED=1, CLD_KILLED=2, CLD_DUMPED=3, killpg=lambda *args: pytest.fail("foreign group signal"))
    child = SimpleNamespace(pid=123, stdout=SimpleNamespace(close=lambda: None),
        poll=lambda: pytest.fail("premature reap"), wait=lambda **kwargs: pytest.fail("unowned reap"))
    child.abandon_ownership = lambda: setattr(child, "_ownership_abandoned", True)
    monkeypatch.setattr(runtime, "os", posix)
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGCHLD=17, SIG_DFL=0, SIGKILL=9, NSIG=65,
        getsignal=lambda sig: 1 if bad == "sigchld_changed" else 0))
    with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed") as caught:
        runtime.cleanup_process(child, None)
    assert str(caught.value) == "owned_cleanup_failed"


@pytest.mark.parametrize("fault", ["echild", "wrong_pid", "wrong_code", "wrong_status", "sigchld"])
def test_real_owned_popen_finalizer_is_disarmed_after_ownership_refusal(monkeypatch, fault):
    child = object.__new__(runtime.OwnedPopen)
    child._child_created, child._ownership_abandoned, child.returncode, child.pid = True, False, None, 123
    child._internal_poll = lambda **kwargs: pytest.fail("stdlib finalizer reaped unowned PID")
    child.wait = child.poll = child.kill = lambda *args, **kwargs: pytest.fail("unowned process operation")
    observed = SimpleNamespace(si_pid=456 if fault == "wrong_pid" else 123,
        si_code=7 if fault == "wrong_code" else 1, si_status=-1 if fault == "wrong_status" else 0)
    def peek(*args):
        if fault == "echild":
            raise ChildProcessError("private-error-canary")
        return observed
    posix = SimpleNamespace(name="posix", waitid=peek, P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8,
        CLD_EXITED=1, CLD_KILLED=2, CLD_DUMPED=3, killpg=lambda *args: pytest.fail("unowned group signal"))
    monkeypatch.setattr(runtime, "os", posix)
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGCHLD=17, SIG_DFL=0, SIGKILL=9, NSIG=65,
        getsignal=lambda sig: 1 if fault == "sigchld" else 0))
    try:
        with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
            runtime.peek_owned_returncode(child)
        assert child._ownership_abandoned and child.returncode is None and child._child_created
        for _ in range(2):
            with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
                runtime.terminate_owned_process(child)
            runtime.OwnedPopen.__del__(child)
        assert child.returncode is None
        assert subprocess._active is None or child not in subprocess._active
    finally:
        child.abandon_ownership()


@pytest.mark.parametrize("finalizer", [subprocess.Popen.__del__, runtime.OwnedPopen.__del__])
def test_standard_finalizer_control_and_owned_normal_finalizer_delegate_once(finalizer):
    child = object.__new__(runtime.OwnedPopen)
    child._child_created, child._ownership_abandoned, child.returncode, child.pid = True, False, None, 123
    calls = []
    def internal_poll(**kwargs):
        calls.append("internal_poll")
        child.returncode = 23  # Synthetic wait result; no native process or signal exists.
    child._internal_poll = internal_poll
    with pytest.warns(ResourceWarning):
        finalizer(child)
    assert calls == ["internal_poll"]
    child.abandon_ownership()


def test_partial_owned_popen_initialization_preserves_base_finalizer_guard(tmp_path):
    child = object.__new__(runtime.OwnedPopen)
    child._internal_poll = lambda **kwargs: pytest.fail("partial constructor must not poll")
    runtime.OwnedPopen.__del__(child)
    with pytest.raises(OSError):
        runtime.OwnedPopen([str(tmp_path / "nonexistent-owned-executable")], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)


def test_private_reader_descriptors_keep_inode_when_caller_output_fd_is_reused(tmp_path):
    source = open(os.devnull, "rb", buffering=0)
    original = os.open(tmp_path / "owned-output",
                       os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    lease = runtime.ReaderDescriptors(source.fileno(), original)
    lease.transfer()
    with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
        lease.close_if_untransferred()
    os.close(original)
    replacement = os.open(tmp_path / "replacement", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.dup2(replacement, original)
        os.write(lease.output_fd, b"owned\r\n\x1abytes")
        lease.close()  # Reader-owned disposal after transfer.
        assert lease.read_fd is lease.output_fd is None
        assert (tmp_path / "replacement").read_bytes() == b""
        assert (tmp_path / "owned-output").read_bytes() == b"owned\r\n\x1abytes"
    finally:
        source.close()
        os.close(original)
        if replacement != original:
            os.close(replacement)


def test_private_descriptor_close_attempts_both_once_and_never_retries_released_numbers(monkeypatch, tmp_path):
    source = open(os.devnull, "rb", buffering=0)
    output = os.open(tmp_path / "output", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    lease = runtime.ReaderDescriptors(source.fileno(), output)
    owned = lease.read_fd, lease.output_fd
    actual_close, calls = os.close, []
    def close(fd):
        calls.append(fd)
        actual_close(fd)
        if fd == owned[0]:
            raise OSError("close-canary")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(runtime.os, "close", close)
            with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
                lease.close()
            lease.close()
        assert calls == list(owned) and lease.read_fd is lease.output_fd is None
        os.fstat(source.fileno())
        os.fstat(output)
    finally:
        source.close()
        actual_close(output)


@pytest.fixture
def owned_process_boundary(monkeypatch):
    actual_class = runtime.OwnedPopen
    child = object.__new__(actual_class)
    child._child_created, child._ownership_abandoned, child.returncode, child.pid = True, False, None, 123
    child.stdout = open(os.devnull, "rb", buffering=0)
    calls = []
    state = SimpleNamespace(child=child, calls=calls)
    def peek(*args):
        calls.append("peek")
        return SimpleNamespace(si_pid=123, si_code=1, si_status=0)
    def kill(*args):
        calls.append("kill")
    def wait(**kwargs):
        assert "kill" in calls
        calls.append("wait")
        child.returncode = 0
        return 0
    child.wait = wait
    child.poll = child._internal_poll = lambda **kwargs: pytest.fail("premature automatic reap")
    posix = SimpleNamespace(name="posix", waitid=peek, P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8,
        CLD_EXITED=1, CLD_KILLED=2, CLD_DUMPED=3, killpg=kill, dup=os.dup, close=os.close, read=os.read,
        write=os.write, set_blocking=lambda *args: None)
    monkeypatch.setattr(runtime, "os", posix)
    monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGCHLD=17, SIG_DFL=0, SIGKILL=9, NSIG=65,
                                                          getsignal=lambda sig: 0))
    monkeypatch.setattr(runtime, "OwnedPopen", lambda *args, **kwargs: child)
    state.os = posix
    try:
        yield state
    finally:
        child.abandon_ownership()
        child.stdout.close()


@pytest.mark.parametrize("fault", ["stdout_dup", "output_dup", "setblocking", "thread_constructor",
                                 "cancel_before_start"])
def test_before_transfer_failure_disposes_only_private_fds_and_kills_owned_group(owned_process_boundary,
                                                                               monkeypatch, tmp_path, fault):
    boundary = owned_process_boundary
    actual_dup, duplicated = os.dup, []
    def dup(fd):
        if fault == "stdout_dup" or fault == "output_dup" and duplicated:
            raise OSError("private-dup-canary")
        result = actual_dup(fd)
        duplicated.append(result)
        return result
    monkeypatch.setattr(boundary.os, "dup", dup)
    if fault == "setblocking":
        monkeypatch.setattr(boundary.os, "set_blocking", lambda *args: (_ for _ in ()).throw(OSError("private-canary")))
    if fault in {"thread_constructor", "cancel_before_start"}:
        error = KeyboardInterrupt() if fault == "cancel_before_start" else OSError("private-thread-canary")
        monkeypatch.setattr(runtime, "threading", SimpleNamespace(Event=threading.Event,
            Thread=lambda **kwargs: (_ for _ in ()).throw(error)))
    output = os.open(tmp_path / "output", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with pytest.raises(KeyboardInterrupt if fault == "cancel_before_start" else OSError):
            runtime.run(["fixed"], environment={}, cwd=tmp_path, deadline=time.monotonic() + 5,
                        limit=32, output_fd=output)
        assert boundary.calls[-3:] == ["peek", "kill", "wait"]
        assert not boundary.child._ownership_abandoned
        for fd in duplicated:
            with pytest.raises(OSError):
                os.fstat(fd)
        os.fstat(output)
    finally:
        os.close(output)


def test_start_interrupted_after_native_thread_creation_keeps_private_fds_until_target_exit(
    owned_process_boundary, monkeypatch, tmp_path
):
    boundary = owned_process_boundary
    gate, state = threading.Event(), SimpleNamespace()
    actual_lease = runtime.ReaderDescriptors
    def descriptors(*args):
        state.lease = actual_lease(*args)
        return state.lease
    class AmbiguousThread:
        def __init__(self, *, target, args, **kwargs):
            self.native = threading.Thread(target=lambda: (gate.wait(3), target(*args)), daemon=True)
            state.thread = self.native
        def start(self):
            assert state.lease.transferred
            self.native.start()
            raise KeyboardInterrupt("native-start-acknowledgement-interrupted")
        def join(self, **kwargs):
            raise RuntimeError("native-start-acknowledgement-unknown")
    monkeypatch.setattr(runtime, "ReaderDescriptors", descriptors)
    monkeypatch.setattr(runtime, "threading", SimpleNamespace(Event=threading.Event, Thread=AmbiguousThread))
    output = os.open(tmp_path / "original", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    replacement = None
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            runtime.run(["fixed"], environment={}, cwd=tmp_path, deadline=time.monotonic() + 5,
                        limit=32, output_fd=output)
        assert caught.value.__notes__ == ["owned_cleanup_failed"]
        assert state.lease.read_fd is not None and state.lease.output_fd is not None
        os.close(output)
        replacement = os.open(tmp_path / "replacement", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.dup2(replacement, output)
        gate.set()
        state.thread.join(timeout=2)
        assert not state.thread.is_alive() and state.lease.read_fd is state.lease.output_fd is None
        assert (tmp_path / "replacement").read_bytes() == b""
        assert boundary.calls[-3:] == ["peek", "kill", "wait"]
    finally:
        gate.set()
        if hasattr(state, "thread"):
            state.thread.join(timeout=2)
        os.close(output)
        if replacement is not None and replacement != output:
            os.close(replacement)


@pytest.mark.parametrize("interrupted", [False, True])
def test_real_reader_completed_before_start_acknowledgement_preserves_failure_contract(
    owned_process_boundary, monkeypatch, tmp_path, interrupted
):
    boundary, state = owned_process_boundary, SimpleNamespace()
    actual_lease = runtime.ReaderDescriptors
    primary = KeyboardInterrupt("private-completed-start-acknowledgement")

    def descriptors(*args):
        lease = actual_lease(*args)
        state.lease_reference = weakref.ref(lease)
        state.fds = lease.read_fd, lease.output_fd
        return lease

    class CompletedThread:
        def __init__(self, *, target, args, **kwargs):
            self.native = threading.Thread(target=target, args=args, daemon=True)
            state.native, state.reader_reference = self.native, weakref.ref(self)

        def start(self):
            self.native.start()
            self.native.join(timeout=2)
            assert not self.native.is_alive()  # Real EOF reader completed before the acknowledgement.
            for fd in state.fds:
                with pytest.raises(OSError):
                    os.fstat(fd)
            if interrupted:
                raise primary

        def join(self, **kwargs):
            self.native.join(**kwargs)  # Cleanup succeeds; no synthetic join error creates the note.

        def is_alive(self):
            return self.native.is_alive()

    monkeypatch.setattr(runtime, "ReaderDescriptors", descriptors)
    monkeypatch.setattr(runtime, "threading", SimpleNamespace(Event=threading.Event, Thread=CompletedThread))
    output = os.open(tmp_path / "output", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        kwargs = dict(environment={}, cwd=tmp_path, deadline=time.monotonic() + 5,
                      limit=32, output_fd=output)
        if interrupted:
            with pytest.raises(KeyboardInterrupt) as caught:
                runtime.run(["fixed"], **kwargs)
            assert caught.value is primary and caught.value.__notes__ == ["owned_cleanup_failed"]
        else:
            assert runtime.run(["fixed"], **kwargs) == b""
            gc.collect()
            assert state.reader_reference() is None and state.lease_reference() is None
        assert boundary.calls.count("kill") == boundary.calls.count("wait") == 1
        assert boundary.calls[-3:] == ["peek", "kill", "wait"]
        assert boundary.child.stdout.closed and not state.native.is_alive()
        os.fstat(output)
        assert (tmp_path / "output").read_bytes() == b""
    finally:
        os.close(output)


def test_start_failure_without_os_thread_leaves_transferred_lease_to_its_own_finalizer(
    owned_process_boundary, monkeypatch, tmp_path
):
    state, actual_lease = SimpleNamespace(), runtime.ReaderDescriptors
    def descriptors(*args):
        lease = actual_lease(*args)
        state.reference, state.fds = weakref.ref(lease), (lease.read_fd, lease.output_fd)
        return lease
    class UnstartedThread:
        def __init__(self, *, target, args, **kwargs):
            self.target, self.args = target, args
        def start(self):
            assert self.args[0].transferred
            raise OSError("private-start-failure")
        def join(self, **kwargs):
            raise RuntimeError("never started")
    monkeypatch.setattr(runtime, "ReaderDescriptors", descriptors)
    monkeypatch.setattr(runtime, "threading", SimpleNamespace(Event=threading.Event, Thread=UnstartedThread))
    output = os.open(tmp_path / "output", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        def refused_start():
            with pytest.raises(OSError) as caught:
                runtime.run(["fixed"], environment={}, cwd=tmp_path, deadline=time.monotonic() + 5,
                            limit=32, output_fd=output)
            assert caught.value.__notes__ == ["owned_cleanup_failed"]
            lease = state.reference()
            assert lease.transferred and all(fd is not None for fd in state.fds)
            with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
                lease.close_if_untransferred()
        refused_start()
        gc.collect()
        assert state.reference() is None
        for fd in state.fds:
            with pytest.raises(OSError):
                os.fstat(fd)
        os.fstat(output)
    finally:
        os.close(output)


@pytest.mark.parametrize("primary", [KeyboardInterrupt("private-cancel-canary"), SystemExit(23)])
def test_cancellation_and_uncertain_ownership_preserve_primary_without_process_operations(
    owned_process_boundary, monkeypatch, tmp_path, primary
):
    boundary = owned_process_boundary
    monkeypatch.setattr(boundary.os, "waitid", lambda *args: (_ for _ in ()).throw(ChildProcessError()))
    with pytest.raises(type(primary)) as caught:
        runtime.run(["fixed"], environment={}, cwd=tmp_path, deadline=time.monotonic() + 5, limit=32,
                    monitor=lambda: (_ for _ in ()).throw(primary))
    assert caught.value is primary and primary.__notes__ == ["owned_cleanup_failed"]
    assert boundary.child._ownership_abandoned and boundary.child.returncode is None
    assert "kill" not in boundary.calls and "wait" not in boundary.calls
    assert boundary.child.stdout.closed


@pytest.mark.skipif(os.name != "posix", reason="real live pipe/nonblocking ownership-refusal proof requires POSIX")
def test_owned_refusal_stops_nonblocking_reader_with_live_fixture_writer(monkeypatch, tmp_path):
    actual_class, actual_waitid, actual_killpg = runtime.OwnedPopen, os.waitid, os.killpg
    state = SimpleNamespace()
    def launch(*args, **kwargs):
        state.child = actual_class(*args, **kwargs)
        return state.child
    monkeypatch.setattr(runtime, "OwnedPopen", launch)
    monkeypatch.setattr(runtime.os, "waitid", lambda *args: (_ for _ in ()).throw(ChildProcessError()))
    before = time.monotonic()
    try:
        with pytest.raises(runtime.GrypeRuntimeError, match="owned_cleanup_failed"):
            runtime.run([sys.executable, "-I", "-B", "-c", "import time;print('fixture',flush=True);time.sleep(60)"],
                        environment=runtime.clean_environment(tmp_path), cwd=tmp_path,
                        deadline=time.monotonic() + 5, limit=32)
        assert time.monotonic() - before < 2.5
        assert state.child._ownership_abandoned and state.child.returncode is None
        assert not any(thread.name == "grype-owned-output" and thread.is_alive() for thread in threading.enumerate())
    finally:
        # The test owns this newly spawned fixture and independently proves its
        # still-waitable PID before cleanup; production refusal performs none.
        child = state.child
        observed = actual_waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert observed is None or observed.si_pid == child.pid
        actual_killpg(child.pid, 9)
        child.wait(timeout=2)


def test_fake_global_clock_counts_download_and_version_and_preserves_cleanup(synthetic, monkeypatch):
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock.now)
    previous = runtime.run

    def advanced(command, **kwargs):
        if command[0] == sys.executable:
            clock.now += 599
        elif "version" in command:
            clock.now += 2
        return previous(command, **kwargs)
    monkeypatch.setattr(runtime, "run", advanced)
    with pytest.raises(runtime.GrypeRuntimeError, match="deadline"):
        with runtime.prepared_grype(**synthetic.args):
            pytest.fail("must not yield")
    assert clock.now == 601 and not list(synthetic.scratch.iterdir())
