"""Adversarial synthetic controls for the finite, non-authoritative CI bridge."""

import contextlib
import copy
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from shadai.qualification import ci_metadata as metadata
from shadai.qualification.schemas import canonical_bytes, load_profile

ROOT = Path(__file__).resolve().parents[1]
CANARY = "PRIVATE-CI-CANARY:/home/private/token?secret=NeverPublish"
REVISION = "a" * 40
RUN_UUID = "b14b66c9-5298-435f-9031-c91cb9888abc"
FALLBACK = "state=unavailable\nphase=unknown\nstage=unknown\nerror_type=UnexpectedError\ncode=exception\n"
AVAILABLE = {
    "state": "available", "phase": "cold_restore", "stage": "cold_restore_inventory_compare_compare",
    "error_type": "AssertionError", "code": "exception",
}
REQUIRED_PATHS = [
    ("report",), ("journal",), ("source",), ("report", "schema"), ("report", "scope"), ("report", "exit_code"),
    ("report", "profile_sha256"), ("journal", "schema"), ("journal", "profile_sha256"),
    ("journal", "config_sha256"), ("journal", "context"), ("journal", "run_id"),
    ("report", "evidence"), ("report", "evidence", "run_id"), ("report", "evidence", "installation"),
    ("report", "evidence", "source"), ("report", "evidence", "source", "revision"),
    ("report", "evidence", "source", "environment"),
    ("report", "evidence", "source", "environment", "docker_context"),
    ("source", "revision"), ("source", "environment"), ("source", "environment", "docker_context"),
    ("report", "evidence", "failure"), ("report", "evidence", "failure", "phase"),
    ("report", "evidence", "failure", "stage"), ("report", "evidence", "failure", "error_type"),
    ("report", "evidence", "failure", "code"),
]


def write_private(path, value):
    path.write_bytes(canonical_bytes(value) if type(value) is not bytes else value)
    path.chmod(0o600)


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    """No source assets are read until a test explicitly selects this fixture."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    repository = tmp_path / "repository"
    profile_path, compose_path = repository / metadata.PROFILE, repository / metadata.COMPOSE
    profile_path.parent.mkdir(parents=True)
    profile = {
        "schema": 1, "scope": "disposable_lab", "installation": "synthetic-lab", "run": "mandatory-ci-smoke",
        "scenarios": ["baseline"],
        "load": {"total_events": 10, "events_per_second": 10, "batch_size": 10, "concurrency": 1,
                 "request_timeout_seconds": 5, "drain_timeout_seconds": 120, "seed": 62747},
        "limits": {"max_wall_seconds": 1500, "max_requests": 500, "max_request_bytes": 2097152,
                   "max_disk_bytes": 10737418240},
    }
    write_private(profile_path, profile)
    write_private(compose_path, b"services: {}\n")
    profile_hash = hashlib.sha256(canonical_bytes(load_profile(profile_path))).hexdigest()
    config_hash = hashlib.sha256(compose_path.read_bytes() + canonical_bytes(profile)).hexdigest()
    run_path = home / "shadai-qualification-123456-2"
    run_path.mkdir(mode=0o700)
    run_path.chmod(0o700)
    source = {"revision": REVISION, "environment": {"docker_context": "default", "private": CANARY},
              "source_sha256": {CANARY: CANARY}, "private": CANARY}
    report = {
        "schema": 1, "scope": "disposable_lab", "exit_code": 1, "profile_sha256": profile_hash,
        "scenarios": [{"measurements": {CANARY: [CANARY]}}], "objectives": {CANARY: CANARY},
        "missing_evidence": [CANARY], "private": CANARY,
        "evidence": {
            "run_id": RUN_UUID, "installation": "q-" + RUN_UUID.replace("-", ""), "source": copy.deepcopy(source),
            "failure": {**{key: value for key, value in AVAILABLE.items() if key != "state"},
                        "message": CANARY, "args": [CANARY], "returncode": CANARY, "secondary": [CANARY],
                        "private": {CANARY: CANARY}}, "private": CANARY,
        },
    }
    journal = {"schema": 1, "run_id": RUN_UUID, "profile_sha256": profile_hash, "config_sha256": config_hash,
               "context": "default", "phase": "cold_restore", "history": [CANARY], "resources": [CANARY],
               "private": CANARY}
    values = {"report": report, "journal": journal, "source": source}
    for key, value in values.items():
        write_private(run_path / (key + ".json"), value)
    monkeypatch.setattr(metadata, "_head_revision", lambda _: REVISION)
    return SimpleNamespace(
        repository=repository, home=home, run_path=run_path, values=values,
        identity={"revision": REVISION, "profile_sha256": profile_hash, "config_sha256": config_hash},
        args={"home": str(home), "run_id": "123456", "run_attempt": "2", "github_sha": REVISION},
    )


def project(bundle):
    return metadata.project_failure(**bundle.values, **bundle.identity)


def collect(bundle):
    return metadata.collect_metadata(bundle.repository, **bundle.args)


def replace_field(values, path, value):
    target = values
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def test_valid_private_bundle_has_only_five_closed_fields_and_does_not_mutate(bundle):
    before = {path: path.read_bytes() for path in bundle.run_path.iterdir()}
    assert project(bundle) == collect(bundle) == AVAILABLE
    assert {path: path.read_bytes() for path in bundle.run_path.iterdir()} == before
    encoded = metadata.render_metadata(collect(bundle))
    assert len(encoded.splitlines()) == 5
    assert CANARY not in encoded and RUN_UUID not in encoded and REVISION not in encoded
    assert "exit_code" not in encoded and "accepted" not in encoded


ENUM_CASES = [(field, value) for field, choices in (
    ("phase", metadata.PHASES), ("stage", metadata.STAGES),
    ("error_type", metadata.ERROR_TYPES), ("code", metadata.CODES),
) for value in sorted(choices)]


@pytest.mark.parametrize(("field", "value"), ENUM_CASES)
def test_every_known_enum_is_available_and_literal(bundle, field, value):
    bundle.values["report"]["evidence"]["failure"][field] = value
    result = project(bundle)
    assert result == {**AVAILABLE, field: value}
    assert CANARY not in metadata.render_metadata(result)


@pytest.mark.parametrize("exit_code", [1, 2])
def test_both_original_failure_exit_codes_are_diagnostic_only(bundle, exit_code):
    bundle.values["report"]["exit_code"] = exit_code
    assert project(bundle) == AVAILABLE
    assert bundle.values["report"]["exit_code"] == exit_code


@pytest.mark.parametrize("path", REQUIRED_PATHS)
@pytest.mark.parametrize("value", [None, True, [], CANARY])
def test_missing_wrong_type_or_unrecognized_required_value_is_unavailable(bundle, path, value):
    replace_field(bundle.values, path, value)
    assert metadata.render_metadata(project(bundle)) == FALLBACK


@pytest.mark.parametrize(("path", "value"), [
    (("report", "schema"), 0), (("report", "schema"), 2), (("journal", "schema"), 2),
    (("report", "scope"), "target"), (("report", "exit_code"), 0), (("report", "exit_code"), -1),
    (("report", "exit_code"), 3), (("report", "exit_code"), 1.0),
    (("report", "profile_sha256"), "b" * 64), (("journal", "profile_sha256"), "b" * 64),
    (("journal", "config_sha256"), "b" * 64), (("journal", "context"), "desktop-linux"),
    (("report", "evidence", "run_id"), "c7aca31b-edce-42bf-8dad-8f6d6a88dbf3"),
    (("journal", "run_id"), "c7aca31b-edce-42bf-8dad-8f6d6a88dbf3"),
    (("journal", "run_id"), RUN_UUID.upper()), (("journal", "run_id"), RUN_UUID.replace("-4", "-3", 1)),
    (("report", "evidence", "installation"), "q-foreign"),
    (("source", "revision"), "b" * 40), (("report", "evidence", "source", "revision"), "b" * 40),
    (("source", "environment", "docker_context"), "desktop-linux"),
    (("report", "evidence", "source", "environment", "docker_context"), "desktop-linux"),
    (("report", "evidence", "failure", "error_type"), "ArbitraryPrivateException"),
])
def test_wrong_identity_schema_exit_and_error_class_are_unavailable(bundle, path, value):
    replace_field(bundle.values, path, value)
    assert project(bundle) == metadata.UNAVAILABLE


@pytest.mark.parametrize("path", REQUIRED_PATHS)
def test_absent_required_fields_are_unavailable(bundle, path):
    target = bundle.values
    for part in path[:-1]:
        target = target[part]
    del target[path[-1]]
    # Top-level Python arguments cannot be absent; represent a missing file input.
    for name in ("report", "journal", "source"):
        bundle.values.setdefault(name, None)
    assert project(bundle) == metadata.UNAVAILABLE


class Poison:
    calls = []

    def callback(self, *args):
        self.calls.append(True)
        raise AssertionError(CANARY)

    __str__ = __repr__ = __eq__ = __bool__ = __iter__ = __getitem__ = __fspath__ = callback


class PoisonString(str):
    __str__ = __repr__ = __eq__ = __hash__ = Poison.callback


class PoisonDict(dict):
    __iter__ = __getitem__ = get = keys = Poison.callback


@pytest.mark.parametrize("path", REQUIRED_PATHS)
@pytest.mark.parametrize("factory", [Poison, lambda: PoisonString("unknown"), PoisonDict])
def test_hostile_values_reject_without_callbacks(bundle, path, factory):
    Poison.calls.clear()
    replace_field(bundle.values, path, factory())
    assert project(bundle) == metadata.UNAVAILABLE
    assert Poison.calls == []


def test_nonstring_keys_reject_before_lookup_and_optional_poison_is_ignored(bundle):
    bundle.values["report"]["evidence"]["failure"]["optional"] = Poison()
    assert project(bundle) == AVAILABLE
    bundle.values["report"][17] = Poison()
    Poison.calls.clear()
    assert project(bundle) == metadata.UNAVAILABLE
    assert Poison.calls == []


@pytest.mark.parametrize("identity", ["revision", "profile_sha256", "config_sha256"])
def test_expected_identity_also_validates_before_comparison(bundle, identity):
    bundle.identity[identity] = Poison()
    Poison.calls.clear()
    assert project(bundle) == metadata.UNAVAILABLE
    assert Poison.calls == []


@pytest.mark.parametrize("field", metadata.FIELDS)
@pytest.mark.parametrize("value", [CANARY, None, True, Poison()])
def test_output_boundary_revalidates_every_field_without_callbacks(field, value):
    Poison.calls.clear()
    assert metadata.render_metadata({**AVAILABLE, field: value}) == FALLBACK
    assert Poison.calls == []


def test_output_boundary_rejects_extra_keys_and_false_unavailability():
    assert metadata.render_metadata({**AVAILABLE, "private": CANARY}) == FALLBACK
    assert metadata.render_metadata({**AVAILABLE, "state": "unavailable"}) == FALLBACK
    assert metadata.render_metadata(PoisonDict()) == FALLBACK


@pytest.mark.parametrize("filename", ["report.json", "journal.json", "source.json"])
@pytest.mark.parametrize("raw", [
    b'{"schema":1,"schema":1}', b'{"private":{"nested":1,"nested":2}}', b'{"private":NaN}',
    b'{"private":Infinity}', b'{"private":-Infinity}', b'{"private":1e99999}', b'{"private":-1e99999}',
    b'not json PRIVATE-CI-CANARY', b'\xff', b'null', b'[]', b'{"private":',
])
def test_invalid_duplicate_or_nonfinite_private_json_is_unavailable(bundle, filename, raw):
    write_private(bundle.run_path / filename, raw)
    assert metadata.render_metadata(collect(bundle)) == FALLBACK


@pytest.mark.parametrize("filename", ["report.json", "journal.json", "source.json"])
def test_absent_or_incomplete_files_are_unavailable(bundle, filename):
    path = bundle.run_path / filename
    path.unlink()
    assert collect(bundle) == metadata.UNAVAILABLE
    write_private(path, {})
    assert collect(bundle) == metadata.UNAVAILABLE


def input_path(bundle, name):
    return {"profile": bundle.repository / metadata.PROFILE, "compose": bundle.repository / metadata.COMPOSE}.get(
        name, bundle.run_path / (name + ".json"))


@pytest.mark.parametrize("name", ["report", "journal", "source", "profile", "compose"])
def test_budget_is_checked_before_opening_or_allocating_file(bundle, monkeypatch, name):
    path = input_path(bundle, name)
    limit = 65536 if name == "profile" else metadata.MAX_METADATA_BYTES
    with path.open("wb") as stream:
        stream.truncate(limit + 1)
    original = metadata.os.open
    opened = []

    def guarded(candidate, *args, **kwargs):
        if candidate == path:
            opened.append(True)
            raise AssertionError(CANARY)
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(metadata.os, "open", guarded)
    assert collect(bundle) == metadata.UNAVAILABLE
    assert opened == []


@pytest.mark.parametrize("name", ["report", "journal", "source", "profile", "compose"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_links_and_nonregular_files_are_refused(bundle, name, kind):
    path = input_path(bundle, name)
    saved = path.with_suffix(".private-original")
    path.rename(saved)
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        try:
            path.symlink_to(saved)
        except PermissionError:
            if os.name != "nt":
                raise
            pytest.skip("Windows refused native symlink creation")
    else:
        try:
            os.link(saved, path)
        except PermissionError:
            if os.name != "nt":
                raise
            pytest.skip("Windows refused native hardlink creation; link-count refusal is tested separately")
    assert collect(bundle) == metadata.UNAVAILABLE


def test_linked_run_root_and_ancestor_are_refused(bundle):
    saved = bundle.run_path.with_name("foreign-private")
    bundle.run_path.rename(saved)
    try:
        bundle.run_path.symlink_to(saved, target_is_directory=True)
    except PermissionError:
        if os.name != "nt":
            raise
        pytest.skip("Windows refused native symlink creation")
    assert collect(bundle) == metadata.UNAVAILABLE
    bundle.run_path.unlink()
    saved.rename(bundle.run_path)
    home_saved = bundle.home.with_name("foreign-home")
    bundle.home.rename(home_saved)
    bundle.home.symlink_to(home_saved, target_is_directory=True)
    assert collect(bundle) == metadata.UNAVAILABLE


@pytest.mark.skipif(os.name == "nt", reason="Native FIFO setup requires POSIX; mode refusal is tested on Windows")
def test_native_fifo_is_refused_without_opening(bundle):
    path = bundle.run_path / "report.json"
    path.unlink()
    os.mkfifo(path, mode=0o600)
    assert collect(bundle) == metadata.UNAVAILABLE


def changed_stat(info, **changes):
    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
    )}
    fields.update(changes)
    return SimpleNamespace(**fields)


@pytest.mark.parametrize("change", ["fifo", "reparse", "hardlink", "private-mode", "owner"])
def test_unsafe_native_file_metadata_rejects_before_open(bundle, monkeypatch, change):
    path = bundle.run_path / "report.json"
    original_stat, original_open = Path.lstat, metadata.os.open
    changes = {
        "fifo": {"st_mode": stat.S_IFIFO | 0o600}, "reparse": {"st_file_attributes": stat.FILE_ATTRIBUTE_REPARSE_POINT},
        "hardlink": {"st_nlink": 2},
        "private-mode": {"st_mode": stat.S_IFREG | 0o644}, "owner": {"st_uid": 7654321},
    }[change]
    monkeypatch.setattr(Path, "lstat", lambda candidate: changed_stat(original_stat(candidate), **changes)
                        if candidate == path else original_stat(candidate))
    opened = []

    def guarded(candidate, *args, **kwargs):
        if candidate == path:
            opened.append(True)
            raise AssertionError(CANARY)
        return original_open(candidate, *args, **kwargs)

    monkeypatch.setattr(metadata.os, "open", guarded)
    if change in {"private-mode", "owner"}:
        # Exercise the POSIX ownership policy even when these tests run on Windows.
        module_os = SimpleNamespace(**vars(metadata.os))
        module_os.name, module_os.getuid = "posix", lambda: original_stat(bundle.run_path).st_uid
        monkeypatch.setattr(metadata, "os", module_os)
    assert collect(bundle) == metadata.UNAVAILABLE
    assert opened == []


@pytest.mark.parametrize("change", ["file-replace-before-open", "descriptor-identity", "private-root"])
def test_open_boundary_and_private_root_are_checked(bundle, monkeypatch, change):
    path = bundle.run_path / "report.json"
    original_open, original_fstat = metadata.os.open, metadata.os.fstat
    if change == "private-root":
        original_stat = Path.lstat
        monkeypatch.setattr(Path, "lstat", lambda candidate: changed_stat(original_stat(candidate), st_mode=0o40755)
                            if candidate == bundle.run_path else original_stat(candidate))
        module_os = SimpleNamespace(**vars(metadata.os))
        module_os.name, module_os.getuid = "posix", lambda: original_stat(bundle.run_path).st_uid
        monkeypatch.setattr(metadata, "os", module_os)
    elif change == "descriptor-identity":
        monkeypatch.setattr(metadata.os, "fstat", lambda descriptor: changed_stat(
            original_fstat(descriptor), st_ino=original_fstat(descriptor).st_ino + 1))
    else:
        def replace_before_open(candidate, *args, **kwargs):
            if candidate == path:
                replacement = path.with_suffix(".replacement")
                write_private(replacement, path.read_bytes())
                os.replace(replacement, path)
            return original_open(candidate, *args, **kwargs)

        monkeypatch.setattr(metadata.os, "open", replace_before_open)
    assert collect(bundle) == metadata.UNAVAILABLE


@pytest.mark.parametrize("change", ["file-replace", "ancestor-replace", "in-place", "late-mutation"])
def test_mutation_of_held_files_or_ancestors_is_refused_and_descriptors_close(bundle, monkeypatch, change):
    original_json, original_fdopen = metadata._json, metadata.os.fdopen
    streams, calls = [], []

    def remember(*args, **kwargs):
        stream = original_fdopen(*args, **kwargs)
        streams.append(stream)
        return stream

    def mutate(raw):
        result = original_json(raw)
        calls.append(True)
        target_call = 4 if change == "late-mutation" else 2  # profile, report, journal, source
        if len(calls) == target_call:
            path = bundle.run_path / "report.json"
            if change == "ancestor-replace":
                saved = bundle.run_path.with_name("moved-private-root")
                bundle.run_path.rename(saved)
                bundle.run_path.mkdir(mode=0o700)
                bundle.run_path.chmod(0o700)
                for item in saved.iterdir():
                    write_private(bundle.run_path / item.name, item.read_bytes())
            elif change == "file-replace":
                replacement = path.with_suffix(".replacement")
                write_private(replacement, path.read_bytes())
                os.replace(replacement, path)
            else:
                with path.open("ab") as stream:
                    stream.write(b" ")
        return result

    monkeypatch.setattr(metadata.os, "fdopen", remember)
    monkeypatch.setattr(metadata, "_json", mutate)
    assert collect(bundle) == metadata.UNAVAILABLE
    assert streams and all(stream.closed for stream in streams)


def test_valid_reads_close_descriptors_and_do_not_compare_windows_path_fd_clocks(bundle, monkeypatch):
    original_fstat, original_fdopen = metadata.os.fstat, metadata.os.fdopen
    streams = []

    def shifted_clock(descriptor):
        info = original_fstat(descriptor)
        return changed_stat(info, st_mtime_ns=info.st_mtime_ns + 10000, st_ctime_ns=info.st_ctime_ns + 10000)

    def remember(*args, **kwargs):
        stream = original_fdopen(*args, **kwargs)
        streams.append(stream)
        return stream

    monkeypatch.setattr(metadata.os, "fstat", shifted_clock)
    monkeypatch.setattr(metadata.os, "fdopen", remember)
    assert collect(bundle) == AVAILABLE
    assert len(streams) == 5 and all(stream.closed for stream in streams)


def test_fd_clock_mutation_is_rejected_even_when_path_stamp_is_stable(bundle, monkeypatch):
    original = metadata.os.fstat
    reads = {}

    def changing_clock(descriptor):
        info = original(descriptor)
        reads[descriptor] = reads.get(descriptor, 0) + 1
        return changed_stat(info, st_mtime_ns=info.st_mtime_ns + reads[descriptor])

    monkeypatch.setattr(metadata.os, "fstat", changing_clock)
    assert collect(bundle) == metadata.UNAVAILABLE


@pytest.mark.parametrize(("field", "value"), [
    ("run_id", "0"), ("run_id", "0123456"), ("run_id", "../123456"), ("run_id", "1\n"),
    ("run_id", True), ("run_attempt", "0"), ("run_attempt", "02"), ("run_attempt", CANARY),
    ("github_sha", "b" * 40), ("github_sha", REVISION.upper()), ("github_sha", CANARY),
    ("home", "."), ("home", "../private"),
])
def test_runner_parameters_are_exact_and_current(bundle, field, value):
    bundle.args[field] = value
    assert collect(bundle) == metadata.UNAVAILABLE


def test_another_attempt_or_another_uuid_cannot_supply_the_current_report(bundle):
    bundle.args["run_attempt"] = "3"
    assert collect(bundle) == metadata.UNAVAILABLE
    bundle.args["run_attempt"] = "2"
    foreign = copy.deepcopy(bundle.values["report"])
    foreign["evidence"]["run_id"] = "c7aca31b-edce-42bf-8dad-8f6d6a88dbf3"
    foreign["evidence"]["installation"] = "q-" + foreign["evidence"]["run_id"].replace("-", "")
    write_private(bundle.run_path / "report.json", foreign)
    assert collect(bundle) == metadata.UNAVAILABLE


def test_changed_public_profile_compose_and_rewritten_installation_profile_cannot_match(bundle):
    path = bundle.repository / metadata.PROFILE
    original = path.read_bytes()
    profile = load_profile(path)
    profile["installation"] = "q-" + RUN_UUID.replace("-", "")
    write_private(path, profile)
    assert collect(bundle) == metadata.UNAVAILABLE
    write_private(path, original)
    with (bundle.repository / metadata.COMPOSE).open("ab") as stream:
        stream.write(b"# private mutation\n")
    assert collect(bundle) == metadata.UNAVAILABLE


def test_checked_out_revision_is_revalidated_after_all_reads(bundle, monkeypatch):
    revisions = iter([REVISION, "b" * 40])
    monkeypatch.setattr(metadata, "_head_revision", lambda _: next(revisions))
    assert collect(bundle) == metadata.UNAVAILABLE


@pytest.mark.parametrize("failure", [
    OSError(CANARY), subprocess.TimeoutExpired(CANARY, 5, output=CANARY, stderr=CANARY),
])
def test_captured_git_failures_are_unavailable_without_leaking(bundle, monkeypatch, capsys, failure):
    def fail(_):
        raise failure

    monkeypatch.setattr(metadata, "_head_revision", fail)
    assert collect(bundle) == metadata.UNAVAILABLE
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(("returncode", "stdout"), [
    (0, REVISION + "\n"), (True, REVISION), (1, CANARY), (0, CANARY), (0, Poison()), (0, "b" * 40 + "\n"),
])
def test_git_revision_capture_is_bounded_and_does_not_publish_stderr(monkeypatch, capsys, returncode, stdout):
    calls = []

    def capture(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=CANARY)

    monkeypatch.setattr(metadata.subprocess, "run", capture)
    Poison.calls.clear()
    if type(returncode) is int and returncode == 0 and type(stdout) is str and len(stdout) == 41:
        assert metadata._head_revision(ROOT) == stdout.strip()
    else:
        with pytest.raises(metadata._UnavailableError):
            metadata._head_revision(ROOT)
    assert calls == [(["git", "rev-parse", "HEAD"],
                      {"cwd": ROOT, "capture_output": True, "text": True, "timeout": 5})]
    assert Poison.calls == [] and capsys.readouterr() == ("", "")


def cli_args(bundle):
    return ["--home", str(bundle.home), "--run-id", "123456", "--run-attempt", "2", "--github-sha", REVISION]


def test_cli_stdout_and_github_output_contain_only_closed_lines(bundle, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PRIVATE_CI_CANARY", CANARY)
    output_path = tmp_path / "GITHUB_OUTPUT"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    with output_path.open("w", encoding="utf-8", newline="\n") as output, contextlib.redirect_stdout(output):
        assert metadata.main(cli_args(bundle), repository=bundle.repository) == 0
    assert output_path.read_text() == metadata.render_metadata(AVAILABLE)
    assert CANARY not in output_path.read_text()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("args", [[], ["--help", CANARY], [CANARY] * 8, [Poison()] * 8, PoisonDict()])
def test_cli_invalid_arguments_are_quiet_and_fixed(args, capsys):
    Poison.calls.clear()
    assert metadata.main(args) == 0
    assert capsys.readouterr() == (FALLBACK, "")
    assert Poison.calls == []


def test_cli_catches_private_internal_exception_without_stringifying(bundle, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError(CANARY)

    monkeypatch.setattr(metadata, "collect_metadata", fail)
    assert metadata.main(cli_args(bundle), repository=bundle.repository) == 0
    assert capsys.readouterr() == (FALLBACK, "")


def test_stdlib_script_has_quiet_malformed_argument_fallback():
    result = subprocess.run([sys.executable, str(ROOT / "scripts/qualification-ci-metadata.py"), CANARY],
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0
    assert result.stdout == FALLBACK and result.stderr == ""


@pytest.fixture
def workflow():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def test_workflow_diagnostics_are_guarded_finite_step_metadata_only(workflow):
    _, document = workflow
    job = document["jobs"]["production-qualification"]
    original, projector, display = job["steps"][2:5]
    assert original["id"] == "qualification_lab"
    assert original["run"] == (
        'python scripts/qualification-lab.py run --execute --docker-context default '
        '--profile deploy/qualification/profiles/lab-smoke.json '
        '--run-dir "$HOME/shadai-qualification-${{ github.run_id }}-${{ github.run_attempt }}"\n'
    )
    guard = "always() && steps.qualification_lab.outcome == 'failure'"
    assert projector["if"] == display["if"] == guard
    assert projector["id"] == "qualification_diagnostic"
    assert projector["run"] == (
        'python scripts/qualification-ci-metadata.py --home "$HOME" --run-id \'${{ github.run_id }}\' '
        '--run-attempt \'${{ github.run_attempt }}\' --github-sha "$GITHUB_SHA" >> "$GITHUB_OUTPUT" 2>/dev/null\n'
    )
    assert display["run"] == ":"
    expected = "Qualification failure diagnostic: " + " ".join(
        key + "=${{ steps.qualification_diagnostic.outputs." + key + " || '" + metadata.UNAVAILABLE[key] + "' }}"
        for key in metadata.FIELDS
    )
    assert display["name"] == expected
    assert all("continue-on-error" not in step for step in job["steps"])
    assert not {"outputs", "if", "continue-on-error"} & job.keys()


def test_workflow_whole_source_preserves_every_original_command_guard_and_job(workflow):
    text, document = workflow
    start = text.index("      - name: Project finite qualification failure metadata\n")
    end = text.index("      - name: Build the maintained Prometheus runtime from its recipe\n", start)
    original = text[:start] + text[end:]
    original = original.replace("        id: qualification_lab\n", "", 1)
    assert hashlib.sha256(original.encode()).hexdigest() == (
        "5a6c394d8e604a6654b2edb5e9b68b13e6ef6813b1ca7d594f5107e3ef32ff04"
    )
    cleanup = document["jobs"]["production-qualification"]["steps"][-1]
    assert cleanup["if"] == "always()"
    assert cleanup["run"] == (
        'if [ -f "$HOME/shadai-qualification-${{ github.run_id }}-${{ github.run_attempt }}/journal.json" ]; then\n'
        '  python scripts/qualification-lab.py clean --execute --remove-volumes --docker-context default '
        '--profile deploy/qualification/profiles/lab-smoke.json '
        '--run-dir "$HOME/shadai-qualification-${{ github.run_id }}-${{ github.run_attempt }}"\nfi\n'
    )


def test_test_module_filtered_collection_has_no_eager_asset_read():
    # Importing the module with absent external assets must remain safe. Execute
    # its definitions with read_text/read_bytes blocked, without running tests.
    source = Path(__file__).read_text(encoding="utf-8")
    namespace = {"__file__": str(Path(__file__))}
    with pytest.MonkeyPatch.context() as patcher:
        def forbidden(*args, **kwargs):
            raise AssertionError("eager_asset_read")

        patcher.setattr(Path, "read_text", forbidden)
        patcher.setattr(Path, "read_bytes", forbidden)
        exec(compile(source, str(Path(__file__)), "exec"), namespace)
    assert "test_workflow_whole_source_preserves_every_original_command_guard_and_job" in namespace
