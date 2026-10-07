"""Failure-only export metadata; real source/archive guards, modeled Docker only."""

import asyncio
import builtins
import json
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_qualification_cold_diagnostics import bare_lab, create_cold_lab
from test_qualification_pressure_diagnostics import CANARY

import shadai.qualification.lab as lab_module
import shadai.qualification.snapshot as snapshot
from shadai.qualification.__main__ import main
from shadai.qualification.lab import EXPORT_SNAPSHOT_CODE, closed_cold_evidence
from shadai.qualification.schemas import QualificationError


def envelope(step="write", reason="operation_error", secondary=None):
    return {"schema": 1, "status": "not_evaluated", "step": step, "reason": reason,
            "secondary": [] if secondary is None else [secondary]}


CLI_ERROR = json.dumps({"schema": 1, "status": "not_evaluated", "reason": "QualificationError", "exit_code": 2})


def test_real_healthy_export_opt_in_preserves_bytes_and_return(tmp_path, capsys):
    source = tmp_path / "source"
    source.mkdir()
    (source / "event").write_bytes(b"opaque data")
    plain = snapshot.export_volume(source, tmp_path / "plain.tar", 1024)
    with snapshot.export_diagnostics() as diagnostic:
        opted = snapshot.export_volume(source, tmp_path / "opted.tar", 1024)
        assert diagnostic.primary is diagnostic.secondary is None
    assert snapshot._EXPORT_CONTEXT.get() is None
    assert {k: v for k, v in plain.items() if k != "archive"} == {k: v for k, v in opted.items() if k != "archive"}
    assert (tmp_path / "plain.tar").read_bytes() == (tmp_path / "opted.tar").read_bytes()
    assert capsys.readouterr().out == ""


def test_ordinary_cli_failure_is_byte_exact_and_opt_in_wrapper_is_closed(tmp_path, monkeypatch, capsys):
    args = ["snapshot", "export", "--volume", str(tmp_path / CANARY), "--archive", str(tmp_path / "a.tar"),
            "--max-bytes", "1024"]
    assert main(args) == 2
    assert capsys.readouterr().out == CLI_ERROR + "\n"
    calls = []
    resource = SimpleNamespace(RLIMIT_FSIZE=1, setrlimit=lambda *args: calls.append(args))
    monkeypatch.setitem(sys.modules, "resource", resource)
    monkeypatch.setattr(sys, "argv", ["-c", "1073741824", *args])
    original_print = builtins.print
    with pytest.raises(SystemExit) as caught:
        exec(EXPORT_SNAPSHOT_CODE, {})
    assert caught.value.code == 2 and builtins.print is original_print
    raw = capsys.readouterr().out
    assert snapshot.parse_export_diagnostic(raw) == envelope("source_guard", "source_guard")
    assert CANARY not in raw and str(tmp_path) not in raw
    assert calls == [(1, (1073741824, 1073741824))]
    assert snapshot._EXPORT_CONTEXT.get() is None


def test_wrapper_healthy_cli_stdout_exact(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    archive = tmp_path / "archive.tar"
    args = ["snapshot", "export", "--volume", str(source), "--archive", str(archive), "--max-bytes", "1024"]
    monkeypatch.setitem(sys.modules, "resource", SimpleNamespace(RLIMIT_FSIZE=1, setrlimit=lambda *args: None))
    monkeypatch.setattr(sys, "argv", ["-c", "1073741824", *args])
    with pytest.raises(SystemExit) as caught:
        exec(EXPORT_SNAPSHOT_CODE, {})
    assert caught.value.code == 0
    raw = capsys.readouterr().out
    manifest = json.loads(Path(str(archive) + ".manifest.json").read_text())
    ordered = {key: manifest[key] for key in ("schema", "sha256", "bytes", "unpacked_bytes", "archive")}
    assert raw == json.dumps(ordered, separators=(",", ":")) + "\n"
    assert snapshot._EXPORT_CONTEXT.get() is None


@pytest.mark.parametrize("kind", [OSError, QualificationError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("step", sorted(snapshot.EXPORT_STEPS - {
    "unknown", "cli_result", "file_close", "archive_close"}))
def test_actual_export_operations_capture_closed_step_without_changing_exception(tmp_path, monkeypatch, kind, step):
    source, archive = tmp_path / "source", tmp_path / "archive.tar"
    source.mkdir()
    (source / "event").write_bytes(b"data")
    error = kind(CANARY)
    original = snapshot.export_checkpoint

    def checkpoint(value):
        original(value)
        if value == step:
            raise error

    monkeypatch.setattr(snapshot, "export_checkpoint", checkpoint)
    with snapshot.export_diagnostics() as diagnostic:
        with pytest.raises(kind) as caught:
            snapshot.export_volume(source, archive, 1024)
        assert caught.value is error
        assert diagnostic.envelope() == envelope(step)
    assert snapshot._EXPORT_CONTEXT.get() is None


def member(name="owned", kind=tarfile.REGTYPE, *, size=0, link=""):
    value = tarfile.TarInfo(name)
    value.type, value.size, value.linkname = kind, size, link
    return value


GUARD_CASES = [
    ("file_budget", [member()] * 100001, 10),
    ("path_guard", [member("../" + CANARY)], 10),
    ("metadata_guard", [member(), member()], 10),
    ("object_guard", [member(kind=tarfile.FIFOTYPE)], 10),
    ("content_budget", [member(size=2)], 1),
    ("link_guard", [member(kind=tarfile.SYMTYPE, link="/" + CANARY)], 10),
    ("link_escape", [member(kind=tarfile.SYMTYPE, link="../" + CANARY)], 10),
    ("link_cycle", [member("a", tarfile.SYMTYPE, link="b"), member("b", tarfile.SYMTYPE, link="a")], 10),
    ("hardlink_missing", [member(kind=tarfile.LNKTYPE, link=CANARY)], 10),
    ("hardlink_nonregular", [member("directory", tarfile.DIRTYPE), member(kind=tarfile.LNKTYPE, link="directory")], 10),
]


@pytest.mark.parametrize("reason,members,budget", GUARD_CASES)
def test_existing_member_guard_reasons_are_closed(reason, members, budget):
    with snapshot.export_diagnostics() as diagnostic:
        snapshot.export_checkpoint("validate")
        with pytest.raises(QualificationError):
            with snapshot.export_capture():
                snapshot.validate_members(members, budget)
        assert diagnostic.envelope() == envelope("validate", reason)
        assert CANARY not in json.dumps(diagnostic.envelope())


def test_existing_header_budget_guard_remains_strict(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(tarfile.TarInfo, "tobuf", lambda *args, **kwargs: b"x" * 10485761)
    with snapshot.export_diagnostics() as diagnostic:
        with pytest.raises(QualificationError, match="metadata exceeds"):
            snapshot.export_volume(source, tmp_path / "archive.tar", 0)
        assert diagnostic.envelope() == envelope("header_budget", "header_budget")


@pytest.mark.parametrize("primary_kind", [ValueError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
@pytest.mark.parametrize("secondary_kind", [OSError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_real_archive_finally_preserves_primary_and_actual_secondary_propagation(
    tmp_path, monkeypatch, primary_kind, secondary_kind
):
    source = tmp_path / "source"
    source.mkdir()
    primary, secondary = primary_kind(CANARY), secondary_kind(CANARY)
    original_exit = tarfile.TarFile.__exit__

    def close(file, *args):
        original_exit(file, *args)
        raise secondary

    def fail(*args, **kwargs):
        raise primary

    monkeypatch.setattr(tarfile.TarFile, "gettarinfo", fail)
    monkeypatch.setattr(tarfile.TarFile, "__exit__", close)
    with snapshot.export_diagnostics() as diagnostic:
        with pytest.raises(secondary_kind) as caught:
            snapshot.export_volume(source, tmp_path / "archive.tar", 1024)
        assert caught.value is secondary
        assert diagnostic.exception is primary
        assert diagnostic.envelope() == envelope(
            "header", secondary={"step": "archive_close", "reason": "operation_error"})


@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_real_source_file_close_is_localized_without_exception_masking(tmp_path, monkeypatch, kind):
    source = tmp_path / "source"
    source.mkdir()
    target = source / "event"
    target.write_bytes(b"data")
    original = Path.open
    error = kind(CANARY)

    class ClosingFile:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self.file.__enter__()

        def __exit__(self, *args):
            self.file.__exit__(*args)
            raise error

    def opened(path, *args, **kwargs):
        file = original(path, *args, **kwargs)
        return ClosingFile(file) if path == target else file

    monkeypatch.setattr(Path, "open", opened)
    with snapshot.export_diagnostics() as diagnostic:
        with pytest.raises(kind) as caught:
            snapshot.export_volume(source, tmp_path / "archive.tar", 1024)
        assert caught.value is error
        assert diagnostic.envelope() == envelope("file_close")


class StringAlias(str):
    def __hash__(self):
        raise AssertionError("untrusted scalar evaluated")


class DictAlias(dict):
    def __iter__(self):
        raise AssertionError("untrusted container evaluated")


class ListAlias(list):
    def __iter__(self):
        raise AssertionError("untrusted container evaluated")


@pytest.mark.parametrize("value", [None, [], DictAlias(), {},
                                  {**envelope(), "schema": True}, {**envelope(), "step": StringAlias("write")},
                                  {**envelope(), "secondary": ListAlias()},
                                  {**envelope(), "secondary": [DictAlias(step="write", reason="operation_error")]},
                                  {**envelope(), "reason": CANARY}, {**envelope(), "payload": CANARY}])
def test_envelope_rejects_virtual_containers_scalars_and_extra_data(value):
    assert not snapshot.closed_export_diagnostic(value)


@pytest.mark.parametrize("raw", [None, 2, StringAlias(CLI_ERROR), b"{}", "", "[]", "null", "{}",
                                "x" * 769, CANARY + json.dumps(envelope()), json.dumps(envelope()) + "\n{}",
                                '{"schema":1,"schema":1}', '{"schema":NaN}', "é",
                                json.dumps({**envelope(), "schema": True}),
                                json.dumps({**envelope(), "secondary": [
                                    {"step": "write", "reason": "operation_error"}] * 2})])
def test_parser_rejects_absent_mixed_duplicate_nonfinite_or_untrusted_output(raw):
    assert snapshot.parse_export_diagnostic(raw) == envelope("unknown", "diagnostic_unavailable")


def test_largest_envelope_and_unknown_points_remain_bounded_and_private(capsys):
    diagnostic = snapshot.ExportDiagnostic()
    longest_step = max(snapshot.EXPORT_STEPS, key=len)
    longest_reason = max(snapshot.EXPORT_REASONS, key=len)
    diagnostic.primary = {"step": longest_step, "reason": longest_reason}
    diagnostic.secondary = diagnostic.primary.copy()
    diagnostic.print(CLI_ERROR)
    raw = capsys.readouterr().out
    assert len(raw.encode("ascii")) <= snapshot.EXPORT_DIAGNOSTIC_LIMIT
    assert snapshot.parse_export_diagnostic(raw) == diagnostic.envelope()
    diagnostic.primary, diagnostic.secondary = DictAlias(payload=CANARY), [CANARY]
    diagnostic.print(CLI_ERROR)
    raw = capsys.readouterr().out
    assert CANARY not in raw and snapshot.parse_export_diagnostic(raw) == envelope("cli_result")


def test_print_forwards_all_healthy_unexpected_malformed_arguments_exactly(monkeypatch):
    seen = []
    monkeypatch.setattr(builtins, "print", lambda *args, **kwargs: seen.append((args, kwargs)))
    diagnostic = snapshot.ExportDiagnostic()
    controls = [((), {}), (("healthy",), {"end": ""}), (("{}",), {}), (("broken{",), {}),
                (("a", "b"), {"sep": "/"}), ((CLI_ERROR,), {"flush": True}),
                ((json.dumps({"schema": True, "status": "not_evaluated", "reason": "OSError", "exit_code": 2}),), {}),
                ((json.dumps({"schema": 1, "status": "not_evaluated", "reason": CANARY, "exit_code": 2}),), {})]
    for args, kwargs in controls:
        diagnostic.print(*args, **kwargs)
    assert seen == controls


@pytest.mark.parametrize("kind", [OSError, RuntimeError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_failed_diagnostic_write_only_suppresses_ordinary_exceptions(monkeypatch, kind):
    error = kind(CANARY)

    def fail(*args, **kwargs):
        raise error

    diagnostic = snapshot.ExportDiagnostic()
    monkeypatch.setattr(builtins, "print", fail)
    if issubclass(kind, Exception):
        diagnostic.print(CLI_ERROR)
    else:
        with pytest.raises(kind) as caught:
            diagnostic.print(CLI_ERROR)
        assert caught.value is error
    with pytest.raises(kind) as caught:
        diagnostic.print("healthy")
    assert caught.value is error


def test_scoped_context_nesting_and_pure_capture_failure_preserve_cancellation(monkeypatch):
    error = KeyboardInterrupt(CANARY)
    with snapshot.export_diagnostics() as outer:
        with snapshot.export_diagnostics() as inner:
            assert snapshot._EXPORT_CONTEXT.get() is inner
        assert snapshot._EXPORT_CONTEXT.get() is outer
        monkeypatch.setattr(snapshot.ExportDiagnostic, "capture", lambda *args: (_ for _ in ()).throw(SystemExit(9)))
        with pytest.raises(KeyboardInterrupt) as caught:
            with snapshot.export_capture():
                raise error
        assert caught.value is error
    assert snapshot._EXPORT_CONTEXT.get() is None


@pytest.mark.parametrize("code", [1, 2, 137, 255, -1, 256, True])
@pytest.mark.parametrize("raw", [json.dumps(envelope("validate", "link_cycle")), CANARY,
                                json.dumps(envelope("write", secondary={
                                    "step": "archive_close", "reason": "operation_error"}))])
def test_lab_failure_enrichment_is_closed_bounded_and_cannot_replace_first_primary(tmp_path, code, raw):
    lab = bare_lab(tmp_path)
    error = QualificationError(CANARY)
    with lab.cold_diagnostics("export"):
        lab.cold_checkpoint("result", service="clickhouse")
        lab.cold_export_failure(error, code, raw)
        frozen = json.dumps(lab.failure, sort_keys=True)
        lab.cold_export_failure(ValueError(CANARY), 3, json.dumps(envelope("digest")))
        assert json.dumps(lab.failure, sort_keys=True) == frozen
        primary = {key: value for key, value in lab.failure.items() if key != "secondary"}
        assert closed_cold_evidence(primary)
        assert all(closed_cold_evidence(value) for value in lab.failure.get("secondary", []))
        assert len(frozen.encode()) <= 2048 and CANARY not in frozen
        assert ("helper_exit_status" in primary) == (type(code) is int and 1 <= code <= 255)
        lab.cold_failure(OSError(CANARY), secondary=True)
        assert len(lab.failure.get("secondary", [])) == 1


def test_actual_helper_nonzero_records_closed_context_and_leaves_exact_resources_cleanable(tmp_path, monkeypatch):
    lab, cli = create_cold_lab(tmp_path, monkeypatch)
    original = cli.runner
    raw = json.dumps(envelope("validate", "link_cycle"))

    def runner(command, **kwargs):
        args = command[3:]
        if args[:2] == ["network", "rm"]:
            cli.networks.pop(args[2])
            return cli.response()
        if lab.cold_section == "export" and args[:2] == ["container", "wait"]:
            return cli.response("2")
        if lab.cold_section == "export" and args[:2] == ["container", "logs"]:
            return cli.response(raw)
        return original(command, **kwargs)

    lab.docker.runner = runner
    with pytest.raises(QualificationError) as caught:
        lab.experiment_cold_restore("unused")
    assert caught.value.args == ("Archive helper failed",)
    assert lab.failure["checkpoint"] == "cold_restore_export_result"
    assert lab.failure["last_completed"] == "cold_restore_export_logs"
    assert lab.failure["service"] == "clickhouse" and lab.failure["helper_exit_status"] == 2
    assert lab.failure["helper_step"] == "validate" and lab.failure["helper_reason"] == "link_cycle"
    assert lab.clean(execute=True, remove_volumes=True)["cleaned"]
    assert not any("_export_" in value for value in cli.volumes)


def test_poisoned_parser_cannot_publish_payload_or_mask_original_exception(tmp_path, monkeypatch):
    lab = bare_lab(tmp_path)
    monkeypatch.setattr(lab_module, "parse_export_diagnostic", lambda raw: DictAlias(payload=CANARY))
    with lab.cold_diagnostics("export"):
        lab.cold_checkpoint("result", service="clickhouse")
        lab.cold_export_failure(QualificationError(CANARY), 2, CANARY)
    assert CANARY not in json.dumps(lab.failure) and "helper_step" not in lab.failure


@pytest.mark.parametrize("kind", [OSError, KeyboardInterrupt, SystemExit, asyncio.CancelledError])
def test_archive_close_without_prior_failure_is_primary(tmp_path, monkeypatch, kind):
    source = tmp_path / "source"
    source.mkdir()
    original = tarfile.TarFile.__exit__
    error = kind(CANARY)

    def close(file, *args):
        original(file, *args)
        raise error

    monkeypatch.setattr(tarfile.TarFile, "__exit__", close)
    with snapshot.export_diagnostics() as diagnostic:
        with pytest.raises(kind) as caught:
            snapshot.export_volume(source, tmp_path / "archive.tar", 1024)
        assert caught.value is error and diagnostic.envelope() == envelope("archive_close")


def test_actual_cli_manifest_failure_remains_failure_without_inferred_system_cause(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    source.mkdir()
    args = ["snapshot", "export", "--volume", str(source), "--archive", str(tmp_path / "a.tar"),
            "--max-bytes", "1024"]
    error = OSError(CANARY)

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("shadai.qualification.journal.atomic_json", fail)
    monkeypatch.setitem(sys.modules, "resource", SimpleNamespace(RLIMIT_FSIZE=1, setrlimit=lambda *args: None))
    monkeypatch.setattr(sys, "argv", ["-c", "1073741824", *args])
    with pytest.raises(SystemExit) as caught:
        exec(EXPORT_SNAPSHOT_CODE, {})
    assert caught.value.code == 2
    raw = capsys.readouterr().out
    assert snapshot.parse_export_diagnostic(raw) == envelope("cli_result")
    assert CANARY not in raw and snapshot._EXPORT_CONTEXT.get() is None


@pytest.mark.parametrize("value", [DictAlias(payload=CANARY), {**envelope(), "payload": CANARY}])
def test_poisoned_emitter_envelope_is_replaced_with_closed_unavailable(monkeypatch, capsys, value):
    diagnostic = snapshot.ExportDiagnostic()
    monkeypatch.setattr(diagnostic, "envelope", lambda: value)
    diagnostic.print(CLI_ERROR)
    raw = capsys.readouterr().out
    assert CANARY not in raw and snapshot.parse_export_diagnostic(raw) == envelope("unknown", "diagnostic_unavailable")


def test_pure_cleanup_metadata_failure_never_masks_active_primary(monkeypatch):
    primary = KeyboardInterrupt(CANARY)
    with snapshot.export_diagnostics() as diagnostic:
        snapshot.export_checkpoint("write")
        monkeypatch.setattr(snapshot, "export_checkpoint", lambda *args: (_ for _ in ()).throw(SystemExit(9)))
        with pytest.raises(KeyboardInterrupt) as caught:
            with snapshot.export_capture("archive_close"):
                raise primary
        assert caught.value is primary and diagnostic.exception is primary
        assert diagnostic.envelope() == envelope("write")


def test_context_rejects_scalar_aliases_and_retains_only_first_secondary():
    with snapshot.export_diagnostics() as diagnostic:
        snapshot.export_checkpoint(StringAlias("write"))
        snapshot.export_refusal(StringAlias("operation_error"))
        diagnostic.capture(ValueError(CANARY))
        assert diagnostic.primary == {"step": "unknown", "reason": "diagnostic_unavailable"}
        snapshot.export_checkpoint("file_close")
        diagnostic.capture(OSError(CANARY))
        snapshot.export_checkpoint("archive_close")
        diagnostic.capture(SystemExit(CANARY))
        assert diagnostic.envelope()["secondary"] == [{"step": "file_close", "reason": "operation_error"}]
