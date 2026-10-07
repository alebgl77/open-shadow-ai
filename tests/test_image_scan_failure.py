"""Unsigned diagnostics localize failures without changing scanner acceptance or cleanup."""

import hashlib
import json
import os
import stat
import subprocess
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from test_image_scan_layout import COMPONENTS, SCAN, load
from test_image_scan_layout import harness as harness
from test_scan_evidence import evidence as evidence

GRYPE = load("grype_runtime")
CANARY = "private-canary-token-path-command-payload"


def failure(output):
    path, = output.glob("*.failure.json")
    data = path.read_bytes()
    assert len(data) <= 2048 and CANARY.encode() not in data
    value = json.loads(data)
    COMPONENTS.validate_failure_diagnostic(value)
    assert value["accepted"] is False and value["status"] == "diagnostic-only"
    return value


@pytest.mark.parametrize("error,kind,code", [
    (ValueError(CANARY), "ValueError", "validation_refused"),
    (PermissionError(CANARY), "PermissionError", "filesystem"),
    (subprocess.CalledProcessError(23, [CANARY], output=CANARY, stderr=CANARY), "CalledProcessError", "nonzero"),
    (subprocess.TimeoutExpired([CANARY], 1, output=CANARY, stderr=CANARY), "TimeoutExpired", "timeout"),
    (KeyboardInterrupt(CANARY), "KeyboardInterrupt", "interrupted"),
])
def test_first_failure_preserves_primary_cleanup_and_closed_payload(harness, error, kind, code):
    harness.state.error = error
    with pytest.raises(type(error)) as raised:
        harness.run()
    assert raised.value is error
    assert harness.calls == ["prepare", "check", "trivy", "cleanup"]
    value = failure(harness.output)
    assert (value["stage"], value["error_type"], value["code"]) == ("trivy_scan", kind, code)
    assert not (harness.output / "redis.metadata.json").exists()
    assert not (harness.output / "redis.evidence-manifest.json").exists()


def test_actual_grype_prepare_error_is_exact_type_and_fixed_code(harness, monkeypatch):
    error = GRYPE.GrypeRuntimeError("nonzero")
    error.add_note(CANARY)
    original = SCAN.script

    @contextmanager
    def refused(**kwargs):
        harness.state.grype_calls.append("prepare")
        raise error
        yield None

    module = SimpleNamespace(prepared_grype=refused, GrypeRuntimeError=GRYPE.GrypeRuntimeError)
    monkeypatch.setattr(SCAN, "script", lambda name: module if name == "grype_runtime" else original(name))
    with pytest.raises(GRYPE.GrypeRuntimeError) as raised:
        harness.run()
    assert raised.value is error and harness.calls[-1] == "cleanup"
    assert harness.state.grype_calls == ["prepare"]
    value = failure(harness.output)
    assert (value["stage"], value["error_type"], value["code"]) == ("grype_prepare", "GrypeRuntimeError", "nonzero")
    assert value["secondary"] == []
    assert not (harness.output / "redis.metadata.json").exists()


@pytest.mark.parametrize("phase,reason", [
    ("check_files", "home_nonempty"),
    ("update", "tree_nonregular"),
    ("update", "tree_unlinked"),
    ("update", "tree_hardlink"),
    ("update", "tree_file_oversize"),
])
def test_actual_prepare_fixed_phase_and_filesystem_reason_are_unsigned_and_bound_to_real_type(
        harness, monkeypatch, phase, reason):
    error = GRYPE.GrypeRuntimeError("filesystem", filesystem_reason=reason)
    error.prepare_phase = phase
    error.add_note("owned_cleanup_failed")
    original = SCAN.script

    @contextmanager
    def refused(**kwargs):
        harness.state.grype_calls.append("prepare")
        raise error
        yield None

    module = SimpleNamespace(prepared_grype=refused, GrypeRuntimeError=GRYPE.GrypeRuntimeError)
    monkeypatch.setattr(SCAN, "script", lambda name: module if name == "grype_runtime" else original(name))
    with pytest.raises(GRYPE.GrypeRuntimeError) as raised:
        harness.run()
    assert raised.value is error and error.args == ("filesystem",)
    value = failure(harness.output)
    assert value["prepare_phase"] == phase and value["filesystem_reason"] == reason
    assert value["stage"] == "grype_prepare" and value["secondary"] == ["owned_cleanup_failed"]
    assert harness.calls[-1] == "cleanup" and harness.state.grype_calls == ["prepare"]
    assert not (harness.output / "redis.metadata.json").exists()
    assert not (harness.output / "redis.evidence-manifest.json").exists()


@pytest.mark.parametrize("poisoned_field", ["prepare_phase", "filesystem_reason"])
def test_exact_grype_exception_poison_attribute_dict_preserves_primary_and_real_context_cleanup(
        harness, monkeypatch, poisoned_field):
    error = GRYPE.GrypeRuntimeError("filesystem", filesystem_reason="home_nonempty")
    error.prepare_phase = "check_files"
    error.add_note("owned_cleanup_failed")
    inspected = []

    class PoisonAttributes(dict):
        def get(self, key, default=None):
            inspected.append(key)
            if key == poisoned_field:
                raise RuntimeError(CANARY)
            return super().get(key, default)

    error.__dict__ = PoisonAttributes(error.__dict__)
    original = SCAN.script

    @contextmanager
    def refused(**kwargs):
        harness.state.grype_calls.append("prepare")
        try:
            raise error
            yield None
        finally:
            harness.state.grype_calls.append("cleanup")

    module = SimpleNamespace(prepared_grype=refused, GrypeRuntimeError=GRYPE.GrypeRuntimeError)
    monkeypatch.setattr(SCAN, "script", lambda name: module if name == "grype_runtime" else original(name))
    with pytest.raises(GRYPE.GrypeRuntimeError) as raised:
        harness.run()
    assert raised.value is error and error.args == ("filesystem",)
    assert harness.calls == ["prepare", "check", "trivy", "check", "cleanup"]
    assert harness.state.grype_calls == ["prepare", "cleanup"]
    assert "prepare_phase" not in inspected and "filesystem_reason" not in inspected
    value = failure(harness.output)
    assert value["stage"] == "grype_prepare" and value["code"] == "filesystem"
    assert value["secondary"] == ["owned_cleanup_failed"]
    assert "prepare_phase" not in value and "filesystem_reason" not in value
    assert not (harness.output / "redis.metadata.json").exists()
    assert not (harness.output / "redis.evidence-manifest.json").exists()


@pytest.mark.parametrize("field,allowed", [("prepare_phase", COMPONENTS.FAILURE_PREPARE_PHASES),
                                         ("filesystem_reason", COMPONENTS.FAILURE_FILESYSTEM_REASONS)])
def test_all_closed_prepare_details_have_typed_unsigned_schema(tmp_path, field, allowed):
    for detail in allowed:
        trace = COMPONENTS.FailureDiagnostic()
        trace.grype_error_type = GRYPE.GrypeRuntimeError
        trace.at("grype_prepare")
        error = GRYPE.GrypeRuntimeError("filesystem")
        setattr(error, field, detail)
        trace.capture(error)
        assert trace.first[field] == detail
        value = {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
                 **trace.first, "secondary": []}
        COMPONENTS.validate_failure_diagnostic(value)
    assert COMPONENTS.FAILURE_PREPARE_PHASES == GRYPE.PREPARE_PHASES
    assert COMPONENTS.FAILURE_FILESYSTEM_REASONS == GRYPE.FILESYSTEM_REASONS


@pytest.mark.parametrize("field", ["prepare_phase", "filesystem_reason"])
@pytest.mark.parametrize("bad", [CANARY, None, True, 1, {}, [], "version" * 1000])
def test_untrusted_prepare_detail_is_omitted_and_schema_rejects_explicit_value(tmp_path, field, bad):
    trace = COMPONENTS.FailureDiagnostic()
    trace.grype_error_type = GRYPE.GrypeRuntimeError
    trace.at("grype_prepare")
    error = GRYPE.GrypeRuntimeError("filesystem")
    setattr(error, field, bad)
    trace.emit(tmp_path, error)
    value = failure(tmp_path)
    assert field not in value
    value[field] = bad
    with pytest.raises(ValueError):
        COMPONENTS.validate_failure_diagnostic(value)


@pytest.mark.parametrize("field", ["prepare_phase", "filesystem_reason"])
def test_poison_string_prepare_details_are_never_compared_or_serialized(tmp_path, field):
    class PoisonString(str):
        def __eq__(self, other):
            raise AssertionError("untrusted detail compared")

        def __hash__(self):
            raise AssertionError("untrusted detail hashed")

        def __str__(self):
            raise AssertionError("untrusted detail serialized")

    trace = COMPONENTS.FailureDiagnostic()
    trace.grype_error_type = GRYPE.GrypeRuntimeError
    trace.at("grype_prepare")
    error = GRYPE.GrypeRuntimeError("filesystem")
    setattr(error, field, PoisonString(CANARY))
    trace.emit(tmp_path, error)
    value = failure(tmp_path)
    assert field not in value
    value[field] = getattr(error, field)
    with pytest.raises(ValueError):
        COMPONENTS.validate_failure_diagnostic(value)


@pytest.mark.parametrize("mutation", ["wrong_stage", "wrong_type", "wrong_code"])
def test_fixed_prepare_detail_cannot_claim_other_stage_or_exception_authority(mutation):
    value = {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
             "stage": "grype_prepare", "error_type": "GrypeRuntimeError", "code": "filesystem", "secondary": [],
             "prepare_phase": "version", "filesystem_reason": "syscall"}
    value[{"wrong_stage": "stage", "wrong_type": "error_type", "wrong_code": "code"}[mutation]] = \
        {"wrong_stage": "sentinel_query", "wrong_type": "ValueError", "wrong_code": "nonzero"}[mutation]
    with pytest.raises(ValueError):
        COMPONENTS.validate_failure_diagnostic(value)


@pytest.mark.parametrize("base", [ValueError, GRYPE.GrypeRuntimeError])
def test_malicious_exception_subclass_is_not_inspected(tmp_path, base):
    class PoisonError(base):
        def __str__(self):
            raise AssertionError("exception string inspected")

        def __getattribute__(self, name):
            if name in {"args", "code", "__dict__", "__notes__"}:
                raise AssertionError("exception payload inspected")
            return super().__getattribute__(name)

    trace = COMPONENTS.FailureDiagnostic()
    trace.grype_error_type = GRYPE.GrypeRuntimeError
    error = PoisonError.__new__(PoisonError)
    ValueError.__init__(error, CANARY)
    trace.emit(tmp_path, error)
    value = failure(tmp_path)
    assert value["error_type"] == value["code"] == "unclassified"


@pytest.mark.parametrize("phase", ["source", "sentinel", "query", "postcheck", "cleanup"])
def test_each_complement_refusal_has_stage_and_no_accepted_metadata(harness, phase):
    expected = {"source": "source_binding", "sentinel": "sentinel_report", "query": "component_report",
                "postcheck": "grype_postcheck", "cleanup": "cleanup"}[phase]
    component = "postgres" if phase == "source" else "redis"
    if phase == "source":
        def mutate_source(doc):
            graph = doc["provenance"]["statement"]["predicate"]["buildDefinition"]["internalParameters"][
                "buildConfig"]["llbDefinition"]
            graph[8]["op"]["Op"]["file"]["actions"][0]["Action"]["copy"]["dest"] = "/foreign-binary"
        harness.state.source_mutate = mutate_source
    elif phase in {"sentinel", "query"}:
        def mutate(report, identifier):
            sentinel = identifier.endswith("@0.1.0") or ":5.0.0:" in identifier
            if sentinel is (phase == "sentinel"):
                report["ignoredMatches"] = [{"payload": CANARY}]
        harness.state.grype_mutate = mutate
    elif phase == "postcheck":
        harness.state.grype_post_error = ValueError(CANARY)
    else:
        harness.state.grype_cleanup_error = ValueError(CANARY)
    with pytest.raises(ValueError):
        harness.run(component)
    assert failure(harness.output)["stage"] == expected
    assert harness.calls[-1] == "cleanup"
    assert not (harness.output / f"{component}.metadata.json").exists()


def test_primary_capture_precedes_both_cleanup_refusals(harness, monkeypatch):
    primary = TimeoutError(CANARY)
    harness.state.grype_error = primary
    harness.state.grype_cleanup_error = ValueError(CANARY)
    original = SCAN.script
    layout = original("oci_scan_layout")

    @contextmanager
    def disposing(*args, **kwargs):
        try:
            with layout.prepared_layout(*args, **kwargs) as handle:
                yield handle
        except BaseException as error:
            error.add_note("owned_cleanup_failed")
            raise

    module = SimpleNamespace(prepared_layout=disposing)
    monkeypatch.setattr(SCAN, "script", lambda name: module if name == "oci_scan_layout" else original(name))
    with pytest.raises(TimeoutError) as raised:
        harness.run()
    assert raised.value is primary and primary.__notes__ == ["owned_cleanup_failed", "owned_cleanup_failed"]
    value = failure(harness.output)
    assert value["stage"] == "sentinel_query" and value["secondary"] == ["owned_cleanup_failed"]
    assert harness.state.grype_calls[-1] == harness.calls[-1] == "cleanup"


@pytest.mark.parametrize("defect", ["extra", "schema_bool", "accepted_int", "accepted_true", "kind",
                                  "status", "stage", "error_type", "code", "secondary", "duplicate_note"])
def test_diagnostic_schema_is_closed_and_typed(defect):
    value = {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
             "stage": "grype_prepare", "error_type": "GrypeRuntimeError", "code": "nonzero", "secondary": []}
    if defect == "extra":
        value["payload"] = CANARY
    elif defect == "schema_bool":
        value["schema"] = True
    elif defect == "accepted_int":
        value["accepted"] = 0
    elif defect == "accepted_true":
        value["accepted"] = True
    elif defect == "duplicate_note":
        value["secondary"] = ["owned_cleanup_failed"] * 2
    elif defect == "secondary":
        value["secondary"] = [CANARY]
    else:
        value[defect] = CANARY
    with pytest.raises(ValueError):
        COMPONENTS.validate_failure_diagnostic(value)


def test_diagnostic_writer_is_exclusive_private_and_never_overwrites(tmp_path, monkeypatch):
    trace = COMPONENTS.FailureDiagnostic()
    monkeypatch.setattr(COMPONENTS, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    trace.emit(tmp_path, ValueError(CANARY))
    path = tmp_path / ("image-scan." + "a" * 32 + ".failure.json")
    before = path.read_bytes()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        trace.emit(tmp_path, KeyboardInterrupt())
    assert path.read_bytes() == before


def test_diagnostic_writer_refuses_symlink_parent_before_creation(tmp_path, monkeypatch):
    original = type(tmp_path).lstat
    def linked(path):
        return SimpleNamespace(st_mode=stat.S_IFLNK) if path == tmp_path else original(path)
    monkeypatch.setattr(type(tmp_path), "lstat", linked)
    with pytest.raises(ValueError, match="parent refused"):
        COMPONENTS.FailureDiagnostic().emit(tmp_path, ValueError(CANARY))
    assert not list(tmp_path.glob("*.failure.json"))


@pytest.mark.parametrize("field", ["kind", "status", "stage", "code"])
def test_schema_rejects_string_subclasses_before_comparing_payload(field):
    class PoisonString(str):
        def __eq__(self, other):
            raise AssertionError("untrusted scalar compared")
    value = {"schema": 1, "kind": "image-scan-failure", "status": "diagnostic-only", "accepted": False,
             "stage": "grype_prepare", "error_type": "GrypeRuntimeError", "code": "nonzero", "secondary": []}
    value[field] = PoisonString(CANARY)
    with pytest.raises(ValueError):
        COMPONENTS.validate_failure_diagnostic(value)


@pytest.mark.parametrize("operation", ["open", "write", "close"])
def test_diagnostic_writer_failure_never_replaces_primary_or_publishes_metadata(harness, monkeypatch, operation):
    error = KeyboardInterrupt(CANARY)
    harness.state.error = error
    original_open, original_write, original_close = COMPONENTS.os.open, COMPONENTS.os.write, COMPONENTS.os.close
    descriptors, closes = set(), []

    def opening(path, *args, **kwargs):
        diagnostic = "image-scan." in str(path)
        if diagnostic and operation == "open":
            raise PermissionError(CANARY)
        fd = original_open(path, *args, **kwargs)
        if diagnostic:
            descriptors.add(fd)
        return fd

    def writing(fd, data):
        if fd in descriptors and operation == "write":
            raise PermissionError(CANARY)
        return original_write(fd, data)

    def closing(fd):
        result = original_close(fd)
        if fd in descriptors:
            closes.append(fd)
            if operation == "close":
                raise PermissionError(CANARY)
        return result

    monkeypatch.setattr(COMPONENTS.os, "open", opening)
    monkeypatch.setattr(COMPONENTS.os, "write", writing)
    monkeypatch.setattr(COMPONENTS.os, "close", closing)
    with pytest.raises(KeyboardInterrupt) as raised:
        harness.run()
    assert raised.value is error and error.__notes__ == ["scanner_diagnostic_failed"]
    assert len(closes) == len(set(closes))
    assert not (harness.output / "redis.metadata.json").exists()
    assert harness.calls[-1] == "cleanup"


def test_successful_scan_has_no_failure_diagnostic_or_extra_tool_calls(harness):
    harness.run()
    assert not list(harness.output.glob("*.failure.json"))
    assert harness.calls == ["prepare", "check", "trivy", "check", "check", "cleanup"]
    assert len(harness.state.grype_calls) == 6 and harness.state.grype_calls[0] == "prepare"
    assert harness.state.grype_calls[-1] == "cleanup"
    assert (harness.output / "redis.metadata.json").exists()


def test_advisory_failure_remains_nonzero_and_explicit_failed_metadata(harness):
    def mutate(report):
        result = report["Results"][0]
        result["Vulnerabilities"] = [{"VulnerabilityID": CANARY, "PkgName": result["Packages"][0]["Name"],
                                     "Severity": "HIGH", "FixedVersion": "999"}]
    harness.state.mutate = mutate
    with pytest.raises(SystemExit):
        harness.run()
    assert failure(harness.output)["code"] == "advisory_failed"
    assert json.loads((harness.output / "redis.metadata.json").read_bytes())["verdict"] == "failed"


def test_unsigned_failure_cannot_become_a_signing_report_even_when_hash_bound(evidence):
    output = evidence.harness.output
    COMPONENTS.FailureDiagnostic().emit(output, ValueError(CANARY))
    path, = output.glob("*.failure.json")
    metadata = evidence.metadata()
    receipt = metadata["complement"]["receipts"][0]
    receipt["report_path"] = path.name
    receipt["report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (output / "postgres.metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="Unsafe or unexpected scanner evidence path"):
        evidence.run()
    assert not (output / "postgres.evidence-manifest.json").exists()
