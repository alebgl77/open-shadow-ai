"""Fail-closed guards for the standalone installed-wheel acceptance helper."""

import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("installed_agent_proof", ROOT / "scripts/test-installed-agent.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


def test_real_file_with_correct_bytes_outside_site_packages_is_rejected(tmp_path):
    checkout = tmp_path / "checkout/main.py"
    checkout.parent.mkdir()
    checkout.write_bytes(b"synthetic matching module\n")
    with pytest.raises(ValueError, match="outside_installed_site_packages"):
        PROOF.verify_module_origin(SimpleNamespace(__file__=str(checkout)), tmp_path / "environment/site-packages",
                                   hashlib.sha256(checkout.read_bytes()).hexdigest())


def test_installed_file_with_changed_bytes_is_rejected(tmp_path):
    purelib = tmp_path / "environment/site-packages"
    purelib.mkdir(parents=True)
    module = purelib / "main.py"
    module.write_bytes(b"different installed bytes\n")
    with pytest.raises(ValueError, match="module_hash_mismatch"):
        PROOF.verify_module_origin(SimpleNamespace(__file__=str(module)), purelib,
                                   hashlib.sha256(b"expected wheel bytes\n").hexdigest())
    PROOF.verify_module_origin(SimpleNamespace(__file__=str(module)), purelib,
                               hashlib.sha256(module.read_bytes()).hexdigest())


def test_corrupt_wheelhouse_manifest_fails_before_installation(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "agent.txt").write_bytes(b"changed dependency bytes\n")
    (wheelhouse / "SHA256SUMS.json").write_text(json.dumps({"agent.txt": "a" * 64}), encoding="utf8")
    with pytest.raises(ValueError, match="wheelhouse_hash_mismatch"):
        PROOF.wheel_inventory(wheelhouse, tmp_path / "checkout")


def test_qa_root_refuses_other_targets_before_creation(tmp_path):
    allowed = tmp_path / ("installed-agent-" + "a" * 32)
    PROOF.verify_qa_root(allowed, tmp_path)
    for target, parent in ((tmp_path, tmp_path), (tmp_path / "shared", tmp_path),
                           (allowed, tmp_path / "other")):
        with pytest.raises(ValueError, match="unsafe_installed_agent_qa_path"):
            PROOF.verify_qa_root(target, parent)
    assert not allowed.exists()


@pytest.mark.parametrize(("filename", "function"), [
    ("test-delivery-spool-acl.py", "fixture_action"),
    ("test-delivery-spool-acl.py", "ancestor_diagnostic"),
    ("test-network-key-acl.py", "fixture_action"),
])
def test_native_fixture_child_environment_has_one_trusted_module_path(tmp_path, monkeypatch, filename, function):
    spec = importlib.util.spec_from_file_location("native_fixture_environment", ROOT / "scripts" / filename)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    inherited = {"SystemRoot": "C:/Windows", "KEEP": "unchanged", "PSMODULEPATH": "untrusted-uppercase",
                 "PSModulePath": "untrusted-mixed", "psmodulepath": "untrusted-lower"}
    before = dict(inherited)
    captured = []

    def capture(*args, **kwargs):
        captured.append(kwargs["env"])
        return SimpleNamespace(returncode=0, stdout='{"first_effective_issue":null}')

    monkeypatch.setattr(fixture.os, "environ", inherited)
    monkeypatch.setattr(fixture.subprocess, "run", capture)
    if function == "ancestor_diagnostic":
        fixture.ancestor_diagnostic(tmp_path)
    elif filename == "test-delivery-spool-acl.py":
        fixture.fixture_action("explicit", tmp_path / "leaf", tmp_path)
    else:
        fixture.fixture_action("setup", tmp_path / "leaf")
    [child] = captured
    assert [key for key in child if key.casefold() == "psmodulepath"] == ["PSMODULEPATH"]
    assert child["PSMODULEPATH"] == str(Path("C:/Windows/System32/WindowsPowerShell/v1.0/Modules"))
    assert child["KEEP"] == "unchanged" and inherited == before


@pytest.fixture
def installed_run(tmp_path, monkeypatch):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel = wheelhouse / "shadai_agent-synthetic.whl"
    wheel.write_bytes(b"synthetic wheel bytes\n")
    modules = {"shadai_agent/main.py": "a" * 64}
    root = tmp_path / ("installed-agent-" + "a" * 32)
    arguments = SimpleNamespace(wheelhouse=wheelhouse, temporary_parent=tmp_path,
                                output=tmp_path / "report.json")
    inherited = {"SystemRoot": "C:/Windows", "KEEP": "unchanged", "PIP_INDEX_URL": "excluded",
                 "HTTP_PROXY": "excluded", "PYTHONPATH": "excluded", "SHADAI_SECRET": "excluded",
                 "PSMODULEPATH": "untrusted-upper", "PSModulePath": "untrusted-mixed"}
    controls = SimpleNamespace(fail_at=None, error=None, state_override=None, replace_state=False,
                               nonzero_at=None, cleanup_error=None)
    calls, workers, cleanup_reports = [], [], []
    original_rmtree = PROOF.shutil.rmtree

    def run(argv, **kwargs):
        calls.append({"argv": list(argv), **kwargs})
        index = len(calls) - 1
        if index == 0:
            root.mkdir()
        if index == controls.fail_at:
            if controls.replace_state:
                execute = inspect.currentframe().f_back.f_back.f_locals["execute"]
                cell = execute.__closure__[execute.__code__.co_freevars.index("active_wait")]
                cell.cell_contents = controls.state_override
            raise controls.error
        if index == controls.nonzero_at:
            return SimpleNamespace(returncode=7, stdout="out" * 1000, stderr="err" * 1000)
        if "--worker" in argv:
            phase = argv[argv.index("--worker") + 1]
            scenario = argv[argv.index("--scenario") + 1]
            row = {"phase": phase, "scenario": scenario, "parent_sha256": "b" * 64, "child_sha256": ["c" * 64]}
            workers.append(row)
            return SimpleNamespace(returncode=0, stdout=json.dumps(row))
        return SimpleNamespace(returncode=0, stdout="")

    def cleanup(path):
        assert path == root
        cleanup_reports.append(json.loads(arguments.output.read_text(encoding="utf8")))
        if controls.cleanup_error:
            raise controls.cleanup_error
        original_rmtree(path)

    monkeypatch.setattr(PROOF, "os", SimpleNamespace(name="nt", environ=inherited, devnull=os.devnull))
    monkeypatch.setattr(PROOF, "sys", SimpleNamespace(version_info=(3, 10), executable="owned-python"))
    monkeypatch.setattr(PROOF, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    monkeypatch.setattr(PROOF, "wheel_inventory", lambda *args: (wheel, modules))
    monkeypatch.setattr(PROOF.subprocess, "run", run)
    monkeypatch.setattr(PROOF.shutil, "rmtree", cleanup)
    return SimpleNamespace(arguments=arguments, controls=controls, calls=calls, workers=workers,
                           root=root, wheel=wheel, modules=modules, inherited=inherited, cleanup=cleanup_reports)


def expected_installed_report(run, *, passed=False):
    return {"wheel_sha256": hashlib.sha256(run.wheel.read_bytes()).hexdigest(),
            "checkout_module_sha256": run.modules, "workers": run.workers,
            "offline_require_hashes": True, "native_guards_mocked": False, "passed": passed}


def installed_report_bytes(report):
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").replace("\n", os.linesep).encode()


@pytest.mark.parametrize(("wait", "phase", "seconds"), [
    (0, "private_directory", 15), (1, "venv", 120), (2, "offline_install", 120),
    (3, "dependency_check", 120), (4, "worker", 120), (7, "worker", 120),
])
def test_installed_timeout_uses_only_fixed_operation_and_preserves_partial_workers(installed_run, wait, phase, seconds):
    run = installed_run
    error = subprocess.TimeoutExpired("sensitive-command-canary", 987654,
                                      output=b"sensitive-output-canary", stderr=b"sensitive-stderr-canary")
    error.timeout_phase = "sensitive-attribute-canary"
    error.timeout_seconds = "sensitive-attribute-canary"
    run.controls.fail_at, run.controls.error = wait, error
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is error
    expected = {**expected_installed_report(run), "failure_type": "TimeoutExpired",
                "timeout_phase": phase, "timeout_seconds": seconds}
    encoded = run.arguments.output.read_bytes()
    assert encoded == installed_report_bytes(expected)
    assert b"canary" not in encoded and len(run.workers) == max(0, wait - 4)
    assert run.cleanup == [expected] and not run.root.exists()
    assert run.calls[-1]["timeout"] == seconds


class UntrustedTuple(tuple):
    def __len__(self):
        raise AssertionError("untrusted tuple inspected")

    def __getitem__(self, key):
        raise AssertionError("untrusted tuple inspected")


class UntrustedString(str):
    def __eq__(self, other):
        raise AssertionError("untrusted string compared")


class UntrustedInteger(int):
    def __eq__(self, other):
        raise AssertionError("untrusted integer compared")


@pytest.mark.parametrize("state", [None, ["worker", 120], (), ("worker",), ("worker", 120, "extra"),
                                  ("unknown-canary", 120), ("worker", 15), ("worker", True),
                                  UntrustedTuple(("worker", 120)), (UntrustedString("worker"), 120),
                                  ("worker", UntrustedInteger(120))])
def test_installed_timeout_omits_unknown_or_untrusted_operation_state(installed_run, state):
    run = installed_run
    run.controls.fail_at, run.controls.error = 1, subprocess.TimeoutExpired("canary", 987654)
    run.controls.replace_state, run.controls.state_override = True, state
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is run.controls.error
    expected = {**expected_installed_report(run), "failure_type": "TimeoutExpired"}
    assert json.loads(run.arguments.output.read_text(encoding="utf8")) == expected
    assert run.cleanup == [expected] and not run.root.exists()


def test_installed_timeout_outside_wait_has_no_stale_phase(installed_run, monkeypatch):
    run = installed_run
    error = subprocess.TimeoutExpired("canary", 987654)
    original = PROOF.clean_environment
    calls = 0

    def clean():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise error
        return original()

    monkeypatch.setattr(PROOF, "clean_environment", clean)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is error and len(run.calls) == 1
    assert run.cleanup == [{**expected_installed_report(run), "failure_type": "TimeoutExpired"}]


def test_installed_non_windows_directory_has_no_timeout_budget(installed_run, monkeypatch):
    run = installed_run
    PROOF.os.name = "posix"
    error = subprocess.TimeoutExpired("canary", 987654)

    def directory(path):
        path.mkdir()
        raise error

    monkeypatch.setattr(PROOF, "private_directory", directory)
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is error and not run.calls
    assert run.cleanup == [{**expected_installed_report(run), "failure_type": "TimeoutExpired"}]


class UntrustedTimeout(subprocess.TimeoutExpired):
    def __getattribute__(self, name):
        if name in {"cmd", "output", "stderr", "timeout", "timeout_phase", "timeout_seconds"}:
            raise AssertionError("untrusted exception attribute inspected")
        return super().__getattribute__(name)


def test_installed_timeout_subclass_is_not_trusted_for_attribution(installed_run):
    run = installed_run
    run.controls.fail_at, run.controls.error = 1, UntrustedTimeout("canary", 987654)
    with pytest.raises(UntrustedTimeout) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is run.controls.error
    assert run.cleanup == [{**expected_installed_report(run), "failure_type": "UntrustedTimeout"}]


def test_installed_nonzero_child_report_is_unchanged(installed_run):
    run = installed_run
    run.controls.nonzero_at = 2
    with pytest.raises(RuntimeError, match="installed_agent_child_failed"):
        PROOF.run_installed(run.arguments)
    expected = {**expected_installed_report(run), "failure_type": "RuntimeError",
                "failed_command": {"argv": run.calls[-1]["argv"], "returncode": 7,
                                   "stdout": ("out" * 1000)[-2048:], "stderr": ("err" * 1000)[-2048:]}}
    assert run.arguments.output.read_bytes() == installed_report_bytes(expected)
    assert run.cleanup == [expected] and not run.root.exists()


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(23)])
def test_installed_cancellation_preserves_identity_and_writes_before_cleanup(installed_run, error):
    run = installed_run
    run.controls.fail_at, run.controls.error = 4, error
    with pytest.raises(type(error)) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is error
    assert run.cleanup == [expected_installed_report(run)] and not run.root.exists()


def test_installed_cleanup_failure_keeps_existing_exception_replacement(installed_run):
    run = installed_run
    run.controls.fail_at, run.controls.error = 1, subprocess.TimeoutExpired("canary", 987654)
    cleanup_error = RuntimeError("synthetic cleanup failure")
    run.controls.cleanup_error = cleanup_error
    with pytest.raises(RuntimeError) as caught:
        PROOF.run_installed(run.arguments)
    assert caught.value is cleanup_error
    assert run.cleanup == [{**expected_installed_report(run), "failure_type": "TimeoutExpired",
                            "timeout_phase": "venv", "timeout_seconds": 120}]
    assert run.root.exists()


def test_installed_healthy_bytes_and_wait_trace_are_unchanged(installed_run):
    run = installed_run
    PROOF.run_installed(run.arguments)
    expected = expected_installed_report(run, passed=True)
    assert run.arguments.output.read_bytes() == installed_report_bytes(expected)
    assert run.cleanup == [expected] and not run.root.exists()
    assert len(run.calls) == 12 and len(run.workers) == 8
    private, *children = run.calls
    powershell = Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    assert private["argv"][:4] == [str(powershell), "-NoProfile", "-NonInteractive", "-Command"]
    assert hashlib.sha256(private["argv"][4].encode()).hexdigest() == \
        "b81b16a660b1b715ee0eebc4720f87a0d81feb2cdbb06d87a4a6e1dfb4a2067b"
    assert set(private) == {"argv", "env", "capture_output", "timeout", "check", "creationflags"}
    assert private["capture_output"] is True and private["check"] is True and private["timeout"] == 15
    assert private["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    base_env = {key: value for key, value in run.inherited.items()
                if key in {"SystemRoot", "KEEP", "PSMODULEPATH", "PSModulePath"}}
    base_env.update(PIP_CONFIG_FILE=os.devnull, NO_PROXY="127.0.0.1")
    private_env = {key: value for key, value in base_env.items() if key.casefold() != "psmodulepath"}
    private_env.update(PSMODULEPATH=str(powershell.parent / "Modules"),
                       SHADAI_INSTALLED_AGENT_PRIVATE_PATH=str(run.root))
    assert private["env"] == private_env
    environment = run.root / "environment"
    python = str(environment / "Scripts/python.exe")
    wheelhouse = run.arguments.wheelhouse
    expected_argv = [
        ["owned-python", "-I", "-m", "venv", str(environment)],
        [python, "-I", "-m", "pip", "--cache-dir", str(run.root / "pip-cache"), "install", "--no-index",
         "--find-links", str(wheelhouse), "--only-binary=:all:", "--require-hashes", "-r",
         str(wheelhouse / "build.txt"), "-r", str(wheelhouse / "agent.txt"), "-r", str(run.root / "exact-agent.txt")],
        [python, "-I", "-m", "pip", "check"],
    ]
    for phase, scenario in [("shapes", "none"), ("utc", "none"),
                            *((stage, scenario) for scenario in PROOF.SCENARIOS for stage in ("seed", "retry"))]:
        expected_argv.append([python, "-I", str(ROOT / "scripts/test-installed-agent.py"), "--worker", phase,
                              "--environment", str(environment), "--expected", str(run.root / "expected.json"),
                              "--spool", str(run.root / ("spool-" + ("utc" if phase == "utc" else scenario))),
                              "--scenario", scenario])
    base_env.update(TMP=str(run.root), TEMP=str(run.root), TMPDIR=str(run.root))
    assert [child["argv"] for child in children] == expected_argv
    for index, child in enumerate(children):
        assert child == {"argv": expected_argv[index], "cwd": None if index < 3 else environment,
                         "env": base_env, "capture_output": True, "text": True, "timeout": 120}
