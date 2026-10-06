"""Windows child module resolution stays trusted without changing parent state."""

import importlib.util
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from shadai_agent import delivery_spool as vendored

from shadai.utils import delivery_spool

COPIES = (delivery_spool, vendored)
HELPERS = ("_windows_private", "_private_ancestors")
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("installed_agent_proof", ROOT / "scripts/test-installed-agent.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)


@pytest.mark.parametrize("module", COPIES, ids=("backend", "agent"))
@pytest.mark.parametrize("helper", HELPERS)
@pytest.mark.parametrize("inherited", [
    {"PSMODULEPATH": "synthetic-untrusted"},
    {"PSModulePath": "synthetic-untrusted"},
    {"PSMODULEPATH": "synthetic-upper", "PSModulePath": "synthetic-mixed", "psmodulepath": "synthetic-lower"},
    {},
], ids=("uppercase", "mixedcase", "duplicates", "absent"))
def test_helpers_use_one_trusted_module_path_and_preserve_parent(module, helper, inherited, monkeypatch, tmp_path):
    parent = {"SystemRoot": r"C:\Windows", "PATH": "synthetic-path", "OTHER": "unchanged", **inherited}
    original = dict(parent)
    # Windows normalizes os.environ keys, but its copied ordinary dict can hold
    # multiple variants. Use that exact mapping failure mode on every platform.
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt", environ=parent))
    captured = []
    def run(command, **options):
        captured.append((command, options))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess, "run", run)
    target = tmp_path / "private"
    if helper == "_windows_private":
        assert module._windows_private(target, create=True)
    else:
        module._private_ancestors(target)
    [(command, options)] = captured
    child = options["env"]
    executable = Path(parent["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    assert command[:4] == [str(executable), "-NoProfile", "-NonInteractive", "-Command"]
    assert [key for key in child if key.casefold() == "psmodulepath"] == ["PSMODULEPATH"]
    assert child["PSMODULEPATH"] == str(executable.parent / "Modules")
    assert all(child[key] == value for key, value in original.items() if key.casefold() != "psmodulepath")
    assert parent == original and child is not parent
    assert options["stdout"] == options["stderr"] == subprocess.DEVNULL
    assert options["timeout"] == 15 and options["check"] is False
    assert options["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if helper == "_windows_private":
        assert child["SHADAI_SPOOL_CREATE_PRIVATE"] == "1" and child["SHADAI_SPOOL_PRIVATE_PATH"] == str(target)
    else:
        assert child["SHADAI_SPOOL_PARENT_PATH"] == str(target.parent)


@pytest.mark.parametrize("module", COPIES, ids=("backend", "agent"))
@pytest.mark.parametrize("helper", HELPERS)
@pytest.mark.parametrize("failure", ("denied", "oserror", "timeout"))
def test_helpers_still_fail_closed(module, helper, failure, monkeypatch, tmp_path):
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt", environ={"PSMODULEPATH": "untrusted"}))
    def run(command, **options):
        if failure == "oserror":
            raise OSError("synthetic")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 15)
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(module.subprocess, "run", run)
    if helper == "_windows_private":
        assert module._windows_private(tmp_path) is False
    else:
        with pytest.raises(module.SpoolError, match="^spool_unsafe_parent$"):
            module._private_ancestors(tmp_path)


def test_vendor_remains_verbatim():
    assert Path(delivery_spool.__file__).read_bytes() == Path(vendored.__file__).read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="Actual native Windows ACL guard")
@pytest.mark.parametrize("module", COPIES, ids=("backend", "agent"))
def test_actual_windows_guards_ignore_poisoned_modules(module, monkeypatch):
    # Python 3.13's mkdir(0o700) adds OWNER RIGHTS outside the guard's allowlist.
    # Provision independently of pytest's temporary-directory ACL recipe.
    parent = Path(os.environ["USERPROFILE"]).resolve(strict=True)
    root = parent / ("installed-agent-" + uuid4().hex)
    PROOF.verify_qa_root(root, parent)
    if root.exists() or root.is_symlink():
        raise ValueError("qa_directory_must_be_new")
    monkeypatch.setenv("PSMODULEPATH", str(root / "untrusted-modules"))
    original = dict(os.environ)
    target = root / module.__name__.replace(".", "-")
    root_created = False
    try:
        PROOF.private_directory(root)
        root_created = True
        assert module._windows_private(target, create=True), "Native private leaf ACL provisioning failed"
        assert module._windows_private(target), "Native private leaf ACL verification failed"
        # An unsafe pre-existing parent still fails the native ancestor guard.
        try:
            module._private_ancestors(target)
        except module.SpoolError as exc:
            pytest.fail(f"Native parent prerequisite failed: {exc}")
        assert dict(os.environ) == original
    finally:
        if root_created:
            PROOF.verify_qa_root(root, parent)
            if target.exists():
                target.rmdir()
            if root.exists():
                root.rmdir()
    assert not root.exists()


def test_native_fixture_collision_preserves_existing_directory(tmp_path, monkeypatch):
    root = tmp_path / ("installed-agent-" + "a" * 32)
    root.mkdir()
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(f"{__name__}.uuid4", lambda: SimpleNamespace(hex="a" * 32))
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        pytest.fail("A colliding root must not be created, guarded or removed")

    monkeypatch.setattr(PROOF, "private_directory", forbidden)
    monkeypatch.setattr(delivery_spool, "_windows_private", forbidden)
    monkeypatch.setattr(delivery_spool, "_private_ancestors", forbidden)
    monkeypatch.setattr(Path, "rmdir", forbidden)
    with pytest.raises(ValueError, match="^qa_directory_must_be_new$"):
        test_actual_windows_guards_ignore_poisoned_modules(delivery_spool, monkeypatch)
    assert calls == []
    assert root.is_dir() and list(root.iterdir()) == []


def test_native_fixture_creator_refusal_preserves_concurrent_directory(tmp_path, monkeypatch):
    root = tmp_path / ("installed-agent-" + "b" * 32)
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(f"{__name__}.uuid4", lambda: SimpleNamespace(hex="b" * 32))
    calls = []

    def refuse(path):
        assert path == root and not root.exists()
        root.mkdir()  # Simulate a competing creator after the absence precheck.
        calls.append("creator")
        raise ValueError("qa_directory_must_be_new")

    def forbidden(*args, **kwargs):
        calls.append("guard_or_cleanup")
        pytest.fail("A refused creator must not guard or remove the competing directory")

    monkeypatch.setattr(PROOF, "private_directory", refuse)
    monkeypatch.setattr(delivery_spool, "_windows_private", forbidden)
    monkeypatch.setattr(delivery_spool, "_private_ancestors", forbidden)
    monkeypatch.setattr(Path, "rmdir", forbidden)
    with pytest.raises(ValueError, match="^qa_directory_must_be_new$"):
        test_actual_windows_guards_ignore_poisoned_modules(delivery_spool, monkeypatch)
    assert calls == ["creator"]
    assert root.is_dir() and list(root.iterdir()) == []
