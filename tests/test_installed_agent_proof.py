"""Fail-closed guards for the standalone installed-wheel acceptance helper."""

import hashlib
import importlib.util
import json
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
