"""Isolate bootstrap secret writer bytes from the native Windows ACL preflight."""

import base64
import importlib.util
import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bootstrap_writer", ROOT / "scripts/bootstrap.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


def test_bootstrap_writer_uses_lf_and_preserves_existing_bytes(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source"
    for relative in ("config/shadai.yaml.example", "config/sources.yaml.example", ".env.example"):
        template = source / relative
        template.parent.mkdir(parents=True, exist_ok=True)
        template.write_bytes(b"SYNTHETIC_BOOTSTRAP_TEST=1\n")
    monkeypatch.setattr(BOOTSTRAP, "__file__", str(source / "scripts/bootstrap.py"))
    # Simulate only preflight here; the native ACL guard has its own security suite.
    preflights = []

    def simulated_preflight(command, **kwargs):
        preflights.append(command)
        assert kwargs["check"] is True
        assert Path(command[command.index("-File") + 1]).name == "Protect-BootstrapWindows.ps1"

    monkeypatch.setattr(BOOTSTRAP.subprocess, "run", simulated_preflight)
    monkeypatch.setattr(BOOTSTRAP.secrets, "token_hex", lambda size: "a" * (2 * size))
    monkeypatch.setattr(BOOTSTRAP.secrets, "token_bytes", lambda size: b"\x01" * size)
    original_open = Path.open
    newlines = []

    def observe_open(path, *args, **kwargs):
        if args and args[0] == "x" and path.parent.name == "secrets":
            newlines.append(kwargs.get("newline"))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", observe_open)
    destination = tmp_path / "deployment"
    BOOTSTRAP.bootstrap(destination, dry_run=True)
    assert not destination.exists() and not preflights
    try:
        BOOTSTRAP.bootstrap(destination)
        expected = dict.fromkeys(
            ("pg_password.txt", "redis_password.txt", "ch_password.txt", "agent_api_key.txt"),
            b"a" * 64 + b"\n",
        )
        expected["jwt_secret.txt"] = b"a" * 128 + b"\n"
        expected["encryption_key.txt"] = base64.urlsafe_b64encode(b"\x01" * 32) + b"\n"
        secret_directory = destination / "secrets"
        assert {path.name: path.read_bytes() for path in secret_directory.iterdir()} == expected
        assert newlines == ["\n"] * 6
        if os.name != "nt":
            assert stat.S_IMODE(secret_directory.stat().st_mode) == 0o700
            assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in secret_directory.iterdir())

        historical = secret_directory / "pg_password.txt"
        historical.chmod(0o600)
        historical.write_bytes(b"synthetic-existing-secret\r\n")
        historical.chmod(0o444)
        before = {path.relative_to(destination): path.read_bytes() for path in destination.rglob("*") if path.is_file()}

        def reject_regeneration(*args):
            raise AssertionError("Existing secrets must not be regenerated")

        monkeypatch.setattr(BOOTSTRAP.secrets, "token_hex", reject_regeneration)
        monkeypatch.setattr(BOOTSTRAP.secrets, "token_bytes", reject_regeneration)
        BOOTSTRAP.bootstrap(destination)
        after = {path.relative_to(destination): path.read_bytes() for path in destination.rglob("*") if path.is_file()}
        assert before == after and historical.read_bytes() == b"synthetic-existing-secret\r\n"
        assert newlines == ["\n"] * 6
        assert len(preflights) == (2 if os.name == "nt" else 0)
        output = capsys.readouterr().out
        assert all(value.rstrip(b"\n").decode() not in output for value in expected.values())
        assert "synthetic-existing-secret" not in output
    finally:
        for path in (destination / "secrets").glob("*.txt"):
            path.chmod(0o600)
