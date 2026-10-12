"""Hardening tests for the browser extension collector (EXT-01)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from shadai_agent.collectors import browser_ext


def _install(root: Path, browser_sub: str, profile: str, ext_id: str, version: str, manifest: object,
             *, serial: int = 0, encoding: str = "utf-8") -> Path:
    """Write a manifest under <root>/<browser_sub>/<profile>/Extensions/<id>/<version>_<serial>/."""
    version_dir = root / browser_sub / profile / "Extensions" / ext_id / f"{version}_{serial}"
    version_dir.mkdir(parents=True, exist_ok=True)
    path = version_dir / "manifest.json"
    text = manifest if isinstance(manifest, str) else json.dumps(manifest)
    path.write_text(text, encoding=encoding)
    return path


@pytest.fixture
def chrome_root(tmp_path, monkeypatch):
    """Point the Linux Chrome root at a temporary tree."""
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        browser_ext,
        "BROWSER_ROOTS",
        {"Linux": [(str(tmp_path / "google-chrome"), "chrome")]},
    )
    return tmp_path / "google-chrome"


def test_collects_a_well_formed_extension(chrome_root):
    _install(chrome_root.parent, "google-chrome", "Default", "a" * 32, "1.0.0",
             {"name": "Tidy", "version": "1.0.0", "permissions": ["tabs"]})
    [record] = browser_ext.collect_extensions()
    assert record["id"] == "a" * 32
    assert record["name"] == "Tidy"
    assert record["browser"] == "chrome"
    assert record["profile"] == "Default"


def test_numeric_version_ordering_picks_the_highest(chrome_root):
    ext = "b" * 32
    _install(chrome_root.parent, "google-chrome", "Default", ext, "9.0.0", {"name": "old", "version": "9.0.0"})
    _install(chrome_root.parent, "google-chrome", "Default", ext, "10.0.0", {"name": "new", "version": "10.0.0"})
    _install(chrome_root.parent, "google-chrome", "Default", ext, "24.9.3", {"name": "mid", "version": "24.9.3"})
    _install(chrome_root.parent, "google-chrome", "Default", ext, "24.10.0", {"name": "newest", "version": "24.10.0"})
    [record] = browser_ext.collect_extensions()
    assert record["name"] == "newest"


def test_scratch_version_directories_are_ignored(chrome_root):
    ext = "c" * 32
    _install(chrome_root.parent, "google-chrome", "Default", ext, "1.0.0", {"name": "real", "version": "1.0.0"})
    for scratch in ("Temp", "CRX_INSTALL"):
        d = chrome_root / "Default" / "Extensions" / ext / scratch
        d.mkdir(parents=True)
        (d / "manifest.json").write_text('{"name": "scratch"}')
    [record] = browser_ext.collect_extensions()
    assert record["name"] == "real"


@pytest.mark.parametrize("payload", [
    "{ this is : not json",          # truncated / invalid JSON
    json.dumps(["not", "an", "object"]),  # JSON but not an object
    "\x81\x8d\x8f bad cp1252 bytes",  # bytes that break a cp1252 decode
])
def test_unusable_manifests_are_skipped_not_raised(chrome_root, payload):
    _install(chrome_root.parent, "google-chrome", "Default", "d" * 32, "1.0.0", payload)
    # Must not raise and must not yield a broken record.
    assert browser_ext.collect_extensions() == []


def test_bom_manifest_name_is_still_read(chrome_root):
    _install(chrome_root.parent, "google-chrome", "Default", "e" * 32, "1.0.0",
             "﻿" + json.dumps({"name": "WithBom", "version": "1.0.0"}))
    [record] = browser_ext.collect_extensions()
    assert record["name"] == "WithBom"


def test_oversized_manifest_is_skipped(chrome_root):
    big = {"name": "huge", "version": "1.0.0", "pad": "x" * (browser_ext.MANIFEST_MAX_BYTES + 10)}
    _install(chrome_root.parent, "google-chrome", "Default", "f" * 32, "1.0.0", big)
    assert browser_ext.collect_extensions() == []


def test_one_bad_extension_does_not_hide_a_good_one(chrome_root):
    _install(chrome_root.parent, "google-chrome", "Default", "0" * 32, "1.0.0", "{ broken")
    _install(chrome_root.parent, "google-chrome", "Default", "1" * 32, "1.0.0",
             {"name": "survivor", "version": "1.0.0"})
    names = {r["name"] for r in browser_ext.collect_extensions()}
    assert "survivor" in names


def test_same_id_in_two_profiles_is_reported_per_profile(chrome_root):
    ext = "7" * 32
    _install(chrome_root.parent, "google-chrome", "Default", ext, "1.0.0", {"name": "dup", "version": "1.0.0"})
    _install(chrome_root.parent, "google-chrome", "Profile 1", ext, "1.0.0", {"name": "dup", "version": "1.0.0"})
    profiles = {r["profile"] for r in browser_ext.collect_extensions()}
    assert profiles == {"Default", "Profile 1"}


def test_missing_root_is_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser_ext, "BROWSER_ROOTS",
                        {"Linux": [(str(tmp_path / "absent"), "chrome")]})
    assert browser_ext.collect_extensions() == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_loop_in_extensions_dir_does_not_hang_or_raise(chrome_root):
    ext_dir = chrome_root / "Default" / "Extensions"
    ext_dir.mkdir(parents=True)
    try:
        os.symlink(ext_dir, ext_dir / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted")
    _install(chrome_root.parent, "google-chrome", "Default", "9" * 32, "1.0.0", {"name": "ok", "version": "1.0.0"})
    names = {r["name"] for r in browser_ext.collect_extensions()}
    assert "ok" in names


def test_version_sort_key_orders_numerically():
    key = browser_ext._version_sort_key
    assert key("10.0.0_0") > key("9.0.0_0")
    assert key("24.10.0_0") > key("24.9.3_0")
    assert key("1.0.0_2") > key("1.0.0_1")


def test_failing_extension_collector_does_not_drop_the_snapshot(monkeypatch):
    """EXT-01: one collector raising must empty its section only, never the whole cycle."""
    from types import SimpleNamespace

    from shadai_agent import main as agent

    payloads = []
    config = SimpleNamespace(hostname="ws-042", spool_dir="unused", spool_max_bytes=1000,
                             spool_max_batches=10, spool_ttl_seconds=60, poll_interval_seconds=0,
                             collect_processes=True, collect_containers=False,
                             collect_local_ai=False, collect_extensions=True)
    spool = SimpleNamespace(enqueue=lambda payload, **kwargs: payloads.append(json.loads(payload)),
                            stats=lambda: {}, close=lambda: None)

    def finish_poll(*args):
        agent._running = False
        return None

    def boom():
        raise UnicodeDecodeError("cp1252", b"\x81", 0, 1, "unreadable manifest")

    monkeypatch.setattr(agent, "_running", True)
    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent, "load_agent_config", lambda: config)
    monkeypatch.setattr(agent, "DurableSpool", lambda *args, **kwargs: spool)
    monkeypatch.setattr(agent, "discover_binding", finish_poll)
    monkeypatch.setattr(agent, "collect_processes",
                        lambda: [{"name": "OUTLOOK.EXE", "parent": "explorer.exe", "username": "u"}])
    monkeypatch.setattr(agent, "collect_extensions", boom)
    agent.main()
    [batch] = payloads
    assert batch["processes"] == [{"name": "OUTLOOK.EXE", "parent": "explorer.exe", "username": "u"}]
    assert batch["extensions"] == []
    assert batch["agent_version"] == agent.__version__
    assert datetime_is_aware(batch["timestamp"])


def datetime_is_aware(stamp: str) -> bool:
    from datetime import datetime
    return datetime.fromisoformat(stamp).tzinfo is not None
