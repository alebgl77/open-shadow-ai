"""Tests for the browser extension collector (EXT-01 hardening, EXT-02 enumeration)."""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

import pytest
from shadai_agent.collectors import browser_ext

CHROME = ".config/google-chrome"


def _install(home: Path, root: str, profile: str, ext_id: str, version: str, manifest: object,
             *, serial: int = 0, encoding: str = "utf-8") -> Path:
    """Write a manifest under <home>/<root>/<profile>/Extensions/<id>/<version>_<serial>/."""
    base = home / root
    base.mkdir(parents=True, exist_ok=True)
    (base / "Local State").write_text("{}")
    version_dir = base / profile / "Extensions" / ext_id / f"{version}_{serial}"
    version_dir.mkdir(parents=True, exist_ok=True)
    path = version_dir / "manifest.json"
    text = manifest if isinstance(manifest, str) else json.dumps(manifest)
    path.write_text(text, encoding=encoding)
    return path


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")


@pytest.fixture
def home(tmp_path, linux):
    """One Linux user's home directory, inventoried on its own."""
    path = tmp_path / "home" / "alice"
    path.mkdir(parents=True)
    return path


def collect(*homes: Path) -> list[dict]:
    return browser_ext.collect_extensions(homes=list(homes))


# --- EXT-01: manifest hardening -------------------------------------------------


def test_collects_a_well_formed_extension(home):
    _install(home, CHROME, "Default", "a" * 32, "1.0.0", {"name": "Tidy", "version": "1.0.0", "permissions": ["tabs"]})
    [record] = collect(home)
    assert record["id"] == "a" * 32
    assert record["name"] == "Tidy"
    assert record["browser"] == "chrome"
    assert record["profile"] == "Default"
    assert record["user"] == "alice"


def test_numeric_version_ordering_picks_the_highest(home):
    ext = "b" * 32
    _install(home, CHROME, "Default", ext, "9.0.0", {"name": "old", "version": "9.0.0"})
    _install(home, CHROME, "Default", ext, "10.0.0", {"name": "new", "version": "10.0.0"})
    _install(home, CHROME, "Default", ext, "24.9.3", {"name": "mid", "version": "24.9.3"})
    _install(home, CHROME, "Default", ext, "24.10.0", {"name": "newest", "version": "24.10.0"})
    [record] = collect(home)
    assert record["name"] == "newest"


def test_scratch_version_directories_are_ignored(home):
    ext = "c" * 32
    _install(home, CHROME, "Default", ext, "1.0.0", {"name": "real", "version": "1.0.0"})
    for scratch in ("Temp", "CRX_INSTALL"):
        d = home / CHROME / "Default" / "Extensions" / ext / scratch
        d.mkdir(parents=True)
        (d / "manifest.json").write_text('{"name": "scratch"}')
    [record] = collect(home)
    assert record["name"] == "real"


@pytest.mark.parametrize("payload", [
    "{ this is : not json",          # truncated / invalid JSON
    json.dumps(["not", "an", "object"]),  # JSON but not an object
    "\x81\x8d\x8f bad cp1252 bytes",  # bytes that break a cp1252 decode
])
def test_unusable_manifests_are_skipped_not_raised(home, payload):
    _install(home, CHROME, "Default", "d" * 32, "1.0.0", payload)
    # Must not raise and must not yield a broken record.
    assert collect(home) == []


def test_bom_manifest_name_is_still_read(home):
    _install(home, CHROME, "Default", "e" * 32, "1.0.0", "\ufeff" + json.dumps({"name": "WithBom", "version": "1.0.0"}))
    [record] = collect(home)
    assert record["name"] == "WithBom"


def test_oversized_manifest_is_skipped(home):
    big = {"name": "huge", "version": "1.0.0", "pad": "x" * (browser_ext.MANIFEST_MAX_BYTES + 10)}
    _install(home, CHROME, "Default", "f" * 32, "1.0.0", big)
    assert collect(home) == []


def test_one_bad_extension_does_not_hide_a_good_one(home):
    _install(home, CHROME, "Default", "0" * 32, "1.0.0", "{ broken")
    _install(home, CHROME, "Default", "1" * 32, "1.0.0", {"name": "survivor", "version": "1.0.0"})
    names = {r["name"] for r in collect(home)}
    assert "survivor" in names


def test_same_id_in_two_profiles_is_reported_per_profile(home):
    ext = "7" * 32
    _install(home, CHROME, "Default", ext, "1.0.0", {"name": "dup", "version": "1.0.0"})
    _install(home, CHROME, "Profile 1", ext, "1.0.0", {"name": "dup", "version": "1.0.0"})
    profiles = {r["profile"] for r in collect(home)}
    assert profiles == {"Default", "Profile 1"}


def test_missing_home_and_missing_root_are_silent(tmp_path, linux):
    assert collect(tmp_path / "absent") == []
    (tmp_path / "empty").mkdir()
    assert collect(tmp_path / "empty") == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_symlink_loop_in_extensions_dir_does_not_hang_or_raise(home):
    ext_dir = home / CHROME / "Default" / "Extensions"
    ext_dir.mkdir(parents=True)
    try:
        os.symlink(ext_dir, ext_dir / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted")
    _install(home, CHROME, "Default", "9" * 32, "1.0.0", {"name": "ok", "version": "1.0.0"})
    names = {r["name"] for r in collect(home)}
    assert "ok" in names


def test_version_sort_key_orders_numerically():
    key = browser_ext._version_sort_key
    assert key("10.0.0_0") > key("9.0.0_0")
    assert key("24.10.0_0") > key("24.9.3_0")
    assert key("1.0.0_2") > key("1.0.0_1")


# --- EXT-05: localized names ------------------------------------------------------


def _locale(path: Path, locale: str, messages: dict) -> None:
    """Write a _locales/<locale>/messages.json next to an installed manifest."""
    table = path.parent / "_locales" / locale
    table.mkdir(parents=True)
    (table / "messages.json").write_text(json.dumps(messages), encoding="utf-8")


def test_msg_placeholder_name_is_resolved_from_the_default_locale(home):
    path = _install(home, CHROME, "Default", "l" * 32, "1.0.0",
                    {"name": "__MSG_appName__", "version": "1.0.0", "default_locale": "fr"})
    _locale(path, "fr", {"appName": {"message": "Assistant IA", "description": "x"}})
    _locale(path, "en", {"appName": {"message": "AI Assistant"}})
    [record] = collect(home)
    assert record["name"] == "Assistant IA"


def test_msg_lookup_is_case_insensitive_and_falls_back_to_english(home):
    path = _install(home, CHROME, "Default", "m" * 32, "1.0.0",
                    {"name": "__MSG_AppName__", "version": "1.0.0", "default_locale": "de"})
    _locale(path, "en_US", {"appname": {"message": "Grammar Helper"}})
    [record] = collect(home)
    assert record["name"] == "Grammar Helper"


def test_msg_placeholder_inside_a_longer_name_is_substituted(home):
    path = _install(home, CHROME, "Default", "n" * 32, "1.0.0",
                    {"name": "__MSG_brand__ for Gmail", "version": "1.0.0", "default_locale": "en"})
    _locale(path, "en", {"brand": {"message": "Writer"}})
    [record] = collect(home)
    assert record["name"] == "Writer for Gmail"


def test_unresolvable_placeholder_is_kept_as_the_raw_key(home):
    _install(home, CHROME, "Default", "o" * 32, "1.0.0",
             {"name": "__MSG_missing__", "version": "1.0.0", "default_locale": "en"})
    [record] = collect(home)
    assert record["name"] == "__MSG_missing__"


def test_locale_from_manifest_cannot_escape_the_extension_directory(home):
    secret = home / "secret"
    secret.mkdir()
    (secret / "messages.json").write_text(json.dumps({"appname": {"message": "leaked"}}))
    _install(home, CHROME, "Default", "q" * 32, "1.0.0",
             {"name": "__MSG_appName__", "version": "1.0.0", "default_locale": "../../../../secret"})
    [record] = collect(home)
    assert record["name"] == "__MSG_appName__"


def test_broken_messages_table_does_not_hide_the_extension(home):
    path = _install(home, CHROME, "Default", "r" * 32, "1.0.0",
                    {"name": "__MSG_appName__", "version": "1.0.0", "default_locale": "en"})
    _locale(path, "en", {"appName": "not an object"})
    (path.parent / "_locales" / "en" / "messages.json").write_text("{ broken")
    [record] = collect(home)
    assert record["id"] == "r" * 32


# --- EXT-02: every user, every Chromium-family browser ---------------------------


def test_every_local_user_is_inventoried(tmp_path, linux):
    alice, bob = tmp_path / "home" / "alice", tmp_path / "home" / "bob"
    _install(alice, CHROME, "Default", "a" * 32, "1.0.0", {"name": "Alice's", "version": "1.0.0"})
    _install(bob, ".config/BraveSoftware/Brave-Browser", "Default", "b" * 32, "1.0.0",
             {"name": "Bob's", "version": "1"})
    records = {(r["user"], r["browser"], r["name"]) for r in collect(alice, bob)}
    assert records == {("alice", "chrome", "Alice's"), ("bob", "brave", "Bob's")}


def test_each_root_carries_its_own_browser_label(home):
    roots = {
        CHROME: "chrome",
        ".config/google-chrome-beta": "chrome",
        ".config/chromium": "chromium",
        "snap/chromium/common/chromium": "chromium",
        ".config/microsoft-edge": "edge",
        ".var/app/com.microsoft.Edge/config/microsoft-edge": "edge",
        ".config/BraveSoftware/Brave-Browser": "brave",
        ".config/vivaldi": "vivaldi",
        ".config/opera": "opera",
    }
    for index, root in enumerate(roots):
        _install(home, root, "Default", f"{index:032d}", "1.0.0", {"name": root, "version": "1.0.0"})
    assert {r["name"]: r["browser"] for r in collect(home)} == roots


@pytest.mark.parametrize("system, root, browser", [
    ("Windows", "AppData/Local/Google/Chrome SxS/User Data", "chrome"),
    ("Windows", "AppData/Local/Microsoft/Edge Dev/User Data", "edge"),
    ("Windows", "AppData/Local/BraveSoftware/Brave-Browser/User Data", "brave"),
    ("Windows", "AppData/Local/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data", "arc"),
    ("Darwin", "Library/Application Support/Google/Chrome Canary", "chrome"),
    ("Darwin", "Library/Application Support/Microsoft Edge Beta", "edge"),
    ("Darwin", "Library/Application Support/Arc/User Data", "arc"),
])
def test_known_roots_on_other_platforms(tmp_path, monkeypatch, system, root, browser):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: system)
    home = tmp_path / "home"
    _install(home, root, "Default", "a" * 32, "1.0.0", {"name": "x", "version": "1.0.0"})
    [record] = collect(home)
    assert record["browser"] == browser


def test_single_profile_layout_is_read_as_default_profile(tmp_path, monkeypatch):
    """Opera keeps Extensions directly under its root, with no profile directory."""
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Windows")
    home = tmp_path / "home"
    base = home / "AppData/Roaming/Opera Software/Opera Stable"
    version_dir = base / "Extensions" / ("o" * 32) / "2.0.0_0"
    version_dir.mkdir(parents=True)
    (version_dir / "manifest.json").write_text(json.dumps({"name": "OperaExt", "version": "2.0.0"}))
    [record] = collect(home)
    assert (record["browser"], record["profile"], record["name"]) == ("opera", "Default", "OperaExt")


def test_unlisted_chromium_browser_is_discovered_from_its_local_state(home):
    _install(home, ".config/Perplexity/Comet", "Default", "p" * 32, "1.0.0", {"name": "InComet", "version": "1"})
    [record] = collect(home)
    assert (record["browser"], record["name"]) == ("perplexity-comet", "InComet")


def test_electron_apps_with_a_local_state_but_no_extensions_are_not_browsers(home):
    code = home / ".config" / "Code"
    (code / "User").mkdir(parents=True)
    (code / "Local State").write_text("{}")
    assert collect(home) == []


def test_discovery_never_reads_a_known_root_twice(home):
    _install(home, CHROME, "Default", "a" * 32, "1.0.0", {"name": "once", "version": "1.0.0"})
    assert [r["name"] for r in collect(home)] == ["once"]


def test_discovery_is_bounded_in_depth(home):
    deep = ".config/a/b/c/d/Browser"
    _install(home, deep, "Default", "z" * 32, "1.0.0", {"name": "TooDeep", "version": "1"})
    assert collect(home) == []


def test_user_homes_are_deduplicated_and_must_exist(tmp_path, monkeypatch, linux):
    alice = tmp_path / "alice"
    alice.mkdir()
    link = tmp_path / "alias"
    try:
        os.symlink(alice, link, target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlink creation not permitted")
    monkeypatch.setattr(browser_ext, "_posix_homes", lambda system: [alice, link, tmp_path / "ghost", alice])
    monkeypatch.setattr(browser_ext.Path, "home", classmethod(lambda cls: alice))
    assert browser_ext.iter_user_homes() == [alice]


def test_posix_homes_skip_system_and_nologin_accounts(tmp_path, monkeypatch, linux):
    users = tmp_path / "home"
    (users / "carol").mkdir(parents=True)
    (users / "lost+found").mkdir()
    entries = [
        types.SimpleNamespace(pw_name="root", pw_uid=0, pw_dir="/root", pw_shell="/bin/bash"),
        types.SimpleNamespace(pw_name="daemon", pw_uid=1, pw_dir="/usr/sbin", pw_shell="/usr/sbin/nologin"),
        types.SimpleNamespace(pw_name="svc", pw_uid=1500, pw_dir="/var/lib/svc", pw_shell="/bin/false"),
        types.SimpleNamespace(pw_name="alice", pw_uid=1000, pw_dir="/home/alice", pw_shell="/bin/zsh"),
        types.SimpleNamespace(pw_name="nobody", pw_uid=65534, pw_dir="/nonexistent", pw_shell="/bin/sh"),
    ]
    monkeypatch.setitem(sys.modules, "pwd", types.SimpleNamespace(getpwall=lambda: entries))
    monkeypatch.setitem(browser_ext._POSIX_USERS_DIRS, "Linux", str(users))
    assert browser_ext._posix_homes("Linux") == [Path("/home/alice"), users / "carol"]


def test_windows_profile_list_keeps_only_user_account_sids(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Windows")
    monkeypatch.setenv("SystemDrive", str(tmp_path))
    profiles = {
        "S-1-5-18": r"%systemroot%\system32\config\systemprofile",
        "S-1-5-19": r"%systemroot%\ServiceProfiles\LocalService",
        "S-1-5-21-1-2-3-1001": str(tmp_path / "Users" / "alice"),
        "S-1-12-1-4-5-6-7": str(tmp_path / "Users" / "bob.entra"),
        "S-1-5-80-1-2-3": r"C:\WINDOWS\ServiceProfiles\SomeService",
    }
    monkeypatch.setitem(sys.modules, "winreg", _fake_winreg(profiles))
    assert browser_ext._windows_profile_homes() == [tmp_path / "Users" / "alice", tmp_path / "Users" / "bob.entra"]


def test_windows_falls_back_to_the_users_directory_without_the_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemDrive", str(tmp_path))
    for name in ("alice", "Public", "Default", "Default User", "All Users"):
        (tmp_path / "Users" / name).mkdir(parents=True)
    monkeypatch.setitem(sys.modules, "winreg", None)  # import raises ImportError
    assert browser_ext._windows_profile_homes() == [tmp_path / "Users" / "alice"]


def _fake_winreg(profiles: dict[str, str]):
    """The subset of winreg the collector touches, over an in-memory ProfileList."""
    import contextlib

    sids = list(profiles)

    class Key:
        def __init__(self, sid=None):
            self.sid = sid

    def open_key(parent, sub_key):
        if parent == "HKLM":
            return contextlib.nullcontext(Key())
        if sub_key in profiles:
            return contextlib.nullcontext(Key(sub_key))
        raise OSError("no such key")

    def enum_key(key, index):
        if index >= len(sids):
            raise OSError("no more data")
        return sids[index]

    def query_value_ex(key, name):
        assert name == "ProfileImagePath"
        return profiles[key.sid], 2  # REG_EXPAND_SZ

    return types.SimpleNamespace(HKEY_LOCAL_MACHINE="HKLM", OpenKey=open_key, EnumKey=enum_key,
                                 QueryValueEx=query_value_ex)


# --- Agent main loop ------------------------------------------------------------


def _run_agent_once(monkeypatch, *, extensions):
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

    monkeypatch.setattr(agent, "_running", True)
    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent, "load_agent_config", lambda: config)
    monkeypatch.setattr(agent, "DurableSpool", lambda *args, **kwargs: spool)
    monkeypatch.setattr(agent, "discover_binding", finish_poll)
    monkeypatch.setattr(agent, "collect_processes",
                        lambda: [{"name": "OUTLOOK.EXE", "parent": "explorer.exe", "username": "u"}])
    monkeypatch.setattr(agent, "collect_extensions", extensions)
    agent.main()
    [batch] = payloads
    return agent, batch


def test_failing_extension_collector_does_not_drop_the_snapshot(monkeypatch):
    """EXT-01: one collector raising must empty its section only, never the whole cycle."""
    from datetime import datetime

    def boom():
        raise UnicodeDecodeError("cp1252", b"\x81", 0, 1, "unreadable manifest")

    agent, batch = _run_agent_once(monkeypatch, extensions=boom)
    assert batch["processes"] == [{"name": "OUTLOOK.EXE", "parent": "explorer.exe", "username": "u"}]
    assert batch["extensions"] == []
    assert batch["agent_version"] == agent.__version__
    assert datetime.fromisoformat(batch["timestamp"]).tzinfo is not None


def test_same_extension_across_users_and_profiles_is_one_wire_record(monkeypatch):
    """EXT-02: v1 wire carries id/name/browser only, so local duplicates collapse."""
    found = [
        {"id": "a" * 32, "name": "Tidy", "browser": "chrome", "profile": "Default", "user": "alice"},
        {"id": "a" * 32, "name": "Tidy", "browser": "chrome", "profile": "Profile 1", "user": "alice"},
        {"id": "a" * 32, "name": "Tidy", "browser": "chrome", "profile": "Default", "user": "bob"},
        {"id": "a" * 32, "name": "Tidy", "browser": "edge", "profile": "Default", "user": "bob"},
    ]
    _, batch = _run_agent_once(monkeypatch, extensions=lambda: found)
    assert batch["extensions"] == [
        {"id": "a" * 32, "name": "Tidy", "browser": "chrome"},
        {"id": "a" * 32, "name": "Tidy", "browser": "edge"},
    ]
