"""Collector-to-wire identity regressions for physical browser installations."""

import hashlib
import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from shadai_agent import main as agent
from shadai_agent.collectors import browser_ext, safari_ext
from shadai_agent.collectors.profile_identity import browser_profile, qualified_profile
from test_browser_ext import _addon, _firefox, _install, _prefs
from test_safari_ext import _app, _info

from shadai.api.agent import ExtensionRecord


@pytest.mark.parametrize("roots,browser", [
    ([".config/google-chrome", ".config/google-chrome-beta", ".config/google-chrome-unstable"], "chrome"),
    ([".config/chromium", "snap/chromium/common/chromium",
      ".var/app/org.chromium.Chromium/config/chromium"], "chromium"),
    ([".mozilla/firefox", "snap/firefox/common/.mozilla/firefox",
      ".var/app/org.mozilla.firefox/.mozilla/firefox"], "firefox"),
])
def test_physical_roots_survive_real_collection_and_wire_dedup(tmp_path, monkeypatch, roots, browser):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    home = tmp_path / "alice"
    for root in roots:
        if browser == "firefox":
            _firefox(home, root, "Default", [_addon("same@test", "Same")])
        else:
            _install(home, root, "Default", "a" * 32, "1", {"name": "Same", "version": "1"})
    records = agent.unique_records("extensions", [agent.conform(r) for r in browser_ext.collect_extensions([home])])
    assert len(records) == 3
    assert {r["browser"] for r in records} == {browser}
    assert {r["user"] for r in records} == {"alice"}
    assert len({r["profile"] for r in records}) == 3
    assert all(re.fullmatch(r"bp1_[a-f0-9]{64}:Default", r["profile"]) for r in records)
    assert all(str(tmp_path) not in json.dumps(record) for record in records)


def test_complete_long_profile_names_are_hashed_before_wire_truncation(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    # Windows MAX_PATH needs a short absolute fixture root for these real long names.
    home = tmp_path / "u"
    prefix = "p" * 254
    for ending in ("x", "y"):
        _firefox(home, ".mozilla/firefox", prefix + ending, [_addon("same@test", "Same")])
    records = agent.unique_records("extensions", [agent.conform(r) for r in browser_ext.collect_extensions([home])])
    assert len(records) == 2
    profiles = [ExtensionRecord.model_validate(record).profile for record in records]
    assert all(len(profile) == 255 for profile in profiles)
    assert profiles[0] != profiles[1]
    assert profiles[0].split(":")[1] == profiles[1].split(":")[1]


def test_format_is_canonical_ascii_and_scope_case_and_unicode_are_explicit():
    root, profile = (".config", "Chrome"), ("Profilé",)
    payload = json.dumps(["browser-profile-v1", "chromium", list(root), list(profile)],
                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
    assert qualified_profile("chromium", root, profile, "Profilé", "Linux") == (
        "bp1_" + hashlib.sha256(payload).hexdigest() + ":Profilé")
    upper = qualified_profile("chromium", root, profile, "Profilé", "Windows")
    assert upper == qualified_profile("chromium", (".CONFIG", "chrome"), ("profilé",), "profilé", "Windows")
    assert upper != qualified_profile("gecko", root, profile, "Profilé", "Windows")
    assert qualified_profile("chromium", root, profile, "Profilé", "Linux") != qualified_profile(
        "chromium", root, ("Profile\u0301",), "Profile\u0301", "Linux")
    assert qualified_profile("chromium", root, profile, "Profilé", "Linux") != qualified_profile(
        "chromium", root, ("profilé",), "profilé", "Linux")
    assert "\ud800" not in qualified_profile("chromium", root, ("bad\ud800",), "bad\ud800", "Linux")


def _alias(link: Path, target: Path):
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        import subprocess

        # Junctions need no Windows symlink privilege; both targets are disposable test directories.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True, capture_output=True)
    else:
        link.symlink_to(target, target_is_directory=True)


def test_internal_aliases_collapse_external_roots_and_profiles_are_skipped(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    home = tmp_path / "alice-private"
    root = ".mozilla/firefox"
    _firefox(home, root, "Default", [_addon("good@test", "Good")])
    _firefox(tmp_path / "outside-private", root, "Default", [_addon("outside@test", "Outside")])
    _alias(home / root / "Alias", home / root / "Default")
    _alias(home / ".mozilla" / "alias", home / root)
    _alias(home / ".mozilla" / "escape", tmp_path / "outside-private" / root)
    _alias(home / root / "Escape", tmp_path / "outside-private" / root / "Default")
    monkeypatch.setattr(browser_ext, "GECKO_ROOTS", {"Linux": [(root, "firefox"),
                       (".mozilla/alias", "firefox"), (".mozilla/escape", "firefox")]})
    [record] = browser_ext.collect_extensions([home])
    assert record["id"] == "good@test"
    assert record["profile"].endswith(":Default")
    assert "alice-private" not in caplog.text and "outside-private" not in caplog.text


def test_home_relocation_preserves_qualified_value(tmp_path):
    values = []
    for owner in ("alice", "relocated"):
        home = tmp_path / owner
        profile = home / "data" / "Default"
        profile.mkdir(parents=True)
        values.append(browser_profile(home, home / "data", profile, "chromium", "Linux"))
    assert values[0] == values[1]


def test_json_parser_errors_cannot_discard_good_browser_or_user_siblings(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    homes = [tmp_path / "alice", tmp_path / "bob"]
    failures, valid = set(), set()
    for home in homes:
        failures.add(_install(home, ".config/google-chrome", "Default", "bad", "1",
                              {"name": "Bad", "version": "1"}).resolve())
        valid.add(_install(home, ".config/google-chrome", "Default", "good", "1",
                           {"name": "Good", "version": "1"}).resolve())
        failures.add(_firefox(home, ".mozilla/firefox", "Bad", [_addon("bad@test", "Bad")]).resolve())
        valid.add(_firefox(home, ".mozilla/firefox", "Good", [_addon("good@test", "Good")]).resolve())
    real_load = json.load
    attempted, delegated = set(), set()

    def selective_load(handle, *args, **kwargs):
        path = Path(handle.name).resolve()
        if path in failures:
            attempted.add(path)
            raise RecursionError("synthetic JSON parser depth failure")
        delegated.add(path)
        return real_load(handle, *args, **kwargs)

    designated = next(iter(failures))
    with designated.open(encoding="utf-8") as handle, pytest.raises(RecursionError):
        selective_load(handle)
    with monkeypatch.context() as context:
        context.setattr(browser_ext, "json", SimpleNamespace(load=selective_load))
        assert browser_ext._read_manifest(designated) is None
        records = browser_ext.collect_extensions(homes)
    assert len(records) == 4
    assert {(r["browser"], r["id"], r["user"]) for r in records} == {
        ("chrome", "good", "alice"), ("firefox", "good@test", "alice"),
        ("chrome", "good", "bob"), ("firefox", "good@test", "bob"),
    }
    assert attempted == failures
    assert valid <= delegated


@pytest.mark.parametrize("active", [None, 1, "yes", [], {}])
def test_malformed_gecko_metadata_preserves_good_addons_profiles_and_users(tmp_path, monkeypatch, active):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    homes = [tmp_path / "alice", tmp_path / "bob"]
    for home in homes:
        _firefox(home, ".mozilla/firefox", "Default", [
            _addon("bad@test", "Bad", active=active, location=[], userPermissions={"permissions": None, "origins": 42}),
            _addon("good@test", "Good")])
    records = browser_ext.collect_extensions(homes)
    assert len(records) == 4
    assert all(r["enabled"] is None and r["permissions"] == [] and r["install_source"] == "unknown"
               for r in records if r["id"] == "bad@test")
    assert all(r["enabled"] is True for r in records if r["id"] == "good@test")
    assert {r["user"] for r in records} == {"alice", "bob"}


@pytest.mark.parametrize("state", [None, True, False, "1", [], {}, 99])
def test_chromium_unknown_state_remains_none_through_real_wire(tmp_path, monkeypatch, state):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    home, root = tmp_path / "alice", ".config/google-chrome"
    _install(home, root, "Default", "a" * 32, "1", {"name": "Same", "version": "1"})
    entry = {"location": 1}
    if state is not None:
        entry["state"] = state
    _prefs(home, root, "Default", {"a" * 32: entry})
    [record] = [agent.conform(r) for r in browser_ext.collect_extensions([home])]
    assert record["enabled"] is None
    assert ExtensionRecord.model_validate(record).enabled is None


def test_safari_copies_are_distinct_and_shared_alias_wins(tmp_path, monkeypatch):
    shared, home = tmp_path / "Applications", tmp_path / "alice"
    shared.mkdir()
    home.mkdir()
    personal = home / "Applications"
    _app(shared, "Shared", "Ext", _info("same.bundle"))
    _app(personal, "Personal", "Ext", _info("same.bundle"))
    _app(shared, "Second", "Ext", _info("same.bundle"))
    _alias(home / "SharedAlias", shared)
    _alias(tmp_path / "ApplicationsAlias", shared)
    monkeypatch.setattr(safari_ext, "APPLICATION_DIRS", [str(shared), str(tmp_path / "ApplicationsAlias")])
    # shared wins even if personal enumeration reaches it: this alias lies outside home and is rejected.
    monkeypatch.setattr(safari_ext, "USER_APPLICATION_DIRS", ["Applications", "SharedAlias"])
    records, errors = safari_ext.collect_safari_extensions([home])
    assert len(records) == 3 and errors == 1
    assert len({r["profile"] for r in records}) == 3
    assert all(r["profile"].endswith(":Default") for r in records)
    assert all(str(tmp_path) not in json.dumps(agent.conform(record)) for record in records)
