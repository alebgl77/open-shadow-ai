"""Safari extension inventory from app bundles (macOS)."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest
from shadai_agent.collectors import browser_ext, safari_ext

WEB_EXTENSION = "com.apple.Safari.web-extension"


def _app(folder: Path, app_name: str, appex_name: str, info: dict, *, manifest: dict | None = None,
         receipt: bool = False) -> Path:
    """Write <folder>/<app>.app/Contents/PlugIns/<appex>.appex with an Info.plist and manifest."""
    app = folder / f"{app_name}.app"
    appex = app / "Contents" / "PlugIns" / f"{appex_name}.appex"
    (appex / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)
    with open(appex / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump(info, handle)
    if manifest is not None:
        (appex / "Contents" / "Resources" / "manifest.json").write_text(json.dumps(manifest))
    if receipt:
        (app / "Contents" / "_MASReceipt").mkdir(parents=True)
        (app / "Contents" / "_MASReceipt" / "receipt").write_bytes(b"x")
    return app


def _info(bundle_id: str, point: str = WEB_EXTENSION, **extra) -> dict:
    return {"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": "2.4",
            "CFBundleDisplayName": "Display Name", "NSExtension": {"NSExtensionPointIdentifier": point}, **extra}


@pytest.fixture
def mac(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Darwin")
    apps = tmp_path / "Applications"
    apps.mkdir()
    monkeypatch.setattr(safari_ext, "APPLICATION_DIRS", [str(apps)])
    home = tmp_path / "Users" / "alice"
    home.mkdir(parents=True)
    return apps, home


def _state(home: Path, enabled: dict[str, bool], *, sandboxed: bool = True) -> None:
    relative = safari_ext.SAFARI_STATE_FILES[0 if sandboxed else 1]
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        plistlib.dump({bundle_id: {"Enabled": flag, "AddedDate": "x"} for bundle_id, flag in enabled.items()}, handle)


def test_web_extension_in_a_host_app_is_inventoried(mac):
    apps, home = mac
    _app(apps, "Grammarly", "Grammarly Extension", _info("com.grammarly.safari.extension"),
         manifest={"name": "Grammarly: AI Writing", "version": "9.1", "permissions": ["activeTab", "<all_urls>"]},
         receipt=True)
    [record] = browser_ext.collect_extensions(homes=[home])
    assert record["id"] == "com.grammarly.safari.extension"
    assert record["name"] == "Grammarly: AI Writing"
    assert record["version"] == "9.1"
    assert record["browser"] == "safari"
    assert record["permissions"] == ["activeTab", "<all_urls>"]
    assert record["install_source"] == "store"
    assert record["host_app"] == "Grammarly.app"
    assert (record["user"], record["profile"], record["enabled"]) == ("alice", "Default", None)


def test_enabled_state_comes_from_the_users_safari_state(mac):
    apps, home = mac
    _app(apps, "A", "A Ext", _info("com.a.ext"), manifest={"name": "A", "version": "1"})
    _app(apps, "B", "B Ext", _info("com.b.ext"), manifest={"name": "B", "version": "1"})
    _state(home, {"com.a.ext": True, "com.b.ext": False})
    records = {r["id"]: r["enabled"] for r in browser_ext.collect_extensions(homes=[home])}
    assert records == {"com.a.ext": True, "com.b.ext": False}


def test_legacy_state_file_is_used_when_the_sandboxed_one_is_absent(mac):
    apps, home = mac
    _app(apps, "A", "A Ext", _info("com.a.ext"), manifest={"name": "A", "version": "1"})
    _state(home, {"com.a.ext": True}, sandboxed=False)
    [record] = browser_ext.collect_extensions(homes=[home])
    assert record["enabled"] is True


def test_non_safari_app_extensions_are_ignored(mac):
    apps, home = mac
    _app(apps, "Notes", "Share", _info("com.notes.share", point="com.apple.share-services"))
    _app(apps, "Blocker", "Rules", _info("com.blocker.rules", point="com.apple.Safari.content-blocker"))
    assert [r["id"] for r in browser_ext.collect_extensions(homes=[home])] == ["com.blocker.rules"]


def test_name_falls_back_to_the_bundle_display_name_without_a_manifest(mac):
    apps, home = mac
    _app(apps, "Legacy", "Old", _info("com.legacy.old", point="com.apple.Safari.extension"))
    [record] = browser_ext.collect_extensions(homes=[home])
    assert (record["name"], record["version"], record["install_source"]) == ("Display Name", "2.4", "user")


def test_localized_manifest_name_is_resolved(mac):
    apps, home = mac
    app = _app(apps, "L", "L Ext", _info("com.l.ext"),
               manifest={"name": "__MSG_appName__", "version": "1", "default_locale": "en"})
    locale = app / "Contents" / "PlugIns" / "L Ext.appex" / "Contents" / "Resources" / "_locales" / "en"
    locale.mkdir(parents=True)
    (locale / "messages.json").write_text(json.dumps({"appName": {"message": "Localized L"}}))
    [record] = browser_ext.collect_extensions(homes=[home])
    assert record["name"] == "Localized L"


def test_apps_one_folder_down_and_in_the_users_applications_are_scanned(mac):
    apps, home = mac
    _app(apps / "Setapp", "Nested", "N Ext", _info("com.nested.ext"), manifest={"name": "Nested", "version": "1"})
    _app(home / "Applications", "Mine", "M Ext", _info("com.mine.ext"), manifest={"name": "Mine", "version": "1"})
    _app(apps / "a" / "b", "TooDeep", "D Ext", _info("com.deep.ext"), manifest={"name": "Deep", "version": "1"})
    assert {r["name"] for r in browser_ext.collect_extensions(homes=[home])} == {"Nested", "Mine"}


def test_broken_or_oversized_plists_are_skipped_not_raised(mac):
    apps, home = mac
    app = _app(apps, "Broken", "B Ext", _info("com.broken.ext"))
    (app / "Contents" / "PlugIns" / "B Ext.appex" / "Contents" / "Info.plist").write_bytes(b"<plist><dict>")
    big = _app(apps, "Big", "Big Ext", _info("com.big.ext"))
    (big / "Contents" / "PlugIns" / "Big Ext.appex" / "Contents" / "Info.plist").write_bytes(
        b"x" * (safari_ext.PLIST_MAX_BYTES + 1))
    _app(apps, "Odd", "Odd Ext", {"NSExtension": "not a dict"})
    _app(apps, "NoId", "NoId Ext", {"NSExtension": {"NSExtensionPointIdentifier": WEB_EXTENSION}})
    _app(apps, "Fine", "F Ext", _info("com.fine.ext"), manifest={"name": "Fine", "version": "1"})
    assert [r["id"] for r in browser_ext.collect_extensions(homes=[home])] == ["com.fine.ext"]


def test_each_user_gets_a_record_with_their_own_state(mac, tmp_path):
    apps, alice = mac
    bob = tmp_path / "Users" / "bob"
    bob.mkdir()
    _app(apps, "A", "A Ext", _info("com.a.ext"), manifest={"name": "A", "version": "1"})
    _state(alice, {"com.a.ext": True})
    records = {(r["user"], r["enabled"]) for r in browser_ext.collect_extensions(homes=[alice, bob])}
    assert records == {("alice", True), ("bob", None)}


def test_safari_is_not_scanned_on_other_platforms(tmp_path, monkeypatch):
    monkeypatch.setattr(browser_ext.platform, "system", lambda: "Linux")
    apps = tmp_path / "Applications"
    apps.mkdir()
    monkeypatch.setattr(safari_ext, "APPLICATION_DIRS", [str(apps)])
    _app(apps, "A", "A Ext", _info("com.a.ext"), manifest={"name": "A", "version": "1"})
    assert browser_ext.collect_extensions(homes=[tmp_path / "home"]) == []
