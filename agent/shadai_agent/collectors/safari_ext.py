"""Safari extension inventory (macOS).

Safari extensions are app extensions: an ``.appex`` bundle inside a host
application, declared in its ``Info.plist`` with a Safari extension point and,
for web extensions, carrying the same ``manifest.json`` as a Chromium
extension. Installed extensions are found by walking the application folders
(system-wide and per user), which works for the agent's service account; whether
a user enabled one is read from that user's Safari extension state when macOS
lets the agent read it (Full Disk Access), and left unknown otherwise.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from xml.parsers.expat import ExpatError

from shadai_agent.collectors.browser_ext import _localized, _read_manifest
from shadai_agent.collectors.profile_identity import safari_profile

PLIST_MAX_BYTES = 4 * 1024 * 1024
# Application folders scanned for host apps, system-wide then relative to a home.
APPLICATION_DIRS = ["/Applications"]
USER_APPLICATION_DIRS = ["Applications"]
# Host apps may sit one folder down ("/Applications/Setapp/Foo.app").
APP_SCAN_DEPTH = 2
SAFARI_EXTENSION_POINTS = {
    "com.apple.Safari.web-extension",
    "com.apple.Safari.extension",
    "com.apple.Safari.content-blocker",
}
# Per-user Safari extension state, relative to the home directory (sandboxed first).
SAFARI_STATE_FILES = [
    "Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist",
    "Library/Safari/AppExtensions/Extensions.plist",
]


def _read_plist(path: Path) -> dict | None:
    """Parse one property list; None if missing, oversized, malformed or not a dict."""

    try:
        if not path.is_file() or path.stat().st_size > PLIST_MAX_BYTES:
            return None
        with open(path, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, ValueError, ExpatError):
        return None
    return data if isinstance(data, dict) else None


def _app_bundles(folder: Path, depth: int = APP_SCAN_DEPTH) -> list[Path]:
    """Application bundles under one folder, at most ``depth`` levels down."""

    found: list[Path] = []
    try:
        children = [child for child in folder.iterdir() if child.is_dir() and not child.is_symlink()]
    except OSError:
        return found
    for child in children:
        if child.suffix == ".app":
            found.append(child)
        elif depth > 1:
            found.extend(_app_bundles(child, depth - 1))
    return found


def _extension_bundles(app: Path) -> list[Path]:
    try:
        plugins = app / "Contents" / "PlugIns"
        return [child for child in plugins.iterdir() if child.suffix == ".appex" and child.is_dir()]
    except OSError:
        return []


def _extension_record(app: Path, appex: Path) -> dict | None:
    """One inventory record for a Safari extension bundle, or None if it is not one."""

    info = _read_plist(appex / "Contents" / "Info.plist")
    if info is None:
        return None
    extension = info.get("NSExtension")
    point = extension.get("NSExtensionPointIdentifier") if isinstance(extension, dict) else None
    if not isinstance(point, str) or point not in SAFARI_EXTENSION_POINTS:
        return None
    bundle_id = info.get("CFBundleIdentifier")
    if not isinstance(bundle_id, str) or not bundle_id:
        return None
    resources = appex / "Contents" / "Resources"
    manifest = _read_manifest(resources / "manifest.json") or {}
    name = manifest.get("name") or info.get("CFBundleDisplayName") or info.get("CFBundleName") or "Unknown"
    permissions = manifest.get("permissions", [])
    return {
        "id": bundle_id,
        "name": _localized(name, manifest, resources) or "Unknown",
        "version": str(manifest.get("version") or info.get("CFBundleShortVersionString") or ""),
        "browser": "safari",
        "permissions": permissions if isinstance(permissions, list) else [],
        "profile": "Default",
        "install_source": "store" if (app / "Contents" / "_MASReceipt" / "receipt").is_file() else "user",
        "host_app": app.name,
    }


def _user_state(home: Path) -> dict[str, bool] | None:
    """Which extensions a user enabled in Safari, or None when the state is unreadable."""

    for relative in SAFARI_STATE_FILES:
        state = _read_plist(home / relative)
        if state is None:
            continue
        enabled: dict[str, bool] = {}
        for bundle_id, entry in state.items():
            if isinstance(entry, dict) and isinstance(entry.get("Enabled"), bool):
                enabled[bundle_id] = entry["Enabled"]
        return enabled
    return None


def collect_safari_extensions(homes: list[Path]) -> tuple[list[dict], int]:
    """Safari extensions installed for each user, with that user's enabled state.

    Returns the records and the number of unreadable paths. Never raises.
    """

    shared: dict[Path, dict] = {}
    errors = 0
    for folder in APPLICATION_DIRS:
        for app in _app_bundles(Path(folder)):
            for appex in _extension_bundles(app):
                try:
                    canonical, profile = safari_profile(Path(folder), appex, "safari-system")
                    if canonical in shared:
                        continue
                    record = _extension_record(app, appex)
                except (OSError, RuntimeError, ValueError, TypeError):
                    errors += 1
                    continue
                if record is not None:
                    shared[canonical] = {**record, "profile": profile}
    extensions: list[dict] = []
    for home in homes:
        home = Path(home)
        personal: dict[Path, dict] = {}
        for relative in USER_APPLICATION_DIRS:
            folder = home / relative
            try:
                folder.resolve(strict=True).relative_to(home.resolve(strict=True))
            except (OSError, RuntimeError, ValueError):
                errors += 1
                continue
            for app in _app_bundles(folder):
                for appex in _extension_bundles(app):
                    try:
                        canonical, profile = safari_profile(folder, appex, "safari-user")
                        if canonical in shared or canonical in personal:
                            continue
                        record = _extension_record(app, appex)
                    except (OSError, RuntimeError, ValueError, TypeError):
                        errors += 1
                        continue
                    if record is not None:
                        personal[canonical] = {**record, "profile": profile}
        state = _user_state(home)
        for record in [*shared.values(), *personal.values()]:
            enabled = state.get(record["id"]) if state is not None else None
            extensions.append({**record, "user": home.name, "enabled": enabled})
    return extensions, errors
