"""Browser extension inventory collector.

Reads installed Chromium-family browser extensions from their on-disk
``manifest.json`` and Firefox-family add-ons from each profile's
``extensions.json``. Only extension metadata is read; extension storage,
cookies, history and sign-in data are never touched. A malformed, oversized or
unreadable manifest is skipped so that one bad file can never abort the
collection cycle (a failure here must not drop the processes and local-AI hits
gathered in the same snapshot).

The agent runs as a service account (SYSTEM on Windows, root elsewhere), so
``~`` is the service profile and holds no browser at all. Every local user
profile on the host is enumerated instead, and every Chromium-family user-data
root under each one is read: stable, beta, dev and canary channels, snap and
flatpak installs, and vendors that ship their own Chromium build.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
from collections.abc import Iterable
from pathlib import Path

logger = logging.getLogger(__name__)

# A manifest larger than this is treated as hostile and skipped rather than read.
MANIFEST_MAX_BYTES = 1024 * 1024
# Firefox's extensions.json lists every add-on of a profile with its locales.
ADDONS_JSON_MAX_BYTES = 8 * 1024 * 1024
# Transient install scratch directories that are not real extension versions.
_SKIP_VERSION_DIRS = {"Temp", "CRX_INSTALL"}
# Chromium i18n placeholder in manifest strings: "__MSG_appName__".
_MSG_PLACEHOLDER = re.compile(r"__MSG_([A-Za-z0-9_@]+)__")
# Locales tried after the manifest's default_locale when a message is missing.
_FALLBACK_LOCALES = ("en", "en_US", "en_GB")

# Chromium-family user-data roots, relative to a user's home directory, each
# tagged with the browser it belongs to so the label never has to be guessed
# from a substring of the path.
CHROMIUM_ROOTS: dict[str, list[tuple[str, str]]] = {
    "Linux": [
        (".config/google-chrome", "chrome"),
        (".config/google-chrome-beta", "chrome"),
        (".config/google-chrome-unstable", "chrome"),
        (".var/app/com.google.Chrome/config/google-chrome", "chrome"),
        (".config/chromium", "chromium"),
        ("snap/chromium/common/chromium", "chromium"),
        (".var/app/org.chromium.Chromium/config/chromium", "chromium"),
        (".config/microsoft-edge", "edge"),
        (".config/microsoft-edge-beta", "edge"),
        (".config/microsoft-edge-dev", "edge"),
        (".var/app/com.microsoft.Edge/config/microsoft-edge", "edge"),
        (".config/BraveSoftware/Brave-Browser", "brave"),
        (".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser", "brave"),
        (".config/vivaldi", "vivaldi"),
        (".config/opera", "opera"),
    ],
    "Darwin": [
        ("Library/Application Support/Google/Chrome", "chrome"),
        ("Library/Application Support/Google/Chrome Beta", "chrome"),
        ("Library/Application Support/Google/Chrome Canary", "chrome"),
        ("Library/Application Support/Chromium", "chromium"),
        ("Library/Application Support/Microsoft Edge", "edge"),
        ("Library/Application Support/Microsoft Edge Beta", "edge"),
        ("Library/Application Support/Microsoft Edge Dev", "edge"),
        ("Library/Application Support/Microsoft Edge Canary", "edge"),
        ("Library/Application Support/BraveSoftware/Brave-Browser", "brave"),
        ("Library/Application Support/Vivaldi", "vivaldi"),
        ("Library/Application Support/com.operasoftware.Opera", "opera"),
        ("Library/Application Support/Arc/User Data", "arc"),
    ],
    "Windows": [
        ("AppData/Local/Google/Chrome/User Data", "chrome"),
        ("AppData/Local/Google/Chrome Beta/User Data", "chrome"),
        ("AppData/Local/Google/Chrome SxS/User Data", "chrome"),
        ("AppData/Local/Chromium/User Data", "chromium"),
        ("AppData/Local/Microsoft/Edge/User Data", "edge"),
        ("AppData/Local/Microsoft/Edge Beta/User Data", "edge"),
        ("AppData/Local/Microsoft/Edge Dev/User Data", "edge"),
        ("AppData/Local/Microsoft/Edge SxS/User Data", "edge"),
        ("AppData/Local/BraveSoftware/Brave-Browser/User Data", "brave"),
        ("AppData/Local/Vivaldi/User Data", "vivaldi"),
        ("AppData/Roaming/Opera Software/Opera Stable", "opera"),
        ("AppData/Roaming/Opera Software/Opera GX Stable", "opera"),
        ("AppData/Local/Packages/TheBrowserCompany.Arc_ttt1ap7aakyb4/LocalCache/Local/Arc/User Data", "arc"),
    ],
}

# Firefox-family profile roots relative to a user's home directory. Each child
# directory holding an extensions.json is one profile.
GECKO_ROOTS: dict[str, list[tuple[str, str]]] = {
    "Linux": [
        (".mozilla/firefox", "firefox"),
        ("snap/firefox/common/.mozilla/firefox", "firefox"),
        (".var/app/org.mozilla.firefox/.mozilla/firefox", "firefox"),
        (".librewolf", "librewolf"),
        (".var/app/io.gitlab.librewolf-community/.librewolf", "librewolf"),
        (".waterfox", "waterfox"),
        (".zen", "zen"),
    ],
    "Darwin": [
        ("Library/Application Support/Firefox/Profiles", "firefox"),
        ("Library/Application Support/LibreWolf/Profiles", "librewolf"),
        ("Library/Application Support/Waterfox/Profiles", "waterfox"),
        ("Library/Application Support/zen/Profiles", "zen"),
    ],
    "Windows": [
        ("AppData/Roaming/Mozilla/Firefox/Profiles", "firefox"),
        ("AppData/Roaming/librewolf/Profiles", "librewolf"),
        ("AppData/Roaming/Waterfox/Profiles", "waterfox"),
        ("AppData/Roaming/zen/Profiles", "zen"),
    ],
}
# Add-ons Mozilla ships inside the browser itself are not user choices.
_GECKO_BUILTIN_LOCATIONS = {"app-builtin", "app-system-defaults", "app-system-addons"}
# Where a Firefox add-on came from, by its install location.
_GECKO_INSTALL_SOURCES = {
    "app-profile": "user",
    "app-temporary": "unpacked",
    "app-global": "external",
    "app-system-share": "external",
    "app-system-local": "external",
    "app-system-user": "external",
    "winreg-app-global": "external",
    "winreg-app-user": "external",
}

# Where vendors put per-user application data, relative to the home directory.
# Any Chromium-family browser not listed above (new entrants bundle their own
# Chromium) is discovered here by its ``Local State`` file, up to this depth.
APP_DATA_DIRS: dict[str, list[str]] = {
    "Linux": [".config"],
    "Darwin": ["Library/Application Support"],
    "Windows": ["AppData/Local", "AppData/Roaming"],
}
DISCOVERY_MAX_DEPTH = 3
DISCOVERY_MAX_ENTRIES = 5000

# Only real accounts hold a browser: local and domain users, and Entra ID users.
_WINDOWS_USER_SID_PREFIXES = ("S-1-5-21-", "S-1-12-1-")
# Folders under the users directory that are never a person's profile.
_WINDOWS_NON_USER_PROFILES = {"public", "default", "default user", "all users"}
_POSIX_NON_USER_HOMES = {"shared", "guest", "lost+found"}
_POSIX_USERS_DIRS = {"Darwin": "/Users", "Linux": "/home"}
_POSIX_NOLOGIN_SHELLS = ("nologin", "false")
_NOBODY_UID = 65534


def _version_sort_key(name: str) -> tuple:
    """Order ``<version>_<serial>`` directories numerically, not lexically.

    Chromium installs an extension under ``<version>_<n>``. A plain string sort
    ranks ``9.0.0_0`` above ``10.0.0_0``; this parses each dotted component so
    ``10.0.0_0`` wins. Non-numeric components sort after numeric ones so an odd
    name never raises.
    """

    version, _, serial = name.partition("_")

    def components(text: str) -> tuple:
        parsed = []
        for chunk in text.split("."):
            parsed.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
        return tuple(parsed)

    return (components(version), int(serial) if serial.isdigit() else -1)


def _read_manifest(path: Path, max_bytes: int = MANIFEST_MAX_BYTES) -> dict | None:
    """Parse one JSON metadata file; return the dict, or None if unusable.

    Reads as UTF-8 (tolerating a BOM) with a size cap, and treats any OS error,
    decode error or non-object JSON as "skip this file" rather than raising.
    """

    try:
        if not path.is_file() or path.stat().st_size > max_bytes:
            return None
        with open(path, encoding="utf-8-sig") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) else None


def _pick_manifest(ext_id_dir: Path) -> tuple[dict, Path] | None:
    """Return the manifest of the highest installed version of an extension, and its directory."""

    try:
        candidates = [
            child
            for child in ext_id_dir.iterdir()
            if child.name not in _SKIP_VERSION_DIRS and child.is_dir()
        ]
    except OSError:
        return None
    for version_dir in sorted(candidates, key=lambda d: _version_sort_key(d.name), reverse=True):
        manifest = _read_manifest(version_dir / "manifest.json")
        if manifest is not None:
            return manifest, version_dir
    return None


def _messages(version_dir: Path, locale: str) -> dict:
    """The ``_locales/<locale>/messages.json`` table, keyed case-insensitively, or empty."""

    if not isinstance(locale, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,16}", locale):
        return {}
    table = _read_manifest(version_dir / "_locales" / locale / "messages.json")
    if not table:
        return {}
    messages = {}
    for key, entry in table.items():
        if isinstance(entry, dict) and isinstance(entry.get("message"), str):
            messages[key.lower()] = entry["message"]
    return messages


def _localized(text: object, manifest: dict, version_dir: Path) -> str:
    """Resolve ``__MSG_key__`` placeholders the way Chromium does for a stored extension.

    The manifest's ``default_locale`` table is used first, then English
    fallbacks. A placeholder with no message anywhere is left as is: the raw
    key still identifies the extension better than an empty name.
    """

    text = str(text)
    if "__MSG_" not in text:
        return text
    tables: list[dict] = []
    for locale in (manifest.get("default_locale"), *_FALLBACK_LOCALES):
        if locale and locale not in [t.get("__locale__") for t in tables]:
            table = _messages(version_dir, locale)
            if table:
                table["__locale__"] = locale
                tables.append(table)

    def lookup(match: re.Match) -> str:
        key = match.group(1).lower()
        for table in tables:
            if key in table:
                return table[key]
        return match.group(0)

    return _MSG_PLACEHOLDER.sub(lookup, text).strip()


def _windows_profile_homes() -> list[Path]:
    """Every user profile registered on a Windows host, read as SYSTEM.

    ``ProfileList`` is the authoritative record, including roaming and Entra
    ID accounts whose folder names differ from their user names. Falls back to
    listing the users directory when the registry is unavailable.
    """

    homes: list[Path] = []
    try:
        import winreg  # noqa: PLC0415 - Windows only

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as profiles:
            index = 0
            while True:
                try:
                    sid = winreg.EnumKey(profiles, index)
                except OSError:
                    break
                index += 1
                if not sid.startswith(_WINDOWS_USER_SID_PREFIXES):
                    continue
                try:
                    with winreg.OpenKey(profiles, sid) as entry:
                        image, _ = winreg.QueryValueEx(entry, "ProfileImagePath")
                except OSError:
                    continue
                homes.append(Path(os.path.expandvars(str(image))))
    except (ImportError, OSError):
        pass
    if homes:
        return homes
    users_dir = Path(os.environ.get("SystemDrive", "C:")) / "Users"
    try:
        return [child for child in users_dir.iterdir()
                if child.is_dir() and child.name.lower() not in _WINDOWS_NON_USER_PROFILES]
    except OSError:
        return []


def _posix_homes(system: str) -> list[Path]:
    """Every interactive account's home, from the account database and the users directory."""

    homes: list[Path] = []
    minimum_uid = 500 if system == "Darwin" else 1000
    try:
        import pwd  # noqa: PLC0415 - POSIX only

        for entry in pwd.getpwall():
            if not minimum_uid <= entry.pw_uid < _NOBODY_UID or entry.pw_shell.endswith(_POSIX_NOLOGIN_SHELLS):
                continue
            homes.append(Path(entry.pw_dir))
    except (ImportError, OSError):
        pass
    # Directory and mobile accounts (LDAP, AD-bound Macs) are not always in
    # the local account database; a home that exists on disk belonged to someone.
    try:
        homes.extend(child for child in Path(_POSIX_USERS_DIRS.get(system, "/home")).iterdir()
                     if child.is_dir() and not child.name.startswith(".")
                     and child.name.lower() not in _POSIX_NON_USER_HOMES)
    except OSError:
        pass
    return homes


def iter_user_homes() -> list[Path]:
    """Home directories of every local user, plus the one the agent runs as.

    Never raises. Duplicates (the same home reached by two routes) are removed
    so an extension is never inventoried twice from the same files.
    """

    system = platform.system()
    candidates = _windows_profile_homes() if system == "Windows" else _posix_homes(system)
    try:
        candidates.append(Path.home())
    except (OSError, RuntimeError):
        pass
    homes: list[Path] = []
    seen: set[str] = set()
    for home in candidates:
        try:
            key = os.path.normcase(str(home.resolve()))
            if key in seen or not home.is_dir():
                continue
        except OSError:
            continue
        seen.add(key)
        homes.append(home)
    return homes


def _slug(relative: Path) -> str:
    """Label an unlisted Chromium-family root after its vendor path ("perplexity-comet")."""

    parts = [part for part in relative.parts if part.lower() != "user data"]
    text = "-".join(parts).lower()
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-") or "chromium"


def _discover_chromium_roots(home: Path, system: str) -> list[tuple[Path, str]]:
    """Find Chromium-family user-data roots not in the known table.

    A user-data root is recognised by its ``Local State`` file next to at least
    one profile holding an ``Extensions`` directory, which rules out the many
    Electron applications that also write a ``Local State``.
    """

    found: list[tuple[Path, str]] = []
    for app_data in APP_DATA_DIRS.get(system, []):
        base = home / app_data
        if not base.is_dir():
            continue
        budget = DISCOVERY_MAX_ENTRIES
        pending = [(base, 0)]
        while pending and budget > 0:
            directory, depth = pending.pop()
            try:
                children = [child for child in directory.iterdir() if child.is_dir() and not child.is_symlink()]
            except OSError:
                continue
            budget -= len(children)
            for child in children:
                if (child / "Local State").is_file():
                    if any((profile / "Extensions").is_dir() for profile in _profile_dirs(child)):
                        found.append((child, _slug(child.relative_to(base))))
                elif depth + 1 < DISCOVERY_MAX_DEPTH:
                    pending.append((child, depth + 1))
    return found


def _profile_dirs(base: Path) -> list[Path]:
    """Profile directories of one user-data root (the root itself for single-profile layouts)."""

    try:
        if (base / "Extensions").is_dir():
            return [base]
        return [child for child in base.iterdir() if child.is_dir()]
    except OSError:
        return []


def _collect_root(base: Path, browser: str, user: str, extensions: list[dict]) -> int:
    """Append every readable extension under one user-data root. Returns errors."""

    errors = 0
    for profile_dir in _profile_dirs(base):
        try:
            ext_dir = profile_dir / "Extensions"
            if not ext_dir.is_dir():
                continue
            ext_id_dirs = list(ext_dir.iterdir())
        except OSError:
            errors += 1
            continue
        for ext_id_dir in ext_id_dirs:
            try:
                if not ext_id_dir.is_dir():
                    continue
                picked = _pick_manifest(ext_id_dir)
                if picked is None:
                    continue
                manifest, version_dir = picked
                extensions.append(
                    {
                        "id": ext_id_dir.name,
                        "name": _localized(manifest.get("name", "Unknown"), manifest, version_dir) or "Unknown",
                        "version": str(manifest.get("version", "")),
                        "browser": browser,
                        "permissions": manifest.get("permissions", []),
                        "profile": "Default" if profile_dir == base else profile_dir.name,
                        "user": user,
                    }
                )
            except OSError:
                errors += 1
    return errors


def _gecko_addon(addon: dict) -> dict | None:
    """One add-on record from a Firefox ``extensions.json`` entry, or None if not an extension."""

    if addon.get("type") != "extension" or addon.get("location") in _GECKO_BUILTIN_LOCATIONS:
        return None
    addon_id = addon.get("id")
    if not isinstance(addon_id, str) or not addon_id:
        return None
    locale = addon.get("defaultLocale")
    name = locale.get("name") if isinstance(locale, dict) else None
    grants = addon.get("userPermissions")
    grants = grants if isinstance(grants, dict) else {}
    permissions = [p for key in ("permissions", "origins") for p in grants.get(key, []) if isinstance(p, str)]
    source = str(addon.get("sourceURI") or "")
    install_source = _GECKO_INSTALL_SOURCES.get(str(addon.get("location")), "unknown")
    if install_source == "user" and "addons.mozilla.org" in source:
        install_source = "store"
    return {
        "id": addon_id,
        "name": str(name) if name else "Unknown",
        "version": str(addon.get("version", "")),
        "permissions": permissions,
        "enabled": bool(addon.get("active")) and not addon.get("userDisabled") and not addon.get("appDisabled"),
        "install_source": install_source,
    }


def _collect_gecko_root(base: Path, browser: str, user: str, extensions: list[dict]) -> int:
    """Append every add-on listed by the profiles under one Firefox-family root. Returns errors."""

    errors = 0
    try:
        profiles = [child for child in base.iterdir() if child.is_dir()]
    except OSError:
        return 1
    for profile_dir in profiles:
        listing = profile_dir / "extensions.json"
        try:
            if not listing.is_file():
                continue
        except OSError:
            errors += 1
            continue
        data = _read_manifest(listing, ADDONS_JSON_MAX_BYTES)
        if data is None:
            errors += 1
            continue
        addons = data.get("addons")
        for addon in addons if isinstance(addons, list) else []:
            record = _gecko_addon(addon) if isinstance(addon, dict) else None
            if record is not None:
                extensions.append({**record, "browser": browser, "profile": profile_dir.name, "user": user})
    return errors


def _gecko_roots(home: Path, system: str) -> list[tuple[Path, str]]:
    roots = []
    for relative, browser in GECKO_ROOTS.get(system, []):
        base = home / relative
        try:
            if base.is_dir():
                roots.append((base, browser))
        except OSError:
            continue
    return roots


def _chromium_roots(home: Path, system: str) -> list[tuple[Path, str]]:
    """Known roots first, then discovered ones, without reading the same root twice."""

    roots: list[tuple[Path, str]] = []
    seen: set[str] = set()
    known = [(home / relative, browser) for relative, browser in CHROMIUM_ROOTS.get(system, [])]
    for base, browser in known + _discover_chromium_roots(home, system):
        try:
            if not base.is_dir():
                continue
            key = os.path.normcase(str(base.resolve()))
        except OSError:
            continue
        if key not in seen:
            seen.add(key)
            roots.append((base, browser))
    return roots


def collect_extensions(homes: Iterable[Path] | None = None) -> list[dict]:
    """Collect installed Chromium- and Firefox-family browser extensions for every local user.

    Never raises: unreadable homes, roots, profiles and manifests are counted
    and skipped. Records carry the raw extension id, name and browser (the only
    fields put on the wire today) plus version, permissions, profile and user
    for local use.
    """

    system = platform.system()
    extensions: list[dict] = []
    errors = 0
    for home in iter_user_homes() if homes is None else homes:
        home = Path(home)
        try:
            chromium, gecko = _chromium_roots(home, system), _gecko_roots(home, system)
        except OSError:
            errors += 1
            continue
        for base, browser in chromium:
            errors += _collect_root(base, browser, home.name, extensions)
        for base, browser in gecko:
            errors += _collect_gecko_root(base, browser, home.name, extensions)
    if errors:
        logger.warning("Extension inventory skipped %s unreadable path(s)", errors)
    return extensions
