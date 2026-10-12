"""Browser extension inventory collector.

Reads installed Chromium-family browser extensions from their on-disk
``manifest.json``. Only manifest metadata is read; extension storage, cookies,
history and sign-in data are never touched. A malformed, oversized or
unreadable manifest is skipped so that one bad file can never abort the
collection cycle (a failure here must not drop the processes and local-AI hits
gathered in the same snapshot).
"""

from __future__ import annotations

import json
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

# A manifest larger than this is treated as hostile and skipped rather than read.
MANIFEST_MAX_BYTES = 1024 * 1024
# Transient install scratch directories that are not real extension versions.
_SKIP_VERSION_DIRS = {"Temp", "CRX_INSTALL"}

# Known user-data roots, each tagged with the browser it belongs to so the label
# never has to be guessed from a substring of the path (that mislabelled
# Chromium as "chrome" and could mislabel Edge). Still single-user ("~") here;
# full multi-user, multi-browser enumeration is a later step.
BROWSER_ROOTS: dict[str, list[tuple[str, str]]] = {
    "Linux": [
        ("~/.config/google-chrome", "chrome"),
        ("~/.config/chromium", "chromium"),
        ("~/.config/microsoft-edge", "edge"),
    ],
    "Darwin": [
        ("~/Library/Application Support/Google/Chrome", "chrome"),
        ("~/Library/Application Support/Chromium", "chromium"),
        ("~/Library/Application Support/Microsoft Edge", "edge"),
    ],
    "Windows": [
        ("~/AppData/Local/Google/Chrome/User Data", "chrome"),
        ("~/AppData/Local/Chromium/User Data", "chromium"),
        ("~/AppData/Local/Microsoft/Edge/User Data", "edge"),
    ],
}


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


def _read_manifest(path: Path) -> dict | None:
    """Parse one ``manifest.json``; return the dict, or None if unusable.

    Reads as UTF-8 (tolerating a BOM) with a size cap, and treats any OS error,
    decode error or non-object JSON as "skip this manifest" rather than raising.
    """

    try:
        if not path.is_file() or path.stat().st_size > MANIFEST_MAX_BYTES:
            return None
        with open(path, encoding="utf-8-sig") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) else None


def _pick_manifest(ext_id_dir: Path) -> dict | None:
    """Return the manifest of the highest installed version of an extension."""

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
            return manifest
    return None


def _collect_root(base: Path, browser: str, extensions: list[dict]) -> int:
    """Append every readable extension under one user-data root. Returns errors."""

    errors = 0
    try:
        profiles = list(base.iterdir())
    except OSError:
        return 1
    for profile_dir in profiles:
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
                manifest = _pick_manifest(ext_id_dir)
                if manifest is None:
                    continue
                extensions.append(
                    {
                        "id": ext_id_dir.name,
                        "name": str(manifest.get("name", "Unknown")),
                        "version": str(manifest.get("version", "")),
                        "browser": browser,
                        "permissions": manifest.get("permissions", []),
                        "profile": profile_dir.name,
                    }
                )
            except OSError:
                errors += 1
    return errors


def collect_extensions() -> list[dict]:
    """Collect installed Chromium-family browser extensions.

    Never raises: unreadable roots, profiles and manifests are counted and
    skipped. Records carry the raw extension id, name and browser (the only
    fields put on the wire today) plus version, permissions and profile for
    local use.
    """

    system = platform.system()
    extensions: list[dict] = []
    errors = 0
    for base_path, browser in BROWSER_ROOTS.get(system, []):
        try:
            base = Path(base_path).expanduser()
            if not base.exists():
                continue
        except OSError:
            errors += 1
            continue
        errors += _collect_root(base, browser, extensions)
    if errors:
        logger.warning("Extension inventory skipped %s unreadable path(s)", errors)
    return extensions
