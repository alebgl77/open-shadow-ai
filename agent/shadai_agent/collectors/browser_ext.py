"""Browser extension inventory collector."""

from __future__ import annotations

import json
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

CHROME_PATHS = {
    "Linux": [
        "~/.config/google-chrome",
        "~/.config/chromium",
        "~/.config/microsoft-edge",
    ],
    "Darwin": [
        "~/Library/Application Support/Google/Chrome",
        "~/Library/Application Support/Microsoft Edge",
    ],
    "Windows": [
        "~/AppData/Local/Google/Chrome/User Data",
        "~/AppData/Local/Microsoft/Edge/User Data",
    ],
}


def collect_extensions() -> list[dict]:
    """Collect installed browser extensions from Chrome/Edge profiles."""
    system = platform.system()
    paths = CHROME_PATHS.get(system, [])
    extensions = []
    seen_ids = set()

    for base_path in paths:
        base = Path(base_path).expanduser()
        if not base.exists():
            continue

        browser = "chrome" if "chrome" in str(base).lower() or "chromium" in str(base).lower() else "edge"

        # Scan all profiles (Default, Profile 1, etc.)
        for profile_dir in base.iterdir():
            ext_dir = profile_dir / "Extensions"
            if not ext_dir.is_dir():
                continue

            for ext_id_dir in ext_dir.iterdir():
                if not ext_id_dir.is_dir():
                    continue

                ext_id = ext_id_dir.name
                if ext_id in seen_ids:
                    continue
                seen_ids.add(ext_id)

                # Read manifest from latest version
                for version_dir in sorted(ext_id_dir.iterdir(), reverse=True):
                    manifest_path = version_dir / "manifest.json"
                    if manifest_path.exists():
                        try:
                            with open(manifest_path) as f:
                                manifest = json.load(f)
                            extensions.append(
                                {
                                    "id": ext_id,
                                    "name": manifest.get("name", "Unknown"),
                                    "version": manifest.get("version", ""),
                                    "browser": browser,
                                    "permissions": manifest.get("permissions", []),
                                }
                            )
                        except (json.JSONDecodeError, PermissionError):
                            pass
                        break  # Only read latest version

    return extensions
