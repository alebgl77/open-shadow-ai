"""Private, bounded profile labels derived from complete canonical relative paths."""

from __future__ import annotations

import hashlib
import json
import ntpath
from pathlib import Path


def qualified_profile(scope: str, root_parts: tuple[str, ...], profile_parts: tuple[str, ...],
                      basename: str, system: str) -> str:
    """Hash full identity before shortening the readable suffix; never hash the home."""
    normalize = ntpath.normcase if system == "Windows" else lambda value: value
    payload = ["browser-profile-v1", scope,
               [normalize(part) for part in root_parts], [normalize(part) for part in profile_parts]]
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()
    readable = normalize(basename).encode("utf-8", errors="replace").decode("utf-8")[:186]
    return f"bp1_{digest}:{readable}"


def browser_profile(home: Path, root: Path, profile: Path, scope: str, system: str) -> str:
    """Resolve strictly and reject roots outside the owner or profiles outside their root."""
    owner = home.resolve(strict=True)
    base = root.resolve(strict=True)
    canonical = profile.resolve(strict=True)
    root_parts = base.relative_to(owner).parts
    profile_parts = canonical.relative_to(base).parts
    return qualified_profile(scope, root_parts, profile_parts, canonical.name if profile_parts else "Default", system)


def safari_profile(folder: Path, appex: Path, scope: str) -> tuple[Path, str]:
    """Use the extension bundle relative to its collection folder, with a fixed Default suffix."""
    base = folder.resolve(strict=True)
    canonical = appex.resolve(strict=True)
    parts = canonical.relative_to(base).parts
    return canonical, qualified_profile(scope, parts, ("Default",), "Default", "Darwin")
