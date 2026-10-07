"""Actual code and interpreter identity, without hostnames or credentials."""

import hashlib
import platform
import re
import subprocess
from pathlib import Path


def source_stamp():
    directory = Path(__file__).resolve().parent
    root = directory.parents[2]
    revision = None
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", result.stdout.strip()):
            revision = result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {
        "revision": revision,
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(directory.glob("*.py"))
        },
        "environment": {
            "system": platform.system(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },
    }
