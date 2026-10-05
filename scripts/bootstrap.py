"""Generate deployment secrets once. Uses only the Python standard library."""
from __future__ import annotations

import argparse
import base64
import os
import secrets
import subprocess
from pathlib import Path


def bootstrap(destination: Path, dry_run: bool = False) -> None:
    source = Path(__file__).resolve().parents[1]
    # Keep junctions visible until the Windows ACL/reparse preflight has checked them.
    destination = Path(os.path.abspath(destination))
    if os.name == "nt" and not dry_run:
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        # A Python process started by pwsh inherits its incompatible Core module path.
        # Windows os.environ keys are uppercase; update that key in a child-only copy.
        child_environment = os.environ.copy()
        child_environment["PSMODULEPATH"] = str(powershell.parent / "Modules")
        subprocess.run([
            str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            str(source / "scripts/Protect-BootstrapWindows.ps1"), "-Directory", str(destination),
        ], check=True, env=child_environment)
    else:
        destination = destination.resolve()
    generated = {
        "pg_password.txt": lambda: secrets.token_hex(32),
        "redis_password.txt": lambda: secrets.token_hex(32),
        "ch_password.txt": lambda: secrets.token_hex(32),
        "jwt_secret.txt": lambda: secrets.token_hex(64),
        "agent_api_key.txt": lambda: secrets.token_hex(32),
        "encryption_key.txt": lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    }
    old_umask = os.umask(0o077)
    try:
        for name, generate in generated.items():
            target = destination / "secrets" / name
            if target.exists():
                print(f"Preserved: {target.name}")
                continue
            if dry_run:
                print(f"Would create: secrets/{name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt":
                target.parent.chmod(0o700)
            # Exclusive creation makes reruns and concurrent invocations non-destructive.
            try:
                with target.open("x", encoding="utf-8") as output:
                    output.write(generate() + "\n")
                target.chmod(0o444)
            except FileExistsError:
                print(f"Preserved: {target.name}")
        for relative in ("config/shadai.yaml", "config/sources.yaml", ".env"):
            target = destination / relative
            if target.exists():
                print(f"Preserved: {relative}")
                continue
            if dry_run:
                print(f"Would copy: {relative}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with target.open("xb") as output:
                    output.write((source / (relative + ".example")).read_bytes())
                if relative.startswith("config/"):
                    target.chmod(0o644)
                    if os.name != "nt":
                        target.parent.chmod(0o755)
            except FileExistsError:
                print(f"Preserved: {relative}")
        print("Dry run complete." if dry_run else "Bootstrap complete. No secret values were printed.")
    finally:
        os.umask(old_umask)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    bootstrap(args.directory, args.dry_run)
