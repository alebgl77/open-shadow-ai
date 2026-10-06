"""Native Windows spool/ancestor ACL and SQLite restart smoke, without guard patches.

All mutations stay in a fresh user-profile fixture outside the checkout. A host
with unsafe profile ancestors fails rather than weakening the production guard.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from shadai.utils.delivery_spool import DurableSpool, SpoolError, _check_path

_FIXTURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($env:SHADAI_SPOOL_ACL_ROOT)
$path = [IO.Path]::GetFullPath($env:SHADAI_SPOOL_ACL_PATH)
if (-not $path.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($root) -notmatch '^delivery-spool-acl-[a-f0-9]{32}$') { exit 10 }
$publicSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
switch ($env:SHADAI_SPOOL_ACL_ACTION) {
    'explicit' {
        & $icacls $path /grant '*S-1-5-32-545:R' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 11 }
        $acl = Get-Acl -LiteralPath $path
        $broad = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and
                $_.AccessControlType -eq 'Allow' -and -not $_.IsInherited })
        if (-not $broad.Count) { exit 12 }
    }
    'inherited' {
        & $icacls $path /grant '*S-1-5-32-545:(OI)(CI)R' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 13 }
        $acl = Get-Acl -LiteralPath (Join-Path $path 'delivery.sqlite3')
        $broad = @($acl.GetAccessRules($false, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and
                $_.AccessControlType -eq 'Allow' -and $_.IsInherited })
        if (-not $broad.Count) { exit 14 }
    }
    'writable' {
        & $icacls $path /grant '*S-1-5-32-545:(OI)(CI)M' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 15 }
        $acl = Get-Acl -LiteralPath $path
        $broad = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and
                $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band 852032) })
        if (-not $broad.Count) { exit 16 }
    }
    'owner' {
        & $icacls $path /setowner '*S-1-5-32-545' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 17 }
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $publicSid.Value) { exit 18 }
    }
    'ancestor-owner' {
        & $icacls $path /grant '*S-1-5-32-545:R' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 20 }
        & $icacls $path /setowner '*S-1-5-32-545' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 21 }
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $publicSid.Value) { exit 22 }
        $replacement = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and
                $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band 852032) })
        if ($replacement.Count) { exit 23 }
    }
    default { exit 19 }
}
exit 0
"""

_RESTART_SCRIPT = """
import hashlib
import json
import os
import sys
from shadai.utils.delivery_spool import DurableSpool

payload = b'\\x00synthetic-spool-restart\\xff\\n'
spool = DurableSpool(sys.argv[1], clock=lambda: 1000)
batch_id = spool.enqueue(payload)
assert batch_id == hashlib.sha256(payload).hexdigest()
print(json.dumps({"batch_id": batch_id}), flush=True)
os._exit(77)
"""


def fixture_action(action: str, path: Path, root: Path) -> None:
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    environment = os.environ.copy()
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    environment["SHADAI_SPOOL_ACL_ROOT"] = str(root)
    environment["SHADAI_SPOOL_ACL_PATH"] = str(path)
    environment["SHADAI_SPOOL_ACL_ACTION"] = action
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", _FIXTURE_SCRIPT],
        env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError("native_fixture_" + action + "_failed_" + str(result.returncode))


def rejected(directory: Path, expected: str) -> None:
    try:
        spool = DurableSpool(directory)
    except SpoolError as error:
        if str(error) != expected:
            raise RuntimeError("native_rejection_wrong_reason") from None
    else:
        spool.close()
        raise RuntimeError("native_unsafe_spool_accepted")


def rejected_file(path: Path) -> None:
    try:
        _check_path(path, directory=False)
    except SpoolError as error:
        if str(error) != "spool_private_acl_required":
            raise RuntimeError("native_file_rejection_wrong_reason") from None
    else:
        raise RuntimeError("native_public_file_accepted")


def verify(root: Path) -> None:
    with DurableSpool(root):
        pass
    print("PASS: real private spool and complete trusted-ancestor guard")
    restart = root / "restart"
    process = subprocess.run(
        [sys.executable, "-c", _RESTART_SCRIPT, str(restart)],
        capture_output=True, text=True, timeout=30, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if process.returncode != 77:
        raise RuntimeError("native_restart_enqueue_failed")
    payload = b"\x00synthetic-spool-restart\xff\n"
    batch_id = hashlib.sha256(payload).hexdigest()
    if json.loads(process.stdout) != {"batch_id": batch_id}:
        raise RuntimeError("native_restart_identity_failed")
    with DurableSpool(restart, clock=lambda: 1000) as spool:
        batches = spool.claim(limit=1)
        if len(batches) != 1 or batches[0].batch_id != batch_id or batches[0].payload != payload:
            raise RuntimeError("native_restart_payload_failed")
        _check_path(restart / "delivery.sqlite3", directory=False)
        try:
            spool.db.execute("BEGIN IMMEDIATE")
            spool.db.execute("UPDATE counters SET value=value+1 WHERE name='enqueued'")
            journal = restart / "delivery.sqlite3-journal"
            if not journal.is_file():
                raise RuntimeError("native_sqlite_journal_missing")
            _check_path(journal, directory=False)
        finally:
            if spool.db.in_transaction:
                spool.db.execute("ROLLBACK")
        if not spool.ack(batches[0]):
            raise RuntimeError("native_restart_ack_failed")
    print("PASS: real process restart preserves exact bytes/ID; database and journal DACLs private")

    for action in ("explicit", "inherited"):
        directory = root / action
        with DurableSpool(directory):
            pass
        database = directory / "delivery.sqlite3"
        fixture_action(action, database if action == "explicit" else directory, root)
        rejected_file(database)
        rejected(directory, "spool_private_acl_required")
        print("PASS: real " + action + " BuiltinUsers file Read rejected")

    parent = root / "writable-parent"
    directory = parent / "spool"
    with DurableSpool(parent):
        pass
    with DurableSpool(directory):
        pass
    fixture_action("writable", parent, root)
    rejected(directory, "spool_unsafe_parent")
    print("PASS: real writable ancestor rejected")

    directory = root / "unsafe-owner"
    with DurableSpool(directory):
        pass
    fixture_action("owner", directory, root)
    rejected(directory, "spool_private_acl_required")
    print("PASS: real unsafe owner rejected")

    parent = root / 'unsafe-ancestor-owner'
    directory = parent / 'private-child'
    with DurableSpool(parent):
        pass
    with DurableSpool(directory):
        pass
    database = directory / 'delivery.sqlite3'
    database.unlink()
    fixture_action('ancestor-owner', parent, root)
    _check_path(directory, directory=True)  # Leaf remains private/current-user-owned.
    rejected(directory, 'spool_unsafe_parent')
    if database.exists():
        raise RuntimeError('native_ancestor_owner_opened_sqlite')
    print('PASS: real unsafe ancestor owner with read-only public ACE rejected before SQLite opens')

    import _winapi

    target = root / "reparse-target"
    with DurableSpool(target):
        pass
    link = root / "reparse-link"
    _winapi.CreateJunction(str(target), str(link))
    try:
        rejected(link, "spool_unsafe_path")
        rejected(link / "nested", "spool_unsafe_path")
    finally:
        link.rmdir()
    print("PASS: real reparse directory and reparse ancestor rejected")


def temporary_root(parent_argument: str | None) -> tuple[Path, Path]:
    # Packaged desktop apps may virtualize LOCALAPPDATA writes into their cache.
    base = parent_argument or os.environ.get("USERPROFILE")
    if not base:
        raise RuntimeError("native_trusted_user_parent_missing")
    parent = Path(os.path.abspath(Path(base).expanduser()))
    checkout = Path(__file__).resolve().parents[1]
    if parent == checkout or checkout in parent.parents or not parent.is_dir():
        raise RuntimeError("native_parent_must_be_outside_checkout")
    root = parent / ("delivery-spool-acl-" + uuid4().hex)
    if root.exists() or root.is_symlink() or root.is_junction():
        raise RuntimeError("native_fixture_already_exists")
    return root, parent


def cleanup(root: Path, parent: Path) -> None:
    absolute = Path(os.path.abspath(root))
    parent_absolute = Path(os.path.abspath(parent))
    if (absolute.parent != parent_absolute or not re.fullmatch(r"delivery-spool-acl-[a-f0-9]{32}", absolute.name)
            or absolute.resolve() != absolute or parent_absolute.resolve() != parent_absolute
            or absolute.is_symlink() or absolute.is_junction()):
        raise RuntimeError("unsafe_native_fixture_cleanup_path")

    def remove(directory: Path) -> None:
        for child in directory.iterdir():
            if child.is_symlink():
                child.unlink()
            elif child.is_junction():
                child.rmdir()
            elif child.is_dir():
                remove(child)
            else:
                child.unlink()
        directory.rmdir()

    if absolute.exists():
        remove(absolute)
    if absolute.exists():
        raise RuntimeError("native_fixture_cleanup_incomplete")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temporary-parent", help="Trusted private user parent outside the checkout")
    arguments = parser.parse_args(argv)
    if os.name != "nt":
        print("delivery_spool_acl_smoke unsupported: native Windows required", file=sys.stderr)
        return 2
    modules_before = os.environ.get("PSModulePath")
    root = parent = None
    result = 1
    try:
        root, parent = temporary_root(arguments.temporary_parent)
        verify(root)
        result = 0
    except SpoolError as error:
        print("delivery_spool_acl_smoke failed: " + str(error), file=sys.stderr)
    except RuntimeError as error:
        print("delivery_spool_acl_smoke failed: " + str(error), file=sys.stderr)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("delivery_spool_acl_smoke failed: native runtime or filesystem error", file=sys.stderr)
    finally:
        if root is not None and parent is not None:
            try:
                cleanup(root, parent)
            except (RuntimeError, OSError):
                print("delivery_spool_acl_smoke failed: scoped cleanup error", file=sys.stderr)
                result = 1
        if os.environ.get("PSModulePath") != modules_before:
            print("delivery_spool_acl_smoke failed: parent module environment changed", file=sys.stderr)
            result = 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
