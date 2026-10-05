"""Real Windows key-file DACL verification using ephemeral synthetic credentials.

This deliberately exercises the production guard and complete read_api_key boundary.
No real credential is read, no value is printed, and ACL changes stay in one new
workspace/tmp directory. Non-Windows hosts are explicitly unsupported.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from shadai.collectors.network import _private_windows_key, read_api_key

_FIXTURE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($env:SHADAI_NETWORK_ACL_SMOKE_ROOT)
$parent = [IO.Path]::GetFullPath($env:SHADAI_NETWORK_ACL_SMOKE_PARENT)
if ([IO.Path]::GetDirectoryName($root) -ne $parent -or
    [IO.Path]::GetFileName($root) -notmatch '^network-key-acl-[a-f0-9]{32}$') { exit 10 }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$publicSid = [Security.Principal.SecurityIdentifier]'S-1-5-32-545'
$private = Join-Path $root 'private.key'
$inherited = Join-Path $root 'inherited.key'
switch ($env:SHADAI_NETWORK_ACL_SMOKE_ACTION) {
    'setup' {
        if (Test-Path -LiteralPath $root) { exit 11 }
        $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
        $directoryAcl.SetAccessRuleProtection($true, $false)
        $directoryAcl.SetOwner($sid)
        foreach ($identity in $sid, [Security.Principal.SecurityIdentifier]'S-1-5-18') {
            $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
        }
        [IO.Directory]::CreateDirectory($root, $directoryAcl) | Out-Null
        $fileAcl = [Security.AccessControl.FileSecurity]::new()
        $fileAcl.SetAccessRuleProtection($true, $false)
        $fileAcl.SetOwner($sid)
        foreach ($identity in $sid, [Security.Principal.SecurityIdentifier]'S-1-5-18') {
            $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $identity, 'FullControl', 'Allow'))
        }
        [IO.File]::Create($private, 4096, [IO.FileOptions]::None, $fileAcl).Dispose()
        $actual = Get-Acl -LiteralPath $private
        if (-not $actual.AreAccessRulesProtected -or
            $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { exit 12 }
        foreach ($rule in $actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -notin @($sid.Value, 'S-1-5-18') -or
                $rule.AccessControlType -ne 'Allow') { exit 13 }
        }
    }
    'explicit' {
        & icacls.exe $private /grant '*S-1-5-32-545:R' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 14 }
        $actual = Get-Acl -LiteralPath $private
        $broad = @($actual.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and $_.AccessControlType -eq 'Allow' })
        if (-not $actual.AreAccessRulesProtected -or $broad.Count -ne 1 -or
            -not ($broad[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)) { exit 15 }
    }
    'inherited' {
        & icacls.exe $root /grant '*S-1-5-32-545:(OI)(CI)R' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { exit 16 }
        [IO.File]::Create($inherited).Dispose()
        $actual = Get-Acl -LiteralPath $inherited
        $broad = @($actual.GetAccessRules($false, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $publicSid.Value -and $_.AccessControlType -eq 'Allow' })
        if ($actual.AreAccessRulesProtected -or $broad.Count -ne 1 -or -not $broad[0].IsInherited -or
            -not ($broad[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData)) { exit 17 }
    }
    default { exit 18 }
}
exit 0
"""


def fixture_action(action: str, root: Path) -> None:
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    environment = os.environ.copy()
    # Fixture construction runs in native PS5 independently of the caller's PS7
    # module paths; the production guard itself receives its real environment.
    environment["PSModulePath"] = str(powershell.parent / "Modules")
    environment["SHADAI_NETWORK_ACL_SMOKE_ROOT"] = str(root)
    environment["SHADAI_NETWORK_ACL_SMOKE_PARENT"] = str(root.parent)
    environment["SHADAI_NETWORK_ACL_SMOKE_ACTION"] = action
    result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", _FIXTURE_SCRIPT],
                            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                            check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("native_fixture_" + action + "_failed_" + str(result.returncode))


def verify_rejected(path: Path) -> None:
    if _private_windows_key(path):
        raise RuntimeError("public_key_guard_accepted")
    try:
        read_api_key(str(path))
    except ValueError as error:
        if str(error) != "API key file must have a private Windows ACL":
            raise RuntimeError("public_key_boundary_wrong_error") from None
    else:
        raise RuntimeError("public_key_boundary_accepted")


def cleanup(root: Path, parent: Path) -> None:
    # Delete only two named fixture files and the verified newly owned directory.
    # No recursive removal or cross-shell filesystem commands are involved.
    if root.resolve().parent != parent.resolve() or not root.name.startswith("network-key-acl-"):
        raise RuntimeError("unsafe_native_fixture_cleanup_path")
    for name in ("private.key", "inherited.key"):
        target = root / name
        if target.exists():
            if target.resolve().parent != root.resolve():
                raise RuntimeError("unsafe_native_fixture_cleanup_file")
            target.unlink()
    if root.exists():
        root.rmdir()


def main() -> int:
    if os.name != "nt":
        print("network_key_acl_smoke unsupported: real Windows DACLs required", file=sys.stderr)
        return 2
    parent = (Path(__file__).resolve().parents[1] / "tmp").resolve()
    parent.mkdir(exist_ok=True)
    root = parent / ("network-key-acl-" + uuid4().hex)
    result = 1
    try:
        fixture_action("setup", root)
        private = root / "private.key"
        synthetic = secrets.token_hex(16)
        private.write_text(synthetic, encoding="utf-8")
        if not _private_windows_key(private):
            raise RuntimeError("private_key_guard_rejected")
        if not secrets.compare_digest(read_api_key(str(private)), synthetic):
            raise RuntimeError("private_key_boundary_failed")
        print("PASS: real private Windows DACL guard and key-read boundary")
        fixture_action("explicit", root)
        verify_rejected(private)
        print("PASS: real explicit BuiltinUsers Read DACL rejected by guard and boundary")
        fixture_action("inherited", root)
        inherited = root / "inherited.key"
        inherited.write_text(synthetic, encoding="utf-8")
        verify_rejected(inherited)
        print("PASS: real inherited BuiltinUsers Read DACL rejected by guard and boundary")
        result = 0
    except RuntimeError as error:
        print("network_key_acl_smoke failed: " + str(error), file=sys.stderr)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("network_key_acl_smoke failed: native runtime or filesystem permission error", file=sys.stderr)
    finally:
        try:
            cleanup(root, parent)
        except (RuntimeError, OSError):
            print("network_key_acl_smoke failed: scoped fixture cleanup error", file=sys.stderr)
            result = 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
