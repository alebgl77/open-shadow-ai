[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Directory = (Split-Path -Parent $PSScriptRoot),
    [string]$Python = 'python',
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$arguments = @((Join-Path $PSScriptRoot 'bootstrap.py'), '--directory', $Directory)
if ($DryRun -or $WhatIfPreference) { $arguments += '--dry-run' }
& $Python @arguments
if ($LASTEXITCODE -ne 0) { throw 'Bootstrap failed.' }
if (-not ($DryRun -or $WhatIfPreference) -and $env:OS -eq 'Windows_NT') {
    $secretPath = Join-Path ([IO.Path]::GetFullPath($Directory)) 'secrets'
    $principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $secretPath /inheritance:r /grant:r "${principal}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the secrets directory ACL.' }
}
