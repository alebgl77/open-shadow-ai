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
# bootstrap.py performs the Windows owner/DACL/reparse checks before generating secrets.
