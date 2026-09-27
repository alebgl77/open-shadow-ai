<#
.SYNOPSIS
Operator-run local endpoint install, suitable for a pilot GPO startup script.
.DESCRIPTION
Does not create or link GPOs. Requires an approved Python installation, trusted offline
wheelhouse and separately provisioned API key. Review and sign before fleet rollout.

Everything the scheduled task later runs as SYSTEM must stay writable only by SYSTEM,
Administrators or TrustedInstaller: the install directory is created with a protected ACL
and must not already exist, and the Python home, wheelhouse and every parent directory
are checked before use.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][string]$WheelPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$WheelSha256,
    [Parameter(Mandatory)][string]$Wheelhouse,
    [Parameter(Mandatory)][string]$ApiKeyFile,
    [Parameter(Mandatory)][uri]$ServerUrl,
    [string]$InstallDirectory = (Join-Path $env:ProgramData 'OpenShadowAI')
)
$ErrorActionPreference = 'Stop'

$trustedSids = @(
    'S-1-5-18'      # LocalSystem
    'S-1-5-32-544'  # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # NT SERVICE\TrustedInstaller
)
$creatorOwner = 'S-1-3-0'
# Rights that let a principal alter content below a directory.
$writeRights = [Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
# Rights on a parent directory that let a principal rename, replace or re-permission a path.
$replaceRights = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
$genericWriteMask = 0x50000000  # GENERIC_ALL | GENERIC_WRITE, as found on inherit-only ACEs

function Get-UntrustedGrant {
    param([string]$Path, [Security.AccessControl.FileSystemRights]$Rights, [switch]$IncludeInherited)
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trustedSids) { return "owner $owner" }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        # CREATOR OWNER only reaches objects created by a principal that already holds create rights.
        if ($rule.AccessControlType -ne 'Allow' -or $sid -in $trustedSids -or $sid -eq $creatorOwner) { continue }
        $inheritOnly = ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        if ($inheritOnly -and -not $IncludeInherited) { continue }
        $mask = [int64]$rule.FileSystemRights
        if (($mask -band [int64]$Rights) -or ($mask -band $genericWriteMask)) { return "$sid $($rule.FileSystemRights)" }
    }
}

function Assert-PathNotReplaceable {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    while ($item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point in trusted path: $($item.FullName)" }
        $grant = Get-UntrustedGrant -Path $item.FullName -Rights $replaceRights
        if ($grant) { throw "$($item.FullName) can be replaced by a non-administrative principal ($grant)." }
        $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
    }
}

function Assert-AdministrativeContent {
    param([string]$Path, [switch]$Recurse)
    Assert-PathNotReplaceable $Path
    $items = @(Get-Item -LiteralPath $Path -Force)
    if ($Recurse) { $items += @(Get-ChildItem -LiteralPath $Path -Force -Recurse) }
    foreach ($item in $items) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point in trusted path: $($item.FullName)" }
        $grant = Get-UntrustedGrant -Path $item.FullName -Rights $writeRights -IncludeInherited
        if ($grant) { throw "$($item.FullName) is writable by a non-administrative principal ($grant)." }
    }
}

function New-ProtectedDirectory {
    param([string]$Path)
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]$sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    # The ACL is part of the creation call: there is no window with inherited ProgramData permissions.
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security)
    } else {
        [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    }
    # Both APIs silently accept an existing directory; detect a concurrent pre-creation.
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $unexpected = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -notin 'S-1-5-18', 'S-1-5-32-544' })
    if ($owner -notin 'S-1-5-18', 'S-1-5-32-544' -or -not $acl.AreAccessRulesProtected -or $unexpected.Count -or
        (Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)) {
        throw "$Path was not created with the expected protected ACL. Remove it and investigate before retrying."
    }
}

if ($ServerUrl.Scheme -ne 'https' -or $ServerUrl.UserInfo -or $ServerUrl.Query -or $ServerUrl.Fragment) { throw 'ServerUrl must be HTTPS without embedded credentials.' }
$resolvedWheel = (Resolve-Path -LiteralPath $WheelPath).Path
if ((Get-FileHash -LiteralPath $resolvedWheel -Algorithm SHA256).Hash -ne $WheelSha256) { throw 'Agent package SHA256 mismatch.' }
$resolvedWheelhouse = (Resolve-Path -LiteralPath $Wheelhouse).Path
$target = [IO.Path]::GetFullPath($InstallDirectory)
if (-not $PSCmdlet.ShouldProcess($target, 'Install agent locally and register an at-startup scheduled task')) { return }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as an administrator on the target pilot computer.' }
if (Test-Path -LiteralPath $target) { throw "$target already exists. Use your reviewed upgrade procedure, or remove the directory after review; an existing directory is never reused." }
$parent = [IO.Path]::GetDirectoryName($target)
if (-not $parent -or -not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'The parent of InstallDirectory must be an existing directory.' }
Assert-PathNotReplaceable $parent
# Dependencies are installed from here and later imported by SYSTEM.
Assert-AdministrativeContent $resolvedWheelhouse -Recurse

New-ProtectedDirectory $target
# Hash the protected copy that pip installs, not a file a user could swap after the check.
$staging = Join-Path $target 'staging'
[IO.Directory]::CreateDirectory($staging) | Out-Null
$stagedWheel = Join-Path $staging ([IO.Path]::GetFileName($resolvedWheel))
Copy-Item -LiteralPath $resolvedWheel -Destination $stagedWheel
if ((Get-FileHash -LiteralPath $stagedWheel -Algorithm SHA256).Hash -ne $WheelSha256) { throw 'Agent package SHA256 mismatch after copy.' }

$venv = Join-Path $target 'venv'
& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
# A Windows virtual environment loads the interpreter and standard library from its base installation.
$pythonHome = (Get-Content -LiteralPath (Join-Path $venv 'pyvenv.cfg') | Where-Object { $_ -match '^\s*home\s*=' } |
    Select-Object -First 1) -replace '^\s*home\s*=\s*', ''
if (-not $pythonHome -or -not (Test-Path -LiteralPath $pythonHome -PathType Container)) { throw 'Could not resolve the base Python installation.' }
Assert-AdministrativeContent $pythonHome
$agentPython = Join-Path $venv 'Scripts/python.exe'
& $agentPython -m pip install --no-index --find-links $resolvedWheelhouse $stagedWheel
if ($LASTEXITCODE -ne 0) { throw 'Offline agent installation failed.' }
Remove-Item -LiteralPath $staging -Recurse -Force

$key = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ApiKeyFile)).Trim()
if ($key.Length -lt 32) { throw 'Invalid API key.' }
[IO.File]::WriteAllText((Join-Path $target 'agent-key.txt'), $key, [Text.UTF8Encoding]::new($false))
$key = $null
$config = @"
server_url: '$($ServerUrl.AbsoluteUri.TrimEnd('/'))'
poll_interval_seconds: 300
collect_processes: true
collect_containers: false
collect_extensions: true
collect_local_ai: true
"@
[IO.File]::WriteAllText((Join-Path $target 'shadai-agent.yaml'), $config, [Text.UTF8Encoding]::new($false))
$runner = @'
$ErrorActionPreference = 'Stop'
$env:SHADAI_AGENT_CONFIG = Join-Path $PSScriptRoot 'shadai-agent.yaml'
$env:AGENT_API_KEY_FILE = Join-Path $PSScriptRoot 'agent-key.txt'
& (Join-Path $PSScriptRoot 'venv/Scripts/python.exe') -m shadai_agent.main
exit $LASTEXITCODE
'@
$runnerPath = Join-Path $target 'Run-Agent.ps1'
[IO.File]::WriteAllText($runnerPath, $runner, [Text.UTF8Encoding]::new($false))
# Whoever created them, every installed file inherits only the protected root ACL and belongs to Administrators.
& icacls.exe (Join-Path $target '*') /reset /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not reset installation ACLs.' }
& icacls.exe $target /setowner '*S-1-5-32-544' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not set installation ownership.' }
# Final gate: nothing the task executes may have gained a non-administrative writer.
Assert-AdministrativeContent $target -Recurse
$taskPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$taskArguments = '-NoProfile -NonInteractive -File "' + $runnerPath + '"'
$action = New-ScheduledTaskAction -Execute $taskPowerShell -Argument $taskArguments -WorkingDirectory $target
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'OpenShadowAI-Agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Write-Output 'Installed locally. Start OpenShadowAI-Agent after reviewing configuration and verify its reporting in the console.'
