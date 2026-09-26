<#
.SYNOPSIS
Operator-run local endpoint install, suitable for a pilot GPO startup script.
.DESCRIPTION
Does not create or link GPOs. Requires an approved Python installation, trusted offline
wheelhouse and separately provisioned API key. Review and sign before fleet rollout.
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
if ($ServerUrl.Scheme -ne 'https' -or $ServerUrl.UserInfo -or $ServerUrl.Query -or $ServerUrl.Fragment) { throw 'ServerUrl must be HTTPS without embedded credentials.' }
$resolvedWheel = (Resolve-Path -LiteralPath $WheelPath).Path
if ((Get-FileHash -LiteralPath $resolvedWheel -Algorithm SHA256).Hash -ne $WheelSha256) { throw 'Agent package SHA256 mismatch.' }
$target = [IO.Path]::GetFullPath($InstallDirectory)
if (-not $PSCmdlet.ShouldProcess($target, 'Install agent locally and register an at-startup scheduled task')) { return }
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as an administrator on the target pilot computer.' }
if (Test-Path -LiteralPath (Join-Path $target 'shadai-agent.yaml')) { throw 'Existing installation detected. Use your reviewed upgrade procedure; configuration is preserved.' }
[IO.Directory]::CreateDirectory($target) | Out-Null
& icacls.exe $target /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict installation ACL.' }
$venv = Join-Path $target 'venv'
& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
$agentPython = Join-Path $venv 'Scripts/python.exe'
& $agentPython -m pip install --no-index --find-links $Wheelhouse $resolvedWheel
if ($LASTEXITCODE -ne 0) { throw 'Offline agent installation failed.' }
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
$taskPowerShell = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$taskArguments = '-NoProfile -NonInteractive -File "' + $runnerPath + '"'
$action = New-ScheduledTaskAction -Execute $taskPowerShell -Argument $taskArguments -WorkingDirectory $target
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'OpenShadowAI-Agent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Write-Output 'Installed locally. Start OpenShadowAI-Agent after reviewing configuration and verify its reporting in the console.'
