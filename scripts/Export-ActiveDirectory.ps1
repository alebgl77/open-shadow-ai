<#
.SYNOPSIS
Export scoped AD computer/user inventory to immutable JSON batches; optionally upload over HTTPS.
.DESCRIPTION
Requires RSAT ActiveDirectory and directory read permissions. Reads no password, group membership,
mail, recovery-key or credential attributes. Inventory is not proof of AI use. -WhatIf performs no query.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ValidateScript({ foreach ($scope in $_) { if ($scope -notmatch '^OU=.+,DC=') { throw 'Each scope must be an OU distinguished name, not the domain root.' } }; $true })]
    [string[]]$SearchBase,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateSet('Computers','Users')][string[]]$ObjectTypes = @('Computers','Users'),
    [ValidateRange(1,500)][int]$BatchSize = 500,
    [ValidatePattern('^[A-Za-z0-9_.-]{1,100}$')][string]$TenantId = 'default',
    [ValidateNotNullOrEmpty()][string]$CollectorId = 'active-directory',
    [string]$Server,
    [switch]$Upload,
    [uri]$ApiUrl,
    [string]$ApiKeyFile = $env:AGENT_API_KEY_FILE
)
$ErrorActionPreference = 'Stop'
if ($Upload -and (-not $ApiUrl -or $ApiUrl.Scheme -ne 'https' -or $ApiUrl.UserInfo -or $ApiUrl.Query -or $ApiUrl.Fragment)) {
    throw 'Upload requires an HTTPS origin without credentials, query or fragment.'
}
if (-not $PSCmdlet.ShouldProcess(($SearchBase -join '; '), 'Read AD inventory, write private JSON batches and optionally upload')) { return }
Import-Module ActiveDirectory -ErrorAction Stop
$apiKey = $null
if ($Upload) {
    $apiKey = if ($ApiKeyFile) { [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ApiKeyFile)).Trim() } else { $env:AGENT_API_KEY }
    if (-not $apiKey -or $apiKey.Length -lt 32) { throw 'Set AGENT_API_KEY or AGENT_API_KEY_FILE to the deployment collector key.' }
    # Platform certificate validation remains enabled. No insecure certificate callback or bypass.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
$runId = [guid]::NewGuid().ToString()
$runDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) $runId
[IO.Directory]::CreateDirectory($runDirectory) | Out-Null
if ($env:OS -eq 'Windows_NT') {
    $principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $runDirectory /inheritance:r /grant:r "${principal}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure inventory output directory.' }
}
$observedAt = [DateTimeOffset]::UtcNow.ToString('o')
$seen = [Collections.Generic.HashSet[string]]::new()
$batch = [Collections.Generic.List[object]]::new()
$script:batchNumber = 0
$script:eventCount = 0

function Save-InventoryBatch {
    param([Collections.Generic.List[object]]$Events)
    if ($Events.Count -eq 0) { return }
    $script:batchNumber++
    $payload = @{ events = @($Events.ToArray()) } | ConvertTo-Json -Depth 8
    $path = Join-Path $runDirectory ('batch-{0:D6}.json' -f $script:batchNumber)
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    if ($Upload) {
        $endpoint = $ApiUrl.AbsoluteUri.TrimEnd('/') + '/api/v1/ingest/events'
        $sent = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                # Redirects disabled: a redirect must never forward a collector credential.
                $null = Invoke-RestMethod -Method Post -Uri $endpoint -Headers @{'X-API-Key' = $apiKey} -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 60 -MaximumRedirection 0
                $sent = $true
                break
            } catch {
                if ($attempt -lt 3) { Start-Sleep -Seconds ($attempt * 2) }
            }
        }
        if (-not $sent) { throw "Upload failed. Retry the unchanged batch saved at $path; event IDs must be preserved." }
    }
    $script:eventCount += $Events.Count
    $Events.Clear()
}

foreach ($scope in $SearchBase) {
    $query = @{Filter = '*'; SearchBase = $scope; SearchScope = 'Subtree'; ResultPageSize = $BatchSize; ErrorAction = 'Stop'}
    if ($Server) { $query.Server = $Server }
    foreach ($kind in $ObjectTypes) {
        $objects = if ($kind -eq 'Computers') {
            Get-ADComputer @query -Properties ObjectGUID, SID, DNSHostName, SamAccountName
        } else {
            Get-ADUser @query -Properties ObjectGUID, SID, SamAccountName
        }
        foreach ($item in $objects) {
            $objectId = $item.ObjectGUID.ToString()
            if (-not $seen.Add($objectId)) { continue }
            $stableId = 'ad:' + $objectId
            $event = @{
                event_id = [guid]::NewGuid().ToString()
                timestamp = $observedAt
                source_type = 'directory'
                evidence_type = 'inventory'
                tenant_id = $TenantId
                collector_id = $CollectorId
                identity_provider = 'active_directory'
                identity_object_id = $objectId
                identity_sid = [string]$item.SID
                device_id = ''
                hostname = ''
                user_id = ''
                username = ''
            }
            if ($kind -eq 'Computers') {
                $event.device_id = $stableId
                $event.hostname = if ($item.DNSHostName) { [string]$item.DNSHostName } else { [string]$item.Name }
            } else {
                $event.user_id = $stableId
                $event.username = [string]$item.SamAccountName
            }
            $batch.Add($event)
            if ($batch.Count -ge $BatchSize) { Save-InventoryBatch $batch }
        }
    }
}
Save-InventoryBatch $batch
$apiKey = $null
Write-Output ("Exported {0} inventory objects in {1} batches to {2}" -f $script:eventCount, $script:batchNumber, $runDirectory)
