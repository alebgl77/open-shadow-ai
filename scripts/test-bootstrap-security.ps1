[CmdletBinding()]
param([string]$Python = 'python', [switch]$BoundaryOnly)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'These tests require real Windows filesystem ACLs.' }
. (Join-Path $PSScriptRoot 'Protect-BootstrapWindows.ps1')

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Refused {
    param([scriptblock]$Action, [string]$Pattern)
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        return
    }
    throw "Expected refusal: $Pattern"
}
function Add-PublicRule {
    param([string]$Path, [string]$Rights = 'Read')
    # Set-Acl also requests SACL privileges on some hosts. icacls changes only this fixture's DACL.
    $flags = switch ($Rights) {
        'Read' { 'R' }
        'FullControl' { 'F' }
        'CreateDirectories' { '(AD)' }
        'CreateFiles' { '(WD)' }
        'WriteAttributes' { '(WA)' }
        'DeleteSubdirectoriesAndFiles' { '(DC)' }
        default { throw "Unsupported test right: $Rights" }
    }
    & icacls.exe $Path /grant ('*S-1-1-0:' + $flags) /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the adverse fixture DACL.' }
    $actual = @((Get-Acl -LiteralPath $Path).GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
        Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and $_.AccessControlType -eq 'Allow' })
    $expected = [Security.AccessControl.FileSystemRights]$Rights
    Assert-True (@($actual | Where-Object { ($_.FileSystemRights -band $expected) -eq $expected }).Count -gt 0) 'Adverse ACE missing.'
}

$workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$temporary = Join-Path $workspace 'tmp'
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$testRoot = Join-Path $temporary ('bootstrap-security-' + [guid]::NewGuid().ToString('N'))
$junctions = [Collections.Generic.List[string]]::new()
New-PrivateDirectory $testRoot
try {
    $fresh = Join-Path $testRoot 'fresh'
    New-PrivateDirectory $fresh
    $acl = Get-Acl -LiteralPath $fresh
    Assert-True $acl.AreAccessRulesProtected 'New directory must disable inheritance.'
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $currentSid) 'Wrong owner.'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-True ($rules.Count -eq 2) 'New directory must have exactly two trusted grants.'
    Assert-SafePath -Path $fresh -Private
    New-PrivateDirectory $fresh
    Assert-SafePath -Path $fresh -Private

    $unsafe = Join-Path $testRoot 'public'
    New-PrivateDirectory $unsafe
    Add-PublicRule $unsafe
    Assert-Refused { Assert-SafePath -Path $unsafe -Private } 'Unsafe ACL'
    # A dangerous explicit ACE remains dangerous after inheritance is disabled.
    Assert-True (Get-Acl -LiteralPath $unsafe).AreAccessRulesProtected 'Fixture must use explicit ACEs.'
    $file = Join-Path $fresh 'existing.txt'
    [IO.File]::WriteAllText($file, 'preserve-existing-content')
    Assert-SafePath -Path $file -Private
    New-PrivateDirectory $fresh
    Assert-True ([IO.File]::ReadAllText($file) -eq 'preserve-existing-content') 'Safe repeat changed existing content.'
    Add-PublicRule $file 'FullControl'
    Assert-Refused { Assert-SafePath -Path $file -Private } 'Unsafe ACL'

    # Read a genuine owner SID from the filesystem, then classify it as a foreign principal.
    # This exercises owner rejection without SeRestorePrivilege or creating a local account.
    $savedTrust = $trustedSids
    try {
        $trustedSids = @('S-1-5-18')
        Assert-Refused { Assert-SafePath -Path $fresh -Private } 'Untrusted owner'
    } finally { $trustedSids = $savedTrust }

    $ancestor = Join-Path $testRoot 'ancestor'
    New-PrivateDirectory $ancestor
    Add-PublicRule $ancestor 'CreateDirectories'
    Assert-SafePath $ancestor
    Add-PublicRule $ancestor 'DeleteSubdirectoriesAndFiles'
    Assert-Refused { Assert-SafePath $ancestor } 'Unsafe ACL'
    foreach ($right in 'CreateFiles', 'WriteAttributes') {
        $reparseAncestor = Join-Path $testRoot ('ancestor-' + $right)
        New-PrivateDirectory $reparseAncestor
        Add-PublicRule $reparseAncestor $right
        Assert-Refused { Assert-SafePath $reparseAncestor } 'Unsafe ACL'
    }

    $outside = Join-Path $testRoot 'junction-target'
    New-PrivateDirectory $outside
    $link = Join-Path $testRoot 'junction'
    New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
    $junctions.Add($link)
    Assert-Refused { Assert-SafePath -Path $link -Private } 'reparse point'
    Assert-True (@(Get-ChildItem -LiteralPath $outside -Force).Count -eq 0) 'Junction target changed.'
    Write-Output 'PASS: real Windows creation DACL, safe repeat, explicit directory/file ACE rejection, owner classification, ancestor rights and junction refusal.'

    if (-not $BoundaryOnly) {
        $deployment = Join-Path $testRoot 'deployment'
        & (Join-Path $PSScriptRoot 'bootstrap.ps1') -Directory $deployment -Python $Python -DryRun
        Assert-True (-not (Test-Path -LiteralPath $deployment)) 'Dry run created the destination.'
        & (Join-Path $PSScriptRoot 'bootstrap.ps1') -Directory $deployment -Python $Python
        $secrets = Join-Path $deployment 'secrets'
        $before = @(Get-ChildItem -LiteralPath $secrets -File | Get-FileHash | ForEach-Object Hash)
        Assert-True ($before.Count -eq 6) 'Expected six secrets.'
        & (Join-Path $PSScriptRoot 'bootstrap.ps1') -Directory $deployment -Python $Python
        $after = @(Get-ChildItem -LiteralPath $secrets -File | Get-FileHash | ForEach-Object Hash)
        Assert-True (($before -join ',') -eq ($after -join ',')) 'Repeat changed secret bytes.'
        Get-ChildItem -LiteralPath $secrets -File | ForEach-Object { Assert-SafePath -Path $_.FullName -Private }
        $badDeployment = Join-Path $testRoot 'bad-deployment'
        New-PrivateDirectory $badDeployment
        $badSecrets = Join-Path $badDeployment 'secrets'
        New-PrivateDirectory $badSecrets
        Add-PublicRule $badSecrets
        Assert-Refused { & (Join-Path $PSScriptRoot 'bootstrap.ps1') -Directory $badDeployment -Python $Python } 'Bootstrap failed'
        Assert-True (@(Get-ChildItem -LiteralPath $badSecrets -Force).Count -eq 0) 'Unsafe directory received secrets.'
        Write-Output 'PASS: complete bootstrap dry run, six private secrets, preservation and refusal before generation.'
    } else {
        Write-Output 'LIMIT: BoundaryOnly skips complete bootstrap; ancestor ownership/DACL trust must be verified in Windows CI.'
    }
} finally {
    # Delete only this generated workspace fixture; remove junction links before recursive cleanup.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($temporary + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing cleanup outside the workspace temporary directory.'
    }
    foreach ($junction in $junctions) { [IO.Directory]::Delete($junction) }
    Get-ChildItem -LiteralPath $resolved -Recurse -File -Force | ForEach-Object { $_.IsReadOnly = $false }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
