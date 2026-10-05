# Called before secret generation, including direct bootstrap.py invocations on Windows.
[CmdletBinding()]
param([string]$Directory)
$ErrorActionPreference = 'Stop'

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trustedSids = @($currentSid, 'S-1-5-18', 'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$replaceRights = [Security.AccessControl.FileSystemRights]'Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership, CreateFiles, WriteAttributes'

function Assert-SafePath {
    param([string]$Path, [switch]$Private)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing reparse point: $Path. Choose a real, private directory."
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trustedSids) {
        throw "Untrusted owner $owner on $Path. Use a directory owned by the current user or a trusted system principal."
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trustedSids) { continue }
        $inheritOnly = ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        # CreateFiles/WriteAttributes can turn an empty ancestor into a reparse point.
        # CreateDirectories alone is common on Windows roots and cannot perform that conversion.
        if (-not $Private -and $inheritOnly) { continue }
        $mask = [int64]$rule.FileSystemRights
        if ($Private -or ($mask -band [int64]$replaceRights) -or ($mask -band 0x50000000)) {
            throw "Unsafe ACL on $Path ($($rule.IdentityReference.Value): $($rule.FileSystemRights)). Review access and use a private directory before retrying."
        }
    }
}

function New-PrivateDirectory {
    param([string]$Path)
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]$currentSid)
    foreach ($sid in $currentSid, 'S-1-5-18') {
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]$sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    # Supply the DACL at creation: there is no interval with inherited public permissions.
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -AssemblyName System.IO.FileSystem.AccessControl
        [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($Path), $security)
    } else {
        [IO.Directory]::CreateDirectory($Path, $security) | Out-Null
    }
    # CreateDirectory accepts an existing path, so also catch concurrent unsafe pre-creation.
    Assert-SafePath -Path $Path -Private
}

function Initialize-PrivateBootstrap {
    param([Parameter(Mandatory)][string]$Directory)
    $destination = [IO.Path]::GetFullPath($Directory)
    $missing = [Collections.Generic.List[string]]::new()
    $ancestor = [IO.DirectoryInfo]::new($destination)
    while ($ancestor -and -not (Test-Path -LiteralPath $ancestor.FullName)) {
        $missing.Add($ancestor.FullName)
        $ancestor = $ancestor.Parent
    }
    if (-not $ancestor) { throw 'No existing parent directory was found.' }
    $existing = $ancestor
    while ($ancestor) {
        Assert-SafePath $ancestor.FullName
        $ancestor = $ancestor.Parent
    }
    if (-not (Test-Path -LiteralPath $existing.FullName -PathType Container)) { throw 'The deployment parent must be a directory.' }
    for ($index = $missing.Count - 1; $index -ge 0; $index--) { New-PrivateDirectory $missing[$index] }

    $secretPath = Join-Path $destination 'secrets'
    if (-not (Test-Path -LiteralPath $secretPath)) { New-PrivateDirectory $secretPath }
    Assert-SafePath -Path $secretPath -Private
    if (-not (Test-Path -LiteralPath $secretPath -PathType Container)) { throw 'The secrets path must be a directory.' }
    # Enumerate one level at a time only after rejecting a reparse directory; never follow a junction.
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($secretPath)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            Assert-SafePath -Path $item.FullName -Private
            if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') { Initialize-PrivateBootstrap -Directory $Directory }
