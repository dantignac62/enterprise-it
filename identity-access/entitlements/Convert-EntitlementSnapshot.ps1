<#
.SYNOPSIS
    Convert raw entitlement snapshots into normalized role-definition files.

.DESCRIPTION
    Reads per-department snapshot JSONs (e.g., Sales.json) emitted by the
    RBAC template-account export, groups users by JobTitle, merges group
    memberships per the chosen strategy, and writes one role file per
    (department, JobTitle) pair to the output directory.

    The output conforms to schema/role.schema.json. M365 license SKUs are
    conferred via group-based licensing on entries in SecurityGroups[];
    they are not enumerated as a separate field.

.PARAMETER SnapshotDir
    Directory containing the raw snapshot JSONs. Defaults to the script's
    own directory (entitlements/).

.PARAMETER OutputDir
    Directory to write normalized role files into. Defaults to
    <SnapshotDir>/roles. Created if missing.

.PARAMETER MergeStrategy
    How to combine entitlements when multiple template users share a JobTitle.
    'intersection' (default) keeps only groups every template has.
    'union' keeps any group at least one template has.
    Single-template roles always use 'single' regardless of this flag.

.EXAMPLE
    pwsh ./Convert-EntitlementSnapshot.ps1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$SnapshotDir = $PSScriptRoot,
    [string]$OutputDir   = (Join-Path $PSScriptRoot 'roles'),
    [ValidateSet('intersection','union')]
    [string]$MergeStrategy = 'intersection'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SchemaVersion = '1.0'

# ---------- Helpers ----------

function ConvertTo-Slug {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)
    $s = $Text -replace '&','And'
    $s = $s -replace '[^A-Za-z0-9]+','_'
    $s = $s.Trim('_')
    if ([string]::IsNullOrEmpty($s)) {
        throw "Cannot derive slug from '$Text'"
    }
    return $s
}

function Get-GitSha {
    [CmdletBinding()]
    param([string]$Path = $PSScriptRoot)
    try {
        Push-Location $Path
        $sha = & git rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $sha) { return $sha.Trim() }
    } catch {
        # fall through
    } finally {
        Pop-Location
    }
    return 'unknown'
}

function Get-SetIntersection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Sets)
    if ($Sets.Count -eq 0) { return ,[string[]]@() }
    $result = [System.Collections.Generic.HashSet[string]]::new([string[]]$Sets[0])
    for ($i = 1; $i -lt $Sets.Count; $i++) {
        $other = [System.Collections.Generic.HashSet[string]]::new([string[]]$Sets[$i])
        [void]$result.IntersectWith($other)
    }
    return ,[string[]]@($result)
}

function Get-SetUnion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Sets)
    $result = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($s in $Sets) {
        foreach ($e in $s) { [void]$result.Add($e) }
    }
    return ,[string[]]@($result)
}

function Get-VarianceItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Sets,
        [Parameter(Mandatory)][string[]]$Sams,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Merged
    )
    if ($Sets.Count -ne $Sams.Count) {
        throw "Sets/Sams index alignment broken: $($Sets.Count) sets vs $($Sams.Count) sams"
    }
    $mergedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$Merged)
    $variant   = [ordered]@{}
    for ($i = 0; $i -lt $Sets.Count; $i++) {
        foreach ($dn in $Sets[$i]) {
            if (-not $mergedSet.Contains($dn)) {
                if (-not $variant.Contains($dn)) { $variant[$dn] = [System.Collections.Generic.List[string]]::new() }
                if (-not $variant[$dn].Contains($Sams[$i])) { $variant[$dn].Add($Sams[$i]) }
            }
        }
    }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($k in ($variant.Keys | Sort-Object)) {
        $items.Add([ordered]@{
            dn        = $k
            presentIn = [string[]]@($variant[$k] | Sort-Object)
        })
    }
    return ,[object[]]$items.ToArray()
}

# ---------- Conversion ----------

if (-not (Test-Path -LiteralPath $SnapshotDir)) {
    throw "SnapshotDir not found: $SnapshotDir"
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$generatedBy = '{0}@{1}' -f (Split-Path -Leaf $PSCommandPath), (Get-GitSha)
$generatedAt = (Get-Date).ToUniversalTime().ToString('o')

$snapshots = Get-ChildItem -LiteralPath $SnapshotDir -Filter '*.json' -File

if ($snapshots.Count -eq 0) {
    Write-Warning "No snapshot files found in $SnapshotDir"
    return
}

$rolesWritten = 0

foreach ($snap in $snapshots) {
    Write-Verbose "Processing $($snap.Name)"
    $data = Get-Content -Raw -LiteralPath $snap.FullName | ConvertFrom-Json

    if (-not $data.PSObject.Properties.Match('Users') -or -not $data.Users -or $data.Users.Count -eq 0) {
        Write-Warning "Skipping $($snap.Name): no Users[]."
        continue
    }

    $departmentSlug = ConvertTo-Slug ([System.IO.Path]::GetFileNameWithoutExtension($snap.Name))

    $titleGroups = $data.Users | Group-Object -Property JobTitle

    foreach ($g in $titleGroups) {
        $title = $g.Name
        $users = @($g.Group)

        # Index-aligned arrays so variance can attribute back to a SAM.
        $samsOrdered = [string[]]@($users | ForEach-Object { $_.SamAccountName })
        $secSets  = [System.Collections.Generic.List[object]]::new()
        $distSets = [System.Collections.Generic.List[object]]::new()
        foreach ($u in $users) {
            $secSets.Add([string[]]@($u.SecurityGroups))
            $distSets.Add([string[]]@($u.DistributionGroups))
        }
        $secSetsArr  = $secSets.ToArray()
        $distSetsArr = $distSets.ToArray()

        $strategy = if ($users.Count -eq 1) { 'single' } else { $MergeStrategy }

        switch ($strategy) {
            'intersection' {
                $secMerged  = Get-SetIntersection -Sets $secSetsArr
                $distMerged = Get-SetIntersection -Sets $distSetsArr
            }
            'union' {
                $secMerged  = Get-SetUnion -Sets $secSetsArr
                $distMerged = Get-SetUnion -Sets $distSetsArr
            }
            'single' {
                $secMerged  = [string[]]@($users[0].SecurityGroups)
                $distMerged = [string[]]@($users[0].DistributionGroups)
            }
        }

        $secVariance  = Get-VarianceItems -Sets $secSetsArr  -Sams $samsOrdered -Merged $secMerged
        $distVariance = Get-VarianceItems -Sets $distSetsArr -Sams $samsOrdered -Merged $distMerged

        $roleId = '{0}-{1}' -f $departmentSlug, (ConvertTo-Slug $title)

        $obj = [ordered]@{
            schemaVersion = $SchemaVersion
            roleId        = $roleId
            displayName   = $title
            department    = $departmentSlug
            source        = [ordered]@{
                snapshotFile  = $snap.Name
                searchBase    = $data.SearchBase
                templateUsers = [string[]]@($samsOrdered | Sort-Object)
                mergeStrategy = $strategy
                generatedAt   = $generatedAt
                generatedBy   = $generatedBy
            }
            entitlements  = [ordered]@{
                securityGroups     = [string[]]@($secMerged  | Sort-Object)
                distributionGroups = [string[]]@($distMerged | Sort-Object)
            }
        }
        if ($secVariance.Count -gt 0 -or $distVariance.Count -gt 0) {
            $obj.variance = [ordered]@{
                securityGroupsAnyOf     = $secVariance
                distributionGroupsAnyOf = $distVariance
            }
        }

        $outFile = Join-Path $OutputDir ('{0}.json' -f $roleId)
        $json = $obj | ConvertTo-Json -Depth 10
        Set-Content -LiteralPath $outFile -Value $json -Encoding utf8

        Write-Verbose ("  wrote {0} ({1} sec / {2} dist; strategy={3})" -f $roleId, $secMerged.Count, $distMerged.Count, $strategy)
        $rolesWritten++
    }
}

Write-Output ('Wrote {0} role definition(s) to {1}' -f $rolesWritten, $OutputDir)
