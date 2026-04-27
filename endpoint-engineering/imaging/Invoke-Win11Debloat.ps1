#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manifest-driven Windows 11 25H2 debloat.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Reads Invoke-Win11Debloat.manifest.json (sibling file by default).

    Schema:
      appx.protect[]    : { pattern, description, enabled }
                          Patterns that, when matched, prevent provisioned
                          AND per-user AppX removal. Evaluated BEFORE allow.
      appx.allow[]      : { pattern, description, enabled }
                          Patterns kept (not removed). Anything not on
                          protect or allow is removed.
      optionalFeatures[]: { name, description, enabled } -> Disable-WindowsOptionalFeature
      services[]        : { name, description, enabled } -> Set-Service Disabled
      scheduledTasks[]  : { path, description, enabled } -> Disable-ScheduledTask
      registrySettings[]: { section, description, path, name, type, value, enabled }

    Pattern entries with enabled=false are excluded from the active match
    set and recorded once as SKIPPED_BY_MANIFEST so the audit trail shows
    the operator's opt-out of that specific rule.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Invoke-Win11Debloat.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Invoke-Win11Debloat.manifest.json

.NOTES
    Version : 5.0.0 | Date: 2026-04-26 | Log Format: CMTrace
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      5.0.0 - Manifest-driven. All AppX protect/allow lists, optional
              features, consumer services, scheduled tasks, and registry
              settings moved to Invoke-Win11Debloat.manifest.json.
              Switch-style 'enabled' flag per entry; disabled entries
              recorded as SKIPPED_BY_MANIFEST. Copilot registry setting
              is now in the manifest (enabled=false default) instead of
              commented out in code.
      4.0.0 - Dropped offline (mounted-WIM) support.
      3.0.1 - Added $AppxProtectList; evaluated before $AppxAllowList.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Invoke-Win11Debloat.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Invoke-Win11Debloat.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Invoke-Win11Debloat'

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('appx','optionalFeatures','services','scheduledTasks','registrySettings')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# Contains-match against a list of -like patterns (preserves v3.0.0 semantics).
# Patterns may include trailing or embedded * wildcards.
function Test-AppxPatternMatch {
    param(
        [Parameter(Mandatory)][string]$PackageName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Patterns
    )
    foreach ($pattern in $Patterns) {
        $p = $pattern.TrimEnd('*')
        if ($PackageName -like "*$p*") { return $true }
    }
    return $false
}

# ===========================================================================
# Phase 1: AppX Provisioned + Per-User Removal
# ===========================================================================
Write-LogSection 'Phase 1: AppX Provisioned Package Removal'

# Build active pattern sets from the manifest. Disabled rule entries get a
# single SKIPPED_BY_MANIFEST event each so the audit trail reflects the
# operator's opt-out of that specific rule.
$activeProtect = New-Object System.Collections.Generic.List[string]
foreach ($p in $manifest.appx.protect) {
    if ($p.enabled) {
        $activeProtect.Add($p.pattern)
    } else {
        Skip-ByManifest -Description "Protect pattern: $($p.description)" `
            -Category 'AppX-ProtectRule' -Target $p.pattern
    }
}

$activeAllow = New-Object System.Collections.Generic.List[string]
foreach ($a in $manifest.appx.allow) {
    if ($a.enabled) {
        $activeAllow.Add($a.pattern)
    } else {
        Skip-ByManifest -Description "Allow pattern: $($a.description)" `
            -Category 'AppX-AllowRule' -Target $a.pattern
    }
}

Write-Log "Active protect patterns: $($activeProtect.Count); allow patterns: $($activeAllow.Count)"

try {
    $provisioned = Get-AppxProvisionedPackage -Online
    Write-Log "Found $($provisioned.Count) provisioned packages"

    foreach ($pkg in $provisioned) {
        $displayName = if ($pkg.DisplayName) { $pkg.DisplayName } else { $pkg.PackageName }
        $pkgDetails = @{ PackageName = $pkg.PackageName; DisplayName = $displayName; Scope = 'Provisioned' }

        if (Test-AppxPatternMatch -PackageName $pkg.PackageName -Patterns $activeProtect.ToArray()) {
            Write-Log "Protected: $displayName" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageName `
                -Description 'On protect list; removal intentionally skipped' -Details $pkgDetails
            continue
        }

        if (Test-AppxPatternMatch -PackageName $pkg.PackageName -Patterns $activeAllow.ToArray()) {
            Write-Log "Kept: $displayName" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageName `
                -Description 'On allow list; kept' -Details $pkgDetails
            continue
        }

        if ($PSCmdlet.ShouldProcess($displayName, 'Remove-AppxProvisionedPackage')) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
                Write-Log "Removed provisioned: $displayName" -Level APPLIED
                Write-ChangeEvent -Action 'APPLIED' -Category 'AppX' -Target $pkg.PackageName `
                    -Description 'Provisioned package removed' -Details $pkgDetails
            }
            catch { Write-Log "Failed: $displayName - $($_.Exception.Message)" -Level WARN }
        }
    }
}
catch { Write-Log "AppxProvisionedPackage error: $($_.Exception.Message)" -Level ERROR }

# Per-user cleanup
Write-Log '-- Phase 1b: Per-User AppX Cleanup --'
try {
    foreach ($pkg in (Get-AppxPackage -AllUsers)) {
        $puDetails = @{ PackageName = $pkg.Name; PackageFullName = $pkg.PackageFullName; Scope = 'PerUser' }

        if (Test-AppxPatternMatch -PackageName $pkg.Name -Patterns $activeProtect.ToArray()) {
            Write-Log "Protected per-user: $($pkg.Name)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'AppX' -Target $pkg.PackageFullName `
                -Description 'Per-user: on protect list; removal intentionally skipped' -Details $puDetails
            continue
        }

        # Allowlisted per-user items are quiet-skipped (no ledger entry) to
        # keep the artifact size manageable: there can be many per-user
        # entries for common frameworks, and the allowlist is fully
        # documented in the manifest. Protect events and removals are what
        # matter for evidence.
        if (Test-AppxPatternMatch -PackageName $pkg.Name -Patterns $activeAllow.ToArray()) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($pkg.Name, 'Remove-AppxPackage -AllUsers')) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                Write-Log "Removed per-user: $($pkg.Name)" -Level APPLIED
                Write-ChangeEvent -Action 'APPLIED' -Category 'AppX' -Target $pkg.PackageFullName `
                    -Description 'Per-user package removed (AllUsers)' -Details $puDetails
            }
            catch { Write-Log "Failed per-user: $($pkg.Name) - $($_.Exception.Message)" -Level WARN }
        }
    }
}
catch { Write-Log "Per-user AppX error: $($_.Exception.Message)" -Level WARN }

# ===========================================================================
# Phase 2: Optional Features
# ===========================================================================
Write-LogSection 'Phase 2: Disable Optional Features'

foreach ($f in $manifest.optionalFeatures) {
    if (-not $f.enabled) {
        Skip-ByManifest -Description "$($f.description) ($($f.name))" `
            -Category 'Feature' -Target $f.name
        continue
    }

    try {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $f.name -ErrorAction SilentlyContinue
        if ($null -eq $state) {
            Write-Log "Feature not found: $($f.name)" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Feature' -Target $f.name `
                -Description 'Optional feature not present on this image' `
                -Details @{ FeatureName = $f.name }
            continue
        }
        $before = [string]$state.State
        if ($state.State -eq 'Disabled') {
            Write-Log "Already disabled: $($f.name)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'Feature' -Target $f.name `
                -Description 'Optional feature already disabled' `
                -Details @{ FeatureName = $f.name; StateBefore = $before; StateAfter = $before }
            continue
        }
        if ($PSCmdlet.ShouldProcess($f.name, 'Disable-WindowsOptionalFeature')) {
            Disable-WindowsOptionalFeature -Online -FeatureName $f.name -NoRestart -ErrorAction Stop | Out-Null
            Write-Log "Disabled feature: $($f.name)" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Feature' -Target $f.name `
                -Description 'Optional feature disabled' `
                -Details @{ FeatureName = $f.name; StateBefore = $before; StateAfter = 'Disabled' }
        }
    }
    catch { Write-Log "Failed feature $($f.name) - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# Phase 3: Consumer Services
# ===========================================================================
Write-LogSection 'Phase 3: Disable Consumer Services'

foreach ($svc in $manifest.services) {
    if (-not $svc.enabled) {
        Skip-ByManifest -Description "$($svc.description) ($($svc.name))" `
            -Category 'Service' -Target $svc.name
        continue
    }

    try {
        $service = Get-Service -Name $svc.name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Log "Service not found: $($svc.name)" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Service' -Target $svc.name `
                -Description "$($svc.description) - service not installed on this image" `
                -Details @{ ServiceName = $svc.name; DisplayName = $svc.description }
            continue
        }
        $startBefore = [string]$service.StartType
        if ($service.StartType -eq 'Disabled') {
            Write-Log "Already disabled: $($svc.name)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'Service' -Target $svc.name `
                -Description "$($svc.description) - already disabled" `
                -Details @{ ServiceName = $svc.name; DisplayName = $svc.description; StartTypeBefore = $startBefore; StartTypeAfter = $startBefore }
            continue
        }
        if ($PSCmdlet.ShouldProcess($svc.name, 'Disable')) {
            if ($service.Status -eq 'Running') { Stop-Service -Name $svc.name -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $svc.name -StartupType Disabled -ErrorAction Stop
            Write-Log "Disabled: $($svc.name) ($($svc.description))" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Service' -Target $svc.name `
                -Description "$($svc.description) - disabled" `
                -Details @{ ServiceName = $svc.name; DisplayName = $svc.description; StartTypeBefore = $startBefore; StartTypeAfter = 'Disabled' }
        }
    }
    catch { Write-Log "Failed: $($svc.name) - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# Phase 4: Scheduled Tasks
# ===========================================================================
Write-LogSection 'Phase 4: Scheduled Tasks'

foreach ($t in $manifest.scheduledTasks) {
    if (-not $t.enabled) {
        Skip-ByManifest -Description $t.description `
            -Category 'ScheduledTask' -Target $t.path
        continue
    }

    try {
        $tp = $t.path -replace '[^\\]*$', ''
        $tn = $t.path -replace '.*\\', ''
        $taskDetails = @{ TaskPath = $tp; TaskName = $tn; FullPath = $t.path }
        $task = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            Write-Log "Task not found: $($t.path)" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'ScheduledTask' -Target $t.path `
                -Description 'Scheduled task not present on this image' -Details $taskDetails
            continue
        }
        $stateBefore = [string]$task.State
        if ($task.State -eq 'Disabled') {
            Write-Log "Already disabled: $($t.path)" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'ScheduledTask' -Target $t.path `
                -Description 'Scheduled task already disabled' `
                -Details ($taskDetails + @{ StateBefore = $stateBefore; StateAfter = $stateBefore })
            continue
        }
        if ($PSCmdlet.ShouldProcess($t.path, 'Disable-ScheduledTask')) {
            Disable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction Stop | Out-Null
            Write-Log "Disabled task: $($t.path)" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'ScheduledTask' -Target $t.path `
                -Description 'Scheduled task disabled' `
                -Details ($taskDetails + @{ StateBefore = $stateBefore; StateAfter = 'Disabled' })
        }
    }
    catch { Write-Log "Failed task $($t.path) - $($_.Exception.Message)" -Level WARN }
}

# ===========================================================================
# Phase 5: Registry - Consumer Experience
# ===========================================================================
Write-LogSection 'Phase 5: Suppress Consumer Features'

$lastSection = $null
foreach ($r in $manifest.registrySettings) {
    if ($r.section -ne $lastSection -and $r.section) {
        # Inner section banner only when the manifest tags entries with a
        # finer-grained 'section' field (Phase 5 currently uses one).
        $lastSection = $r.section
    }

    if (-not $r.enabled) {
        Skip-ByManifest -Description $r.description `
            -Category 'Registry' -Target "$($r.path)\$($r.name)"
        continue
    }

    Set-HardenedRegistry -Path $r.path -Name $r.name -Value $r.value `
        -Type $r.type -Description $r.description
}

Write-LogSummary -ScriptName 'Invoke-Win11Debloat'
Write-Host '  Reboot recommended.' -ForegroundColor Yellow
