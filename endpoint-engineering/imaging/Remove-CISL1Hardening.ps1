#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Reverts the CIS L1 controls that Set-CISL1Hardening.manifest.json has
    opted out of (every entry with "enabled": false), on machines where a
    PRIOR run applied them.

.DESCRIPTION
    Set-CISL1Hardening.ps1 only applies or skips controls -- it never reverts.
    So when you flip a control to "enabled": false in the manifest, machines
    that were hardened by an earlier run keep the old setting. This script
    closes that gap: it reads the SAME manifest and walks back exactly the
    controls now marked "enabled": false, leaving the still-enabled controls
    untouched. It is data-driven -- opt another control out in the manifest
    and this script will revert it too (services fall back to a 'Manual' start
    type with a warning if not in the known-default table below).

    Revert actions:
      registrySettings (enabled:false) -> remove the policy VALUE, returning
        the setting to "not configured" (Windows default). These are all
        Policies\ keys, so absence == default behavior.
      services (enabled:false)         -> restore the service start type to its
        Windows default (see $ServiceDefaults).

    Credential Guard (DeviceGuard policy) gets special handling: removing the
    policy value is NOT enough when CG was enabled with a UEFI lock. After the
    revert this script checks Win32_DeviceGuard and, if CG is still running,
    prints the manual UEFI-lock removal procedure (which requires physical
    presence at the next boot).

    Requires ImageHardeningLib.ps1 in the same directory. Honors -WhatIf.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Remove-CISL1Hardening.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Set-CISL1Hardening.manifest.json
    (the same manifest Set-CISL1Hardening.ps1 reads).

.EXAMPLE
    # Preview what would be reverted, change nothing:
    .\Remove-CISL1Hardening.ps1 -WhatIf

.EXAMPLE
    .\Remove-CISL1Hardening.ps1

.NOTES
    Version : 1.0.0 | Date: 2026-05-30 | Log Format: CMTrace
    Baseline: CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1
    Pairs with: Set-CISL1Hardening.ps1 (apply) / Set-CISL1Hardening.manifest.json
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Remove-CISL1Hardening.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Set-CISL1Hardening.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Remove-CISL1Hardening'

# Windows 11 default start types for the services this baseline can disable.
# Anything not listed falls back to 'Manual' with a WARN, so newly opted-out
# services still get a sane revert.
$ServiceDefaults = @{
    sshd        = 'Manual'      # OpenSSH Server (optional feature)
    WpnService  = 'Automatic'   # Windows Push Notifications
    LxssManager = 'Manual'      # Windows Subsystem for Linux
}

function Remove-HardenedRegistryValue {
    <#
    .SYNOPSIS
        Removes a single registry value to revert a policy to "not configured".
        No-op (recorded as NOT_APPLICABLE) when the key or value is already
        absent. Never throws -- failures are logged as ERROR like the apply path.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [string]$CISRef,
        [string]$Description
    )
    $label = if ($CISRef) { "[$CISRef] $Description" } else { $Description }
    try {
        if (-not (Test-Path -Path $Path)) {
            Write-Log "$label - key absent, nothing to revert" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Registry' -Target "$Path\$Name" `
                -Description $Description -Details @{ Path = $Path; Name = $Name; CISRef = $CISRef; Reason = 'Key absent' }
            return
        }
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $prop -or -not $prop.PSObject.Properties[$Name]) {
            Write-Log "$label - value absent, nothing to revert" -Level SKIP
            Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Registry' -Target "$Path\$Name" `
                -Description $Description -Details @{ Path = $Path; Name = $Name; CISRef = $CISRef; Reason = 'Value absent' }
            return
        }
        $old = $prop.$Name
        if ($PSCmdlet.ShouldProcess("$Path\$Name", "Remove value (revert $label)")) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
            Write-Log "$label - reverted (value removed; was $old)" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Registry' -Target "$Path\$Name" `
                -Description $Description -Details @{
                    Path = $Path; Name = $Name; OldValue = $old; NewValue = $null
                    CISRef = $CISRef; Operation = 'RemoveValue'
                }
        }
    } catch {
        Write-Log "FAILED revert: $label - $($_.Exception.Message)" -Level ERROR
    }
}

function Restore-ServiceStartType {
    <#
    .SYNOPSIS
        Restores a service's start type to a target default. Records
        NOT_APPLICABLE when the service is not installed and VERIFIED when it
        is already at the target. Stop-on-error is downgraded to a WARN so one
        stubborn service does not abort the revert.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Automatic','Manual','Disabled')][string]$StartType,
        [string]$CISRef,
        [string]$Description
    )
    $label = if ($CISRef) { "[$CISRef] $Description ($Name)" } else { "$Description ($Name)" }
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Log "$label - not installed, nothing to revert" -Level SKIP
        Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Service' -Target $Name `
            -Description $Description -Details @{ CISRef = $CISRef; Reason = 'Service not installed' }
        return
    }
    if ([string]$svc.StartType -eq $StartType) {
        Write-Log "$label - already $StartType" -Level SKIP
        Write-ChangeEvent -Action 'VERIFIED' -Category 'Service' -Target $Name `
            -Description $Description -Details @{ CISRef = $CISRef; StartType = $StartType }
        return
    }
    if ($PSCmdlet.ShouldProcess($Name, "Set StartType=$StartType (revert $label)")) {
        try {
            $prev = [string]$svc.StartType
            Set-Service -Name $Name -StartupType $StartType -ErrorAction Stop
            Write-Log "$label - StartType $prev -> $StartType" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Service' -Target $Name `
                -Description $Description -Details @{
                    CISRef = $CISRef; PreviousStartType = $prev; NewStartType = $StartType
                }
        } catch {
            Write-Log "FAILED revert: $label - $($_.Exception.Message)" -Level WARN
        }
    }
}

# ===========================================================================
# Load manifest and snapshot pre-revert state
# ===========================================================================

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('registrySettings','services','notes')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "Baseline: $($manifest.baseline)"

$regToRevert = @($manifest.registrySettings | Where-Object { -not $_.enabled })
$svcToRevert = @($manifest.services         | Where-Object { -not $_.enabled })
Write-Log "Controls opted out in manifest: $($regToRevert.Count) registry, $($svcToRevert.Count) service(s)"

if ($regToRevert.Count -eq 0 -and $svcToRevert.Count -eq 0) {
    Write-Log 'No opted-out controls to revert. Nothing to do.' -Level INFO
    Write-LogSummary -ScriptName 'Remove-CISL1Hardening'
    return
}

Save-HardeningSnapshot -Phase Pre | Out-Null

# ===========================================================================
# Revert registry controls (remove the value -> "not configured")
# ===========================================================================

Write-LogSection 'Reverting registry controls (opted out in manifest)'
foreach ($s in $regToRevert) {
    Remove-HardenedRegistryValue -Path $s.path -Name $s.name -CISRef $s.cisRef -Description $s.description
}

# ===========================================================================
# Restore services to their default start type
# ===========================================================================

Write-LogSection 'Restoring services (opted out in manifest)'
foreach ($svc in $svcToRevert) {
    $target = if ($ServiceDefaults.ContainsKey($svc.name)) {
        $ServiceDefaults[$svc.name]
    } else {
        Write-Log "No known default start type for '$($svc.name)'; using 'Manual'." -Level WARN
        'Manual'
    }
    Restore-ServiceStartType -Name $svc.name -StartType $target -CISRef $svc.cisRef -Description $svc.description
}

# ===========================================================================
# Credential Guard: policy removal is not enough when UEFI-locked
# ===========================================================================

$cgOptedOut = @($regToRevert | Where-Object { $_.path -like '*DeviceGuard*' }).Count -gt 0
if ($cgOptedOut) {
    Write-LogSection 'Credential Guard / VBS status check'
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop
        $running = @($dg.SecurityServicesRunning)
        # SecurityServicesRunning codes: 1 = Credential Guard, 2 = HVCI.
        if ($running -contains 1) {
            Write-Log 'Credential Guard is STILL RUNNING after policy removal -- it was likely enabled with a UEFI lock.' -Level WARN
            Write-Log 'Removing the policy value alone will NOT disable a UEFI-locked Credential Guard. Manual steps:' -Level WARN
            Write-Log '  1. (done) DeviceGuard policy values removed by this script.' -Level WARN
            Write-Log '  2. Also clear HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags (set 0 or delete).' -Level WARN
            Write-Log '  3. Run Microsoft''s Device Guard / Credential Guard hardware readiness tool with -Disable.' -Level WARN
            Write-Log '  4. Reboot and ACCEPT the firmware prompt at boot (physical presence required).' -Level WARN
            Write-Log '  5. Re-run this check to confirm SecurityServicesRunning no longer lists Credential Guard.' -Level WARN
        } else {
            Write-Log 'Credential Guard is not running. Policy removal is sufficient; reboot to finalize VBS changes.'
        }
    } catch {
        Write-Log "Could not query Win32_DeviceGuard ($($_.Exception.Message)). Verify Credential Guard state manually." -Level WARN
    }
}

# ===========================================================================
# Post-revert snapshot + summary
# ===========================================================================

Save-HardeningSnapshot -Phase Post | Out-Null
Write-LogSummary -ScriptName 'Remove-CISL1Hardening'
Write-Host '  Reboot recommended to finalize service and VBS/Credential Guard changes.' -ForegroundColor Yellow
