#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manifest-driven CIS Windows 11 Enterprise Benchmark v5.0.0 L1 hardening.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Reads Set-CISL1Hardening.manifest.json (sibling file by default) and
    applies each registry setting and service disablement marked with
    "enabled": true. Entries with "enabled": false are recorded as
    SKIPPED_BY_MANIFEST in the change ledger so the auditor can see the
    full universe of CIS L1 controls considered, including those
    intentionally opted out.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-CISL1Hardening.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Set-CISL1Hardening.manifest.json

.NOTES
    Version  : 5.0.0 | Date: 2026-04-26 | Log Format: CMTrace
    Baseline : CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1
    Changes  :
      5.0.0 - Manifest-driven. All hardening data moved to
              Set-CISL1Hardening.manifest.json. Switch-style 'enabled'
              flag per control; disabled controls are recorded as
              SKIPPED_BY_MANIFEST so the audit trail covers the full
              control universe.
      4.0.0 - Dropped offline (mounted-WIM) support.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Set-CISL1Hardening.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Set-CISL1Hardening.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CISL1Hardening'

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('registrySettings','services','notes')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "Baseline: $($manifest.baseline)"
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# ===========================================================================
# Registry settings
# ===========================================================================

$lastSection = $null
foreach ($s in $manifest.registrySettings) {
    if ($s.section -ne $lastSection) {
        Write-LogSection $s.section
        $lastSection = $s.section
    }

    if (-not $s.enabled) {
        Skip-ByManifest -CISRef $s.cisRef -Description $s.description `
            -Category 'Registry' -Target "$($s.path)\$($s.name)"
        continue
    }

    Set-HardenedRegistry -Path $s.path -Name $s.name -Value $s.value `
        -Type $s.type -CISRef $s.cisRef -Description $s.description
}

# ===========================================================================
# Services
# ===========================================================================

$lastSection = $null
foreach ($svc in $manifest.services) {
    if ($svc.section -ne $lastSection) {
        Write-LogSection $svc.section
        $lastSection = $svc.section
    }

    if (-not $svc.enabled) {
        Skip-ByManifest -CISRef $svc.cisRef `
            -Description "$($svc.description) ($($svc.name))" `
            -Category 'Service' -Target $svc.name
        continue
    }

    $current = Get-Service -Name $svc.name -ErrorAction SilentlyContinue
    if ($null -eq $current) {
        Write-Log "[$($svc.cisRef)] Not present: $($svc.name)" -Level SKIP
        Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Service' `
            -Target $svc.name -Description $svc.description `
            -Details @{ CISRef = $svc.cisRef; Reason = 'Service not installed' }
        continue
    }
    if ($current.StartType -eq 'Disabled') {
        Write-Log "[$($svc.cisRef)] Already disabled: $($svc.name)" -Level SKIP
        Write-ChangeEvent -Action 'VERIFIED' -Category 'Service' `
            -Target $svc.name -Description $svc.description `
            -Details @{ CISRef = $svc.cisRef; PreviousStartType = 'Disabled' }
        continue
    }

    if ($PSCmdlet.ShouldProcess($svc.name, 'Disable')) {
        try {
            $previousStart = [string]$current.StartType
            if ($current.Status -eq 'Running') {
                Stop-Service -Name $svc.name -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $svc.name -StartupType Disabled
            Write-Log "[$($svc.cisRef)] Disabled: $($svc.name) ($($svc.description))" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Service' `
                -Target $svc.name -Description $svc.description `
                -Details @{
                    CISRef            = $svc.cisRef
                    PreviousStartType = $previousStart
                    NewStartType      = 'Disabled'
                }
        } catch {
            Write-Log "[$($svc.cisRef)] Failed: $($svc.name) - $($_.Exception.Message)" -Level WARN
        }
    }
}

# ===========================================================================
# Notes (informational only)
# ===========================================================================

Write-LogSection 'GPO/Intune required (informational)'
Write-Log '-- The following items must be applied separately via GPO/Intune --'
foreach ($note in $manifest.notes) {
    Write-Log "[$($note.cisRef)] $($note.description)"
}

Write-LogSummary -ScriptName 'Set-CISL1Hardening'
Write-Host '  Run CIS-CAT Pro to validate gaps.' -ForegroundColor Yellow
Write-Host '  Reboot recommended.' -ForegroundColor Yellow
