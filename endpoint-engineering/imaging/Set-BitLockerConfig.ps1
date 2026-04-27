#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manifest-driven BitLocker FVE Group Policy registry hardening.
    Policy only - does NOT enable encryption. Encryption is handled
    post-deploy by Intune/SCCM/Autopilot.

.DESCRIPTION
    Reads Set-BitLockerConfig.manifest.json (sibling file in .\manifests
    by default) and applies each enabled FVE policy registry value.
    Disabled entries are recorded as SKIPPED_BY_MANIFEST in the change
    ledger. A TPM pre-flight check runs first as informational evidence;
    policy is written regardless of TPM state (Intune deployment may
    handle TPM provisioning later).

    Schema:
      registrySettings[] - { section, description, path, name, type, value, enabled }
                           Writes go through Set-HardenedRegistry.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-BitLockerConfig.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Set-BitLockerConfig.manifest.json

.NOTES
    Version : 6.0.0 | Date: 2026-04-26 | Log Format: CMTrace
    Changes :
      6.0.0 - Manifest-driven. All FVE policy registry values moved to
              Set-BitLockerConfig.manifest.json. Switch-style 'enabled'
              flag per entry; disabled entries recorded as
              SKIPPED_BY_MANIFEST.
      5.0.1 - Last inline-data version.
      5.0.0 - Policy-only. Removed encryption phases.
      4.0.0 - Dropped offline support.
      3.0.0 - Initial consolidated release.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Set-BitLockerConfig.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Set-BitLockerConfig.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-BitLockerConfig'

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('registrySettings')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

# TPM pre-flight (informational; policy is set regardless)
try {
    $tpm = Get-Tpm -ErrorAction Stop
    if (-not $tpm.TpmPresent) {
        Write-Log 'TPM NOT present. Policy will still be written.' -Level WARN
    } elseif (-not $tpm.TpmReady) {
        Write-Log 'TPM present but NOT ready.' -Level WARN
    } else {
        $ver = (Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
        Write-Log "TPM: Present, Ready=$($tpm.TpmReady), Version=$ver"
    }
}
catch [System.Management.Automation.CommandNotFoundException] {
    Write-Log 'Get-Tpm unavailable' -Level WARN
}
catch {
    Write-Log "TPM check: $($_.Exception.Message)" -Level WARN
}

# ===========================================================================
# Apply FVE policy from manifest
# ===========================================================================

$lastSection = $null
foreach ($r in $manifest.registrySettings) {
    if ($r.section -ne $lastSection) {
        Write-LogSection "BitLocker FVE - $($r.section)"
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

Write-LogSummary -ScriptName 'Set-BitLockerConfig'
Write-Host '  BitLocker policy set. Encryption will be enabled by deployment platform.' -ForegroundColor Cyan
