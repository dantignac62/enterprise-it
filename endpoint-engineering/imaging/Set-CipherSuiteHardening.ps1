#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manifest-driven SCHANNEL protocol, cipher, and hash hardening.
    Runs online against the live OS (intended use: audit-mode VM reference image).

.DESCRIPTION
    Reads Set-CipherSuiteHardening.manifest.json (sibling file by default).
    Each entry has an 'enabled' flag (operator opt-out toggle); entries
    with enabled=false are recorded as SKIPPED_BY_MANIFEST.

    Schema:
      protocols[] : { name, description,
                      clientEnabled (bool), serverEnabled (bool),
                      disabledByDefault (bool), enabled (bool) }
                    Writes Enabled and DisabledByDefault under
                    SCHANNEL\Protocols\<name>\Client and \Server.
      ciphers[]   : { name, description,
                      state ("Enabled"|"Disabled"), enabled (bool) }
                    Writes Enabled DWord under SCHANNEL\Ciphers\<name>.
                    Enabled state -> 0xFFFFFFFF; Disabled state -> 0.
      hashes[]    : same shape as ciphers, under SCHANNEL\Hashes\<name>.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-CipherSuiteHardening.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Set-CipherSuiteHardening.manifest.json

.NOTES
    Version : 3.0.0 | Date: 2026-04-26 | Log Format: CMTrace
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      3.0.0 - Manifest-driven. All hardening data moved to
              Set-CipherSuiteHardening.manifest.json. Switch-style
              'enabled' flag per entry; disabled entries recorded as
              SKIPPED_BY_MANIFEST. SHA-1 added to manifest as
              enabled=false, state=Disabled placeholder so the audit
              trail covers it as a deliberate opt-out.
      2.0.0 - Dropped offline (mounted-WIM) support.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Set-CipherSuiteHardening.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Set-CipherSuiteHardening.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CipherSuiteHardening'

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('protocols','ciphers','hashes')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

$SchannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

# SCHANNEL Ciphers/Hashes 'Enabled' DWORD = 0xFFFFFFFF for enabled, 0 for
# disabled. Use [uint32]::MaxValue because the literal 0xFFFFFFFF parses as
# Int32 -1 in PS 5.1 and 7.x. Set-HardenedRegistryNet (.NET fallback used
# for paths containing '/') normalizes via BitConverter.
$EnableSentinel = [uint32]::MaxValue

# ===========================================================================
# Phase 1: SSL/TLS Protocols
# ===========================================================================
Write-LogSection 'Phase 1: SSL/TLS Protocol Enforcement'

foreach ($p in $manifest.protocols) {
    if (-not $p.enabled) {
        Skip-ByManifest -Description $p.description `
            -Category 'Schannel-Protocol' -Target $p.name
        continue
    }

    $base       = "$SchannelBase\Protocols\$($p.name)"
    $clientVal  = if ($p.clientEnabled)     { 1 } else { 0 }
    $serverVal  = if ($p.serverEnabled)     { 1 } else { 0 }
    $disByDef   = if ($p.disabledByDefault) { 1 } else { 0 }
    $clientLbl  = if ($p.clientEnabled)     { 'Enabled' } else { 'Disabled' }
    $serverLbl  = if ($p.serverEnabled)     { 'Enabled' } else { 'Disabled' }

    Set-HardenedRegistry -Path "$base\Client" -Name 'Enabled'           -Value $clientVal -Description "$($p.name) Client: $clientLbl"
    Set-HardenedRegistry -Path "$base\Client" -Name 'DisabledByDefault' -Value $disByDef  -Description "$($p.name) Client: DisabledByDefault=$disByDef"
    Set-HardenedRegistry -Path "$base\Server" -Name 'Enabled'           -Value $serverVal -Description "$($p.name) Server: $serverLbl"
    Set-HardenedRegistry -Path "$base\Server" -Name 'DisabledByDefault' -Value $disByDef  -Description "$($p.name) Server: DisabledByDefault=$disByDef"
}

# ===========================================================================
# Phase 2: Ciphers
# ===========================================================================
Write-LogSection 'Phase 2: Cipher Algorithm Enforcement'

foreach ($c in $manifest.ciphers) {
    if (-not $c.enabled) {
        Skip-ByManifest -Description $c.description `
            -Category 'Schannel-Cipher' -Target $c.name
        continue
    }

    $val = switch ($c.state) {
        'Enabled'  { $EnableSentinel }
        'Disabled' { 0 }
        default    {
            Write-Log "Cipher '$($c.name)': unknown state '$($c.state)' in manifest. Skipping." -Level WARN
            $null
        }
    }
    if ($null -eq $val) { continue }

    Set-HardenedRegistry -Path "$SchannelBase\Ciphers\$($c.name)" -Name 'Enabled' `
        -Value $val -Description "Cipher $($c.name): $($c.state)"
}

# ===========================================================================
# Phase 3: Hashes
# ===========================================================================
Write-LogSection 'Phase 3: Hash Algorithm Enforcement'

foreach ($h in $manifest.hashes) {
    if (-not $h.enabled) {
        Skip-ByManifest -Description $h.description `
            -Category 'Schannel-Hash' -Target $h.name
        continue
    }

    $val = switch ($h.state) {
        'Enabled'  { $EnableSentinel }
        'Disabled' { 0 }
        default    {
            Write-Log "Hash '$($h.name)': unknown state '$($h.state)' in manifest. Skipping." -Level WARN
            $null
        }
    }
    if ($null -eq $val) { continue }

    Set-HardenedRegistry -Path "$SchannelBase\Hashes\$($h.name)" -Name 'Enabled' `
        -Value $val -Description "Hash $($h.name): $($h.state)"
}

Write-LogSummary -ScriptName 'Set-CipherSuiteHardening'
Write-Host '  Reboot required for SCHANNEL changes to take effect.' -ForegroundColor Yellow
