#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Manifest-driven company customizations beyond CIS L1 hardening.
    Runs online against the live OS (audit-mode VM reference image).

.DESCRIPTION
    Reads Set-CompanyCustomizations.manifest.json (sibling file in
    .\manifests by default) and applies each enabled control. Disabled
    entries are recorded as SKIPPED_BY_MANIFEST.

    Schema:
      registrySettings[]              - HKLM/HKCU writes via Set-HardenedRegistry.
      services[]                      - Set-Service -StartupType. Optional
                                        startAfter=true triggers Start-Service
                                        after the StartupType is set (used for
                                        services whose configuration must be
                                        running for downstream readers).
      defaultProfile.registrySettings - Writes into Users\Default\NTUSER.DAT so
                                        new profiles created post-sysprep
                                        inherit the configuration. Hive is
                                        mounted/unmounted via reg.exe.
      defaultProfile.foldersToRemove  - Folders under Users\Default to delete.
      oneDriveWin32Uninstall          - Single gate on running
                                        %SystemRoot%\\System32\\OneDriveSetup.exe
                                        /uninstall.

    Intended to run after Set-CISL1Hardening and before
    Set-CipherSuiteHardening.

    Requires ImageHardeningLib.ps1 in the same directory.

.PARAMETER Quiet
    Suppress console output. Log file still written.

.PARAMETER LogPath
    Log file path. Default: .\Logs\Set-CompanyCustomizations.log

.PARAMETER ManifestPath
    Manifest file path. Default: .\manifests\Set-CompanyCustomizations.manifest.json

.NOTES
    Version : 2.0.0 | Date: 2026-04-26 | Log Format: CMTrace
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      2.0.0 - Manifest-driven. All customization data moved to
              Set-CompanyCustomizations.manifest.json. Switch-style
              'enabled' flag per entry; disabled entries recorded as
              SKIPPED_BY_MANIFEST. Service and default-profile changes
              now emit ChangeLedger events (previously only registry did).
      1.1.0 - Added Automatic Time Zone, Delivery Optimization disable,
              OneDrive uninstall.
      1.0.0 - Edge FRE suppression, web search disable.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$LogPath      = (Join-Path $PSScriptRoot 'Logs\Set-CompanyCustomizations.log'),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'manifests\Set-CompanyCustomizations.manifest.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\ImageHardeningLib.ps1"
Initialize-HardeningLog -LogPath $LogPath -Quiet:$Quiet -Component 'Set-CompanyCustomizations'

$manifest = Read-HardeningManifest -Path $ManifestPath `
    -RequiredSections @('registrySettings','services','defaultProfile','oneDriveWin32Uninstall')

Write-Log "Manifest: $ManifestPath (v$($manifest.version))"
Write-Log "OS Build: $((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber)"

# ===========================================================================
# Phase 1: Registry settings (HKLM + HKCU)
# ===========================================================================

$lastSection = $null
foreach ($r in $manifest.registrySettings) {
    if ($r.section -ne $lastSection) {
        Write-LogSection $r.section
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

# ===========================================================================
# Phase 2: Services
# ===========================================================================

$lastSection = $null
foreach ($svc in $manifest.services) {
    if ($svc.section -ne $lastSection) {
        Write-LogSection "Services - $($svc.section)"
        $lastSection = $svc.section
    }
    if (-not $svc.enabled) {
        Skip-ByManifest -Description "$($svc.description) ($($svc.name))" `
            -Category 'Service' -Target $svc.name
        continue
    }

    $current = Get-Service -Name $svc.name -ErrorAction SilentlyContinue
    if ($null -eq $current) {
        Write-Log "Service not found: $($svc.name)" -Level SKIP
        Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'Service' -Target $svc.name `
            -Description $svc.description `
            -Details @{ ServiceName = $svc.name; Reason = 'Not installed on this image' }
        continue
    }

    $startBefore = [string]$current.StartType
    if ($startBefore -eq $svc.startupType) {
        Write-Log "Already $($svc.startupType): $($svc.name)" -Level SKIP
        Write-ChangeEvent -Action 'VERIFIED' -Category 'Service' -Target $svc.name `
            -Description $svc.description `
            -Details @{ ServiceName = $svc.name; StartTypeBefore = $startBefore; StartTypeAfter = $startBefore }
    } else {
        if ($PSCmdlet.ShouldProcess($svc.name, "Set-Service -StartupType $($svc.startupType)")) {
            try {
                Set-Service -Name $svc.name -StartupType $svc.startupType -ErrorAction Stop
                Write-Log "Set startup type: $($svc.name) -> $($svc.startupType)" -Level APPLIED
                Write-ChangeEvent -Action 'APPLIED' -Category 'Service' -Target $svc.name `
                    -Description $svc.description `
                    -Details @{ ServiceName = $svc.name; StartTypeBefore = $startBefore; StartTypeAfter = $svc.startupType }
            } catch {
                Write-Log "Set-Service failed for $($svc.name): $($_.Exception.Message)" -Level WARN
            }
        }
    }

    # startAfter: ensure the service is running after its StartupType is set.
    # Used for services whose configuration must be running for downstream
    # readers (e.g., lfsvc for the location consent re-read on reboot).
    $hasStartAfter = $svc.PSObject.Properties.Name -contains 'startAfter'
    if ($hasStartAfter -and $svc.startAfter) {
        try {
            $now = Get-Service -Name $svc.name -ErrorAction Stop
            if ($now.Status -eq 'Running') {
                Write-Log "Service already running: $($svc.name)" -Level SKIP
            } else {
                if ($PSCmdlet.ShouldProcess($svc.name, 'Start-Service')) {
                    Start-Service -Name $svc.name -ErrorAction Stop
                    Write-Log "Started service: $($svc.name)" -Level APPLIED
                    Write-ChangeEvent -Action 'APPLIED' -Category 'Service' -Target $svc.name `
                        -Description "Started after StartupType configured" `
                        -Details @{ ServiceName = $svc.name; Action = 'Start' }
                }
            }
        } catch {
            Write-Log "Could not start $($svc.name): $($_.Exception.Message)" -Level WARN
        }
    }
}

# ===========================================================================
# Phase 3: Default Profile (NTUSER.DAT)
# ===========================================================================

Write-LogSection 'Default Profile (NTUSER.DAT)'

$defaultHive = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
$hiveKey     = 'HKU\DefaultProfile'
$hiveMounted = $false

# Mount only if there's enabled work to do.
$enabledDpRegs = @($manifest.defaultProfile.registrySettings | Where-Object { $_.enabled })

if ($enabledDpRegs.Count -gt 0) {
    if (Test-Path -LiteralPath $defaultHive) {
        & reg.exe load $hiveKey $defaultHive 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $hiveMounted = $true
            Write-Log "Mounted default profile hive: $hiveKey ($defaultHive)"
        } else {
            Write-Log "reg load failed: exit $LASTEXITCODE" -Level WARN
        }
    } else {
        Write-Log "Default profile NTUSER.DAT not found at $defaultHive" -Level WARN
    }
}

try {
    foreach ($r in $manifest.defaultProfile.registrySettings) {
        if (-not $r.enabled) {
            Skip-ByManifest -Description $r.description `
                -Category 'DefaultProfile-Registry' -Target $r.subKey
            continue
        }
        if (-not $hiveMounted) {
            Write-Log "Cannot apply (hive not mounted): $($r.description)" -Level WARN
            continue
        }

        $regPath = "Registry::$hiveKey\$($r.subKey)"
        try {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name $r.name -Value $r.value -Type $r.type -Force
            Write-Log "Default profile: $($r.subKey)\$($r.name) -> $($r.value)" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'DefaultProfile-Registry' `
                -Target "$($r.subKey)\$($r.name)" -Description $r.description `
                -Details @{ SubKey = $r.subKey; Name = $r.name; Value = $r.value; ValueType = $r.type }
        } catch {
            Write-Log "Default profile write failed: $($r.subKey)\$($r.name) - $($_.Exception.Message)" -Level WARN
        }
    }
}
finally {
    if ($hiveMounted) {
        # Release any open handles before unloading. PS holds references to
        # registry keys it touched until GC runs; an unload while a handle
        # remains will fail with "key still in use."
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 500
        & reg.exe unload $hiveKey 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Unmounted default profile hive: $hiveKey"
        } else {
            Write-Log "reg unload returned $LASTEXITCODE; hive may still be loaded." -Level WARN
        }
    }
}

# Folder removals (not hive-related)
$defaultRoot = Join-Path $env:SystemDrive 'Users\Default'
foreach ($f in $manifest.defaultProfile.foldersToRemove) {
    if (-not $f.enabled) {
        Skip-ByManifest -Description $f.description `
            -Category 'DefaultProfile-Folder' -Target $f.relativePath
        continue
    }
    $target = Join-Path $defaultRoot $f.relativePath
    if (-not (Test-Path -LiteralPath $target)) {
        Write-Log "Default profile folder not present: $($f.relativePath)" -Level SKIP
        Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'DefaultProfile-Folder' `
            -Target $f.relativePath -Description $f.description `
            -Details @{ Path = $target }
        continue
    }
    if ($PSCmdlet.ShouldProcess($target, 'Remove-Item -Recurse -Force')) {
        try {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
            Write-Log "Removed default profile folder: $($f.relativePath)" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'DefaultProfile-Folder' `
                -Target $f.relativePath -Description $f.description `
                -Details @{ Path = $target }
        } catch {
            Write-Log "Remove failed: $target - $($_.Exception.Message)" -Level WARN
        }
    }
}

# ===========================================================================
# Phase 4: OneDrive Win32 Uninstall
# ===========================================================================

Write-LogSection 'OneDrive Win32 Uninstall'

if (-not $manifest.oneDriveWin32Uninstall.enabled) {
    Skip-ByManifest -Description $manifest.oneDriveWin32Uninstall.description `
        -Category 'OneDrive-Win32Uninstall' -Target 'OneDriveSetup.exe'
} else {
    $oneDriveSetup = Join-Path $env:SystemRoot 'System32\OneDriveSetup.exe'
    if (-not (Test-Path -LiteralPath $oneDriveSetup)) {
        $oneDriveSetup = Join-Path $env:SystemRoot 'SysWOW64\OneDriveSetup.exe'
    }

    if (-not (Test-Path -LiteralPath $oneDriveSetup)) {
        Write-Log 'OneDriveSetup.exe not found; Win32 client not installed.' -Level SKIP
        Write-ChangeEvent -Action 'NOT_APPLICABLE' -Category 'OneDrive-Win32Uninstall' `
            -Target 'OneDriveSetup.exe' -Description $manifest.oneDriveWin32Uninstall.description `
            -Details @{ Reason = 'Setup binary not present in System32 or SysWOW64' }
    } elseif ($PSCmdlet.ShouldProcess($oneDriveSetup, 'Uninstall OneDrive Win32 client')) {
        Write-Log "Uninstalling OneDrive via $oneDriveSetup /uninstall"
        try {
            Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            $proc = Start-Process -FilePath $oneDriveSetup -ArgumentList '/uninstall' `
                        -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            $details = @{ ExitCode = $proc.ExitCode; SetupPath = $oneDriveSetup }
            switch ($proc.ExitCode) {
                0 {
                    Write-Log 'OneDrive Win32 client uninstalled.' -Level APPLIED
                    Write-ChangeEvent -Action 'APPLIED' -Category 'OneDrive-Win32Uninstall' `
                        -Target 'OneDriveSetup.exe' -Description $manifest.oneDriveWin32Uninstall.description -Details $details
                }
                -2147219813 {
                    # 0x8004069B - nothing to uninstall / already removed.
                    # Common when the AppX package was removed first by Invoke-Win11Debloat.
                    Write-Log 'OneDrive already removed (setup returned 0x8004069B).' -Level SKIP
                    Write-ChangeEvent -Action 'VERIFIED' -Category 'OneDrive-Win32Uninstall' `
                        -Target 'OneDriveSetup.exe' -Description $manifest.oneDriveWin32Uninstall.description -Details $details
                }
                default {
                    Write-Log "OneDriveSetup /uninstall exited with code $($proc.ExitCode)" -Level WARN
                }
            }
        } catch {
            Write-Log "OneDrive uninstall failed: $($_.Exception.Message)" -Level WARN
        }
    }
}

Write-LogSummary -ScriptName 'Set-CompanyCustomizations'
