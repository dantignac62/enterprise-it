#Requires -RunAsAdministrator
#Requires -Version 5.1
<#

.SYNOPSIS
    Runs the Windows 11 25H2 hardening pipeline in order and emits
    a HITRUST-friendly evidence artifact. Intended use: single command
    before sysprep+capture of an audit-mode VM.

.DESCRIPTION
    Precondition: the operator runs Windows Update manually via the
    Settings UI before invoking this script. The orchestrator does not
    install updates. The pipeline assumes the OS is at the desired
    Build.UBR before it starts.

    Executes, in order:
      1. Invoke-Win11Debloat.ps1
      2. Set-CompanyCustomizations.ps1
      3. Set-CipherSuiteHardening.ps1
      4. Set-BitLockerConfig.ps1

    A failure in one script is logged and the next still runs (failures
    do not abort the pipeline) - each area lands independently.

    Each child script writes its own CMTrace log under .\Logs\; this wrapper
    prints a combined per-script pass/fail summary, writes an evidence
    artifact, and exits non-zero if any child reported an error.

    Artifact location:  .\Evidence\<yyyyMMdd_HHmmss>\report.{json,md}

    Artifact contents:
      - Host identity: OS name/version/build.UBR, edition, architecture,
        installed KBs, TPM state, operator, machine
      - Baseline reference: CIS Microsoft Windows 11 Enterprise L1 v5.0.0
      - Per-script execution: status, start/end UTC, duration, log path,
        log SHA256, counters (Applied/Skipped/Warned/Errors) read from
        each script's sidecar summary file
      - Pre-run and post-run state snapshots (same shape, taken from the
        running OS before and after the pipeline):
          Firewall profiles, BitLocker volume protection+method,
          Defender real-time+tamper protection, SMB signing, SCHANNEL
          TLS protocol enablement, UAC, RDP NLA+encryption level
      - StateDelta: flattened list of leaf values that changed between
        pre and post snapshots (dotted path, old value, new value)
      - ChangeLedger: per-setting record of every Set-HardenedRegistry
        call, with Action (APPLIED = state transition, VERIFIED =
        already at target), path, name, old/new value, CIS ref,
        description -- read from each script's .changes.jsonl

.PARAMETER Quiet
    Suppress child-script console output. Log files still written.

.PARAMETER EvidencePath
    Override for the evidence root. Default: .\Evidence

.PARAMETER Revert
    Run the revert pipeline instead of the hardening pipeline. Executes
    Remove-CISL1Hardening.ps1, which walks back the CIS L1 controls currently
    opted out (enabled:false) in Set-CISL1Hardening.manifest.json. Produces the
    same evidence artifact (pre/post snapshots, delta, change ledger), tagged
    Mode=Revert. Combine with -WhatIf to preview without changing anything.

.NOTES
    Version : 2.3.0 | Date: 2026-05-30
    Target  : Windows 11 Enterprise 25H2 (Build 26200.x+)
    Changes :
      2.3.0 - Added -Revert mode. Runs Remove-CISL1Hardening.ps1 to walk back
              the CIS L1 controls opted out in the manifest, emitting the same
              evidence artifact (tagged Mode=Revert). Default behavior (the
              hardening pipeline) is unchanged.
      2.2.0 - Removed the Set-CISL1Hardening.ps1 stage from the pipeline.
              The CIS L1 stage no longer runs. Snapshot/delta/state-readback
              helpers (Get-SystemStateSnapshot, Get-RegValue, ConvertTo-FlatDict,
              Get-StateDelta) now live in ImageHardeningLib.ps1 and are
              consumed here by dot-sourcing the library, so the pipeline-level
              snapshot and each stage's per-script snapshot share one shape.
      2.1.0 - Added 'Disabled' counter column to the per-stage Pipeline
              table and SKIPPED_BY_MANIFEST tally to each stage's
              Change Ledger summary. Supports manifest-driven
              hardening scripts that record intentionally opted-out
              controls.
      2.0.0 - Removed automated patching. Stage 0 (Install-PendingUpdates),
              the smart-gate WUA query, sentinel file (UpdatesFinished.txt),
              RunOnce HardeningResume, post-patch reboot, and the
              UpdatePolicy artifact section are all gone. Updates are
              now applied manually via Settings before invoking the
              orchestrator. Pipeline starts at the debloat stage.
      1.2.0 - Added PreRunState, StateDelta, ChangeLedger.
      1.1.0 - Initial HITRUST artifact with host identity, pipeline
              results, and post-run state.
      1.0.0 - Pipeline runner without artifact.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Quiet,
    [string]$EvidencePath,
    [switch]$Revert
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared infrastructure. Provides the canonical Get-SystemStateSnapshot,
# Get-RegValue, ConvertTo-FlatDict, and Get-StateDelta used below for the
# pre/post pipeline snapshots (same implementation each child stage uses).
. "$PSScriptRoot\ImageHardeningLib.ps1"

if (-not $EvidencePath) {
    $EvidencePath = Join-Path $PSScriptRoot 'Evidence'
}
$runStamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$evidenceDir   = Join-Path $EvidencePath $runStamp
if (-not (Test-Path -LiteralPath $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

# ---------- Helpers --------------------------------------------------------

function Get-FileSha256Hex {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return $null }
}

# Get-RegValue, Get-SystemStateSnapshot, ConvertTo-FlatDict, and Get-StateDelta
# now live in ImageHardeningLib.ps1 (dot-sourced above) so the pipeline-level
# snapshot and each child stage's snapshot are produced by identical code.

function Get-HostSnapshot {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ubr = Get-RegValue $cv 'UBR'
    $build = Get-RegValue $cv 'CurrentBuild'
    $kbs = @()
    try { $kbs = @(Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID | Sort-Object -Unique) } catch { }

    $tpm = [ordered]@{ Present = $null; Ready = $null; SpecVersion = $null }
    try {
        $t = Get-Tpm -ErrorAction Stop
        $tpm.Present = [bool]$t.TpmPresent
        $tpm.Ready   = [bool]$t.TpmReady
        $tpm.SpecVersion = (Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    } catch { }

    [pscustomobject]@{
        OsProductName    = (Get-RegValue $cv 'ProductName')
        OsDisplayVersion = (Get-RegValue $cv 'DisplayVersion')
        OsEditionId      = (Get-RegValue $cv 'EditionID')
        OsInstallationType = (Get-RegValue $cv 'InstallationType')
        OsVersion        = if ($os) { $os.Version } else { $null }
        Build            = if ($build) { [int]$build } else { $null }
        UBR              = if ($ubr)   { [int]$ubr }   else { $null }
        BuildUbr         = if ($build -and $ubr) { "$build.$ubr" } else { $null }
        Architecture     = $env:PROCESSOR_ARCHITECTURE
        Operator         = $env:USERNAME
        Machine          = $env:COMPUTERNAME
        InstalledKBs     = $kbs
        Tpm              = $tpm
    }
}

function Get-ScriptSummary {
    # Locate and parse the .summary.json sidecar that Write-LogSummary
    # emits next to the child's CMTrace log.
    param([string]$ScriptPath)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    $sidecar = Join-Path $PSScriptRoot "Logs\$stem.summary.json"
    if (-not (Test-Path -LiteralPath $sidecar)) { return $null }
    try { return (Get-Content -LiteralPath $sidecar -Raw -ErrorAction Stop | ConvertFrom-Json) }
    catch { return $null }
}

function Get-ChangeLedger {
    # Reads the per-setting JSONL ledger a child script emitted via
    # Write-ChangeEvent. Returns an array of pscustomobjects (one per
    # APPLIED or VERIFIED setting). Empty array when the file is missing
    # or empty - children that don't use Set-HardenedRegistry (e.g., the
    # debloat script, which mostly calls DISM/Get-Service) may emit only
    # a handful of events or none.
    param([string]$ChangesFile)
    if (-not $ChangesFile -or -not (Test-Path -LiteralPath $ChangesFile)) { return @() }
    $events = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($line in Get-Content -LiteralPath $ChangesFile -ErrorAction Stop) {
            if (-not $line.Trim()) { continue }
            try { $events.Add(($line | ConvertFrom-Json)) } catch { }
        }
    } catch { }
    return ,$events.ToArray()
}

# ---------- Pipeline selection ---------------------------------------------
# Default: the hardening pipeline (stages 1-4). With -Revert: a single-stage
# revert pipeline that walks back the controls opted out in the CIS L1 manifest.

if ($Revert) {
    $mode     = 'Revert'
    $pipeline = @(
        @{ Name = 'Remove-CISL1Hardening.ps1'; Args = @{} }
    )
} else {
    $mode     = 'Harden'
    $pipeline = @(
        @{ Name = 'Invoke-Win11Debloat.ps1';       Args = @{} }
        @{ Name = 'Set-CompanyCustomizations.ps1'; Args = @{} }
        @{ Name = 'Set-CipherSuiteHardening.ps1'; Args = @{} }
        @{ Name = 'Set-BitLockerConfig.ps1';       Args = @{} }
    )
}

Write-Host ''
Write-Host "  Orchestrator mode: $mode" -ForegroundColor $(if ($Revert) { 'Yellow' } else { 'Cyan' })

$common = @{ Quiet = $Quiet }
if ($WhatIfPreference) { $common['WhatIf'] = $true }

$results         = New-Object System.Collections.Generic.List[object]
$preHost    = Get-HostSnapshot
Write-Host '  Capturing pre-run state snapshot...' -ForegroundColor Cyan
$preState   = Get-SystemStateSnapshot
$runStart   = (Get-Date).ToUniversalTime()

foreach ($step in $pipeline) {
    $path = Join-Path $PSScriptRoot $step.Name
    $startUtc = (Get-Date).ToUniversalTime()

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "`n  [MISSING] $($step.Name)" -ForegroundColor Red
        $results.Add([pscustomobject]@{
            Script    = $step.Name
            Status    = 'Missing'
            StartUtc  = $startUtc.ToString('o')
            EndUtc    = $startUtc.ToString('o')
            DurationSec = 0
            Error     = "Not found: $path"
        })
        continue
    }

    Write-Host ''
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  $($step.Name)" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    $callArgs = @{}
    foreach ($k in $common.Keys)    { $callArgs[$k] = $common[$k] }
    foreach ($k in $step.Args.Keys) { $callArgs[$k] = $step.Args[$k] }

    $status = 'OK'
    $err    = $null
    try {
        & $path @callArgs
    }
    catch {
        $status = 'Failed'
        $err    = $_.Exception.Message
        Write-Host "  [ERR]  $($step.Name): $err" -ForegroundColor Red
    }

    $endUtc  = (Get-Date).ToUniversalTime()
    $summary = Get-ScriptSummary -ScriptPath $path

    # Silent-failure promotion: child caught its own errors internally and
    # returned cleanly, but the sidecar shows Counters.Errors > 0.
    if ($status -eq 'OK' -and $summary -and $summary.Counters -and ([int]$summary.Counters.Errors -gt 0)) {
        $status = 'Failed'
    }

    $logPath     = if ($summary) { [string]$summary.LogFile }     else { $null }
    $changesPath = if ($summary -and $summary.PSObject.Properties.Name -contains 'ChangesFile') { [string]$summary.ChangesFile } else { $null }
    $ledger      = Get-ChangeLedger -ChangesFile $changesPath

    $results.Add([pscustomobject]@{
        Script         = $step.Name
        Status         = $status
        StartUtc       = $startUtc.ToString('o')
        EndUtc         = $endUtc.ToString('o')
        DurationSec    = [math]::Round(($endUtc - $startUtc).TotalSeconds, 2)
        LogPath        = $logPath
        LogSha256      = if ($logPath) { Get-FileSha256Hex -Path $logPath } else { $null }
        ChangesPath    = $changesPath
        ChangesSha256  = if ($changesPath) { Get-FileSha256Hex -Path $changesPath } else { $null }
        Counters       = if ($summary) { $summary.Counters } else { $null }
        ChangeLedger   = $ledger
        Error          = $err
    })

}

$runEnd = (Get-Date).ToUniversalTime()

# ---------- Post-run state + artifact --------------------------------------

Write-Host ''
Write-Host '  Capturing post-run state snapshot...' -ForegroundColor Cyan
$postState = Get-SystemStateSnapshot
$stateDelta = Get-StateDelta -Before $preState -After $postState

# Build artifact incrementally. PS 5.1 reports the opening line of
# [ordered]@{} for ANY error in the value expressions, making monolithic
# hashtable literals impossible to debug. Incremental .Add() gives each
# assignment its own traceable line number.
$artifact = [ordered]@{}
$artifact['GeneratedUtc']        = $runEnd.ToString('o')
$artifact['OrchestratorVersion'] = '2.3.0'
$artifact['Mode']                = $mode
$artifact['Baseline']            = 'CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1'
$artifact['HitrustCsfRefs']      = @('01.x Access Control','09.x Communications and Operations Management','10.x Information Systems Acquisition, Development, and Maintenance')
$artifact['RunStartUtc']         = $runStart.ToString('o')
$artifact['RunEndUtc']           = $runEnd.ToString('o')
$artifact['RunDurationSec']      = [math]::Round(($runEnd - $runStart).TotalSeconds, 2)
$artifact['Host']                = $preHost
$artifact['Pipeline']            = $results.ToArray()
$artifact['PreRunState']         = $preState
$artifact['PostRunState']        = $postState
$artifact['StateDelta']          = $stateDelta

$jsonPath = Join-Path $evidenceDir 'report.json'
$mdPath   = Join-Path $evidenceDir 'report.md'

# Use -InputObject to serialize the OrderedDictionary as a whole. Piping
# an OrderedDictionary through the pipeline enumerates its DictionaryEntry
# objects in PS 5.1, producing per-entry JSON fragments instead of one object.
ConvertTo-Json -InputObject $artifact -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

# Markdown rendering -------------------------------------------------------
$md = New-Object System.Collections.Generic.List[string]
$md.Add("# Windows 11 $mode - Evidence Artifact")
$md.Add('')
$md.Add('| Field | Value |')
$md.Add('| --- | --- |')
$md.Add("| Generated | $($artifact.GeneratedUtc) |")
$md.Add("| Mode | $mode |")
$md.Add("| Operator | $($preHost.Operator) |")
$md.Add("| Machine | $($preHost.Machine) |")
$md.Add("| OS | $($preHost.OsProductName) $($preHost.OsDisplayVersion) ($($preHost.OsEditionId)) |")
$md.Add("| Build.UBR | **$($preHost.BuildUbr)** |")
$md.Add("| Architecture | $($preHost.Architecture) |")
$md.Add("| TPM | Present=$($preHost.Tpm.Present), Ready=$($preHost.Tpm.Ready), Version=$($preHost.Tpm.SpecVersion) |")
$md.Add("| Baseline | $($artifact.Baseline) |")
$md.Add("| Run duration (s) | $($artifact.RunDurationSec) |")
$md.Add('')
$md.Add('## Installed KBs')
$md.Add('')
if ($preHost.InstalledKBs.Count -eq 0) { $md.Add('_none detected_') }
else { $md.Add(($preHost.InstalledKBs -join ', ')) }
$md.Add('')
$md.Add('## Pipeline')
$md.Add('')
$md.Add('| Script | Status | Duration (s) | Applied | Skipped | Disabled | Warned | Errors |')
$md.Add('| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |')
foreach ($r in $results) {
    $a = if ($r.Counters) { $r.Counters.Applied } else { '-' }
    $s = if ($r.Counters) { $r.Counters.Skipped } else { '-' }
    # SkippedByManifest may be absent from a sidecar written by an older
    # version of the lib -- render '-' if so.
    $d = if ($r.Counters -and $r.Counters.PSObject.Properties.Name -contains 'SkippedByManifest') {
            $r.Counters.SkippedByManifest
         } else { '-' }
    $w = if ($r.Counters) { $r.Counters.Warned }  else { '-' }
    $e = if ($r.Counters) { $r.Counters.Errors }  else { '-' }
    $md.Add("| $($r.Script) | $($r.Status) | $($r.DurationSec) | $a | $s | $d | $w | $e |")
}
$md.Add('')
$md.Add('## State Delta (Pre vs Post)')
$md.Add('')
if ($stateDelta.Count -eq 0) {
    $md.Add('_No leaf-level state changes detected. The image was already at target before the pipeline ran._')
} else {
    $md.Add("_$($stateDelta.Count) leaf value(s) changed._")
    $md.Add('')
    $md.Add('| Path | Old | New |')
    $md.Add('| --- | --- | --- |')
    foreach ($d in $stateDelta) {
        $o = if ($null -eq $d.OldValue) { '_null_' } else { ConvertTo-Json -InputObject $d.OldValue -Compress -Depth 3 }
        $n = if ($null -eq $d.NewValue) { '_null_' } else { ConvertTo-Json -InputObject $d.NewValue -Compress -Depth 3 }
        $md.Add("| $($d.Path) | $o | $n |")
    }
}
$md.Add('')
$md.Add('## Change Ledger')
$md.Add('')
$md.Add('Per-action record. **APPLIED** = state transition; **VERIFIED** = already at target (compliance evidence); **NOT_APPLICABLE** = target does not exist on this image (evidence that it was evaluated); **SKIPPED_BY_MANIFEST** = control intentionally disabled in the operator manifest.')
$md.Add('')
foreach ($r in $results) {
    $ledger = $r.ChangeLedger
    $md.Add("### $($r.Script)")
    $md.Add('')
    if (-not $ledger -or $ledger.Count -eq 0) {
        $md.Add('_No ledger events recorded._')
        $md.Add('')
        continue
    }
    $applied  = @($ledger | Where-Object { $_.Action -eq 'APPLIED' }).Count
    $verified = @($ledger | Where-Object { $_.Action -eq 'VERIFIED' }).Count
    $na       = @($ledger | Where-Object { $_.Action -eq 'NOT_APPLICABLE' }).Count
    $disabled = @($ledger | Where-Object { $_.Action -eq 'SKIPPED_BY_MANIFEST' }).Count
    $md.Add("Total events: $($ledger.Count) (APPLIED: $applied, VERIFIED: $verified, NOT_APPLICABLE: $na, SKIPPED_BY_MANIFEST: $disabled)")
    $md.Add('')
    $md.Add('| Action | Category | Target | Description | Details |')
    $md.Add('| --- | --- | --- | --- | --- |')
    foreach ($e in $ledger) {
        $target = if ($e.Target) { $e.Target } else { '-' }
        $desc   = if ($e.Description) { $e.Description } else { '-' }
        $detailSummary = if ($e.Details) {
            ($e.Details | ConvertTo-Json -Compress -Depth 3)
        } else { '-' }
        # Escape pipes inside cell content so markdown tables stay intact.
        $detailSummary = $detailSummary -replace '\|', '\|'
        $desc = $desc -replace '\|', '\|'
        $md.Add("| $($e.Action) | $($e.Category) | $target | $desc | $detailSummary |")
    }
    $md.Add('')
}
$md.Add('## Post-run State')
$md.Add('')
$md.Add('### Firewall')
$md.Add('')
$md.Add('| Profile | Enabled | Inbound | Outbound |')
$md.Add('| --- | --- | --- | --- |')
foreach ($k in @('Domain','Private','Public','DomainProfile','PrivateProfile','PublicProfile')) {
    if ($postState.Firewall.Contains($k)) {
        $p = $postState.Firewall[$k]
        $md.Add("| $k | $($p.Enabled) | $($p.DefaultInboundAction) | $($p.DefaultOutboundAction) |")
    }
}
$md.Add('')
$md.Add('### BitLocker')
$md.Add('')
$md.Add('| Mount | Type | Protection | Method | Status | % | Protectors |')
$md.Add('| --- | --- | --- | --- | --- | ---: | --- |')
foreach ($v in $postState.BitLocker) {
    if ($v.Contains('_error')) { $md.Add("| _error_ | | $($v['_error']) | | | | |"); continue }
    $kp = if ($v.KeyProtectorTypes) { ($v.KeyProtectorTypes -join ', ') } else { '-' }
    $md.Add("| $($v.MountPoint) | $($v.VolumeType) | $($v.ProtectionStatus) | $($v.EncryptionMethod) | $($v.VolumeStatus) | $($v.EncryptionPercentage) | $kp |")
}
$md.Add('')
$md.Add('### Defender')
$md.Add('')
foreach ($k in $postState.Defender.Keys) { $md.Add("- **$k**: $($postState.Defender[$k])") }
$md.Add('')
$md.Add('### SMB Signing')
$md.Add('')
$md.Add("- **Client RequireSecuritySignature**: $($postState.SMB.ClientRequireSecuritySignature)")
$md.Add("- **Server RequireSecuritySignature**: $($postState.SMB.ServerRequireSecuritySignature)")
$md.Add('')
$md.Add('### SCHANNEL TLS Enablement')
$md.Add('')
$md.Add('| Protocol | Client Enabled | Server Enabled |')
$md.Add('| --- | ---: | ---: |')
foreach ($p in $postState.Schannel.Keys) {
    $md.Add("| $p | $($postState.Schannel[$p].ClientEnabled) | $($postState.Schannel[$p].ServerEnabled) |")
}
$md.Add('')
$md.Add('### UAC')
$md.Add('')
foreach ($k in $postState.UAC.Keys) { $md.Add("- **$k**: $($postState.UAC[$k])") }
$md.Add('')
$md.Add('### RDP')
$md.Add('')
foreach ($k in $postState.RDP.Keys) { $md.Add("- **$k**: $($postState.RDP[$k])") }
$md.Add('')
$md.Add('## Reference')
$md.Add('')
$md.Add('- CIS Microsoft Windows 11 Enterprise Benchmark v5.0.0 L1')
$md.Add('- HITRUST CSF families: ' + ($artifact.HitrustCsfRefs -join '; '))

($md -join "`r`n") | Set-Content -LiteralPath $mdPath -Encoding UTF8

# ---------- Console summary ------------------------------------------------

Write-Host ''
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Pipeline Summary" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
foreach ($r in $results) {
    $color = switch ($r.Status) {
        'OK'                     { 'Green' }
        'Failed'                 { 'Red' }
        'Missing'                { 'Red' }
        'Skipped-RebootRequired' { 'Yellow' }
        default                  { 'Yellow' }
    }
    Write-Host ("  {0,-40} {1}" -f $r.Script, $r.Status) -ForegroundColor $color
}
Write-Host ''
Write-Host "  Evidence: $jsonPath"                 -ForegroundColor Cyan
Write-Host "  Evidence: $mdPath"                   -ForegroundColor Cyan
Write-Host ''

$failed = @($results.ToArray() | Where-Object { $_.Status -ne 'OK' })
if ($Revert) {
    if ($failed.Count -gt 0) {
        Write-Host "  Investigate revert failures above. Reboot to finalize any changes that did apply." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  Revert complete. Reboot to finalize service and VBS/Credential Guard changes." -ForegroundColor Yellow
} else {
    if ($failed.Count -gt 0) {
        Write-Host "  Investigate failures before sysprep /generalize /oobe /shutdown." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "  Next: sysprep /generalize /oobe /shutdown, then capture the VHDX with DISM /Capture-Image." -ForegroundColor Yellow
}
