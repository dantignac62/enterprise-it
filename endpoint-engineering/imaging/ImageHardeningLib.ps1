<#

.SYNOPSIS
    Shared infrastructure for Windows 11 25H2 image hardening scripts.
    Dot-source this file from each hardening script.

.DESCRIPTION
    Provides:
      - CMTrace-compatible file logging
      - Color-coded console output (always on by default; use -Quiet to suppress)
      - Idempotent registry write helper

.NOTES
    Usage in calling script:
      . "$PSScriptRoot\ImageHardeningLib.ps1"
      Initialize-HardeningLog -LogPath $LogPath -Component 'Invoke-Win11Debloat'
#>

# ===============================================================================
# LOGGING
# ===============================================================================

$script:LogFile      = $null
$script:ChangesFile  = $null
$script:Component    = 'ImageHardening'
$script:QuietMode    = $false
$script:DebugEnabled = $false
$script:Counters     = @{ Applied = 0; Skipped = 0; SkippedByManifest = 0; Warned = 0; Errors = 0 }

function Write-ChangeEvent {
    <#
    .SYNOPSIS
        Emits one JSON line to the per-run change ledger. Shape is
        category-agnostic so registry, AppX, optional-feature, service,
        and scheduled-task actions can all record structured evidence.

        Action:
          APPLIED             - state transition was performed
          VERIFIED            - setting was already at target (compliance)
          NOT_APPLICABLE      - target object does not exist on this image
                                (still evidence that it was evaluated)
          SKIPPED_BY_MANIFEST - control was disabled in the manifest
                                (intentional opt-out, distinct from
                                NOT_APPLICABLE)

        Category identifies the surface (Registry / AppX / Feature /
        Service / ScheduledTask / ...). Target is a short human-readable
        identifier of the thing acted on. Details is a free-form
        hashtable for category-specific fields (Path/Name/OldValue/...
        for Registry, PackageName for AppX, etc.).

        No-op if Initialize-HardeningLog has not set up a ledger path.
    #>
    param(
        [ValidateSet('APPLIED','VERIFIED','NOT_APPLICABLE','SKIPPED_BY_MANIFEST')][string]$Action,
        [string]$Category,
        [string]$Target,
        [string]$Description,
        [hashtable]$Details
    )
    if (-not $script:ChangesFile) { return }
    $evt = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        Component    = $script:Component
        Action       = $Action
        Category     = $Category
        Target       = $Target
        Description  = $Description
        Details      = if ($Details) { $Details } else { @{} }
    }
    try { ($evt | ConvertTo-Json -Compress -Depth 6) | Out-File -FilePath $script:ChangesFile -Append -Encoding utf8 }
    catch { }
}

function Set-HardeningDebug {
    <#
    .SYNOPSIS
        Enables or disables DEBUG-level logging. When disabled (default),
        Write-Log calls with -Level DEBUG are dropped. When enabled, they
        are written to file and console in DarkGray.
    #>
    param([bool]$Enabled)
    $script:DebugEnabled = [bool]$Enabled
}

function Initialize-HardeningLog {
    <#
    .SYNOPSIS
        Initializes the log file and console behavior. Call once at script start.
    .PARAMETER LogPath
        Full path to the .log file. Parent directory is created if missing.
        If the path is relative, it resolves from the current directory.
    .PARAMETER Component
        Component name written into every CMTrace entry.
    .PARAMETER Quiet
        Suppress console output. Log file still written.
    #>
    param(
        [Parameter(Mandatory)][string]$LogPath,
        [string]$Component = 'ImageHardening',
        [switch]$Quiet
    )

    $script:Component = $Component
    $script:QuietMode = [bool]$Quiet
    $script:Counters  = @{ Applied = 0; Skipped = 0; SkippedByManifest = 0; Warned = 0; Errors = 0 } 

    # Resolve relative paths against current working directory
    if (-not [System.IO.Path]::IsPathRooted($LogPath)) {
        $LogPath = Join-Path (Get-Location).Path $LogPath
    }
    $script:LogFile = $LogPath

    # Create log directory
    $logDir = Split-Path $LogPath -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        try {
            New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host "  Created log directory: $logDir" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  WARNING: Cannot create log directory $logDir - $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Logging to console only." -ForegroundColor Yellow
            $script:LogFile = $null
            return
        }
    }

    # Rotate if existing log > 5 MB
    if ($script:LogFile -and (Test-Path $script:LogFile)) {
        $size = (Get-Item $script:LogFile).Length
        if ($size -gt 5MB) {
            $archive = $script:LogFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            try { Rename-Item -Path $script:LogFile -NewName $archive -Force }
            catch { }
        }
    }

    # Per-setting change ledger (JSONL, one event per line). Reset each run
    # so the orchestrator's artifact reflects only this pipeline invocation.
    # Written by Set-HardenedRegistry / Set-HardenedRegistryNet via
    # Write-ChangeEvent. Consumed by Invoke-HardeningOrchestrator.ps1.
    if ($script:LogFile) {
        $script:ChangesFile = $script:LogFile -replace '\.log$', '.changes.jsonl'
        try { Set-Content -LiteralPath $script:ChangesFile -Value '' -Encoding utf8 -Force }
        catch { $script:ChangesFile = $null }
    }

    # Write header
    $header = @"
================================================================================
  $Component
  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Host    : $env:COMPUTERNAME
  User    : $env:USERNAME
  PS      : $($PSVersionTable.PSVersion)
================================================================================
"@
    if ($script:LogFile) {
        try {
            $header | Out-File -FilePath $script:LogFile -Encoding utf8 -Force
        }
        catch {
            Write-Host "  WARNING: Cannot write to $($script:LogFile) - $($_.Exception.Message)" -ForegroundColor Yellow
            $script:LogFile = $null
        }
    }

    # Print header to console
    if (-not $script:QuietMode) {
        Write-Host ''
        Write-Host "  $Component" -ForegroundColor Cyan
        Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
        if ($script:LogFile) {
            Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
        }
        Write-Host ''
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a CMTrace-compatible log entry to file and console.
    .PARAMETER Message
        Log message text.
    .PARAMETER Level
        INFO, WARN, ERROR, SKIP, SKIP_MANIFEST, APPLIED, DEBUG.
        SKIP_MANIFEST is reserved for controls intentionally disabled in
        the manifest and increments a distinct counter from SKIP (which
        means "already at target").
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SKIP','SKIP_MANIFEST','APPLIED','DEBUG')]
        [string]$Level = 'INFO'
    )

    # DEBUG is gated by Set-HardeningDebug. Drop entirely when disabled so
    # diagnostic call sites can emit freely without polluting normal runs.
    if ($Level -eq 'DEBUG' -and -not $script:DebugEnabled) { return }

    # CMTrace type
    $cmType = switch ($Level) {
        'ERROR' { 3 }
        'WARN'  { 2 }
        default { 1 }
    }

    # Update counters (DEBUG is not counted — it's diagnostic noise, not
    # an outcome)
    switch ($Level) {
        'APPLIED'       { $script:Counters.Applied++ }
        'SKIP'          { $script:Counters.Skipped++ }
        'SKIP_MANIFEST' { $script:Counters.SkippedByManifest++ }
        'WARN'          { $script:Counters.Warned++  }
        'ERROR'         { $script:Counters.Errors++  }
    }

    # Build CMTrace line and write to file
    if ($script:LogFile) {
        $now  = Get-Date
        $time = $now.ToString('HH:mm:ss.fff') + '+000'
        $date = $now.ToString('MM-dd-yyyy')

        $logPrefix = switch ($Level) {
            'SKIP'          { '[SKIP] ' }
            'SKIP_MANIFEST' { '[DIS]  ' }
            'APPLIED'       { '[SET]  ' }
            'WARN'          { '[WARN] ' }
            'ERROR'         { '[ERR]  ' }
            'DEBUG'         { '[DBG]  ' }
            default         { '[INFO] ' }
        }

        $cmLine = "<![LOG[$logPrefix$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$($script:Component)`" context=`"`" type=`"$cmType`" thread=`"$PID`" file=`"`">"

        try {
            $cmLine | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        }
        catch { }
    }

    # Console output (always unless -Quiet)
    if (-not $script:QuietMode) {
        switch ($Level) {
            'ERROR'         { Write-Host "  [ERR]  $Message" -ForegroundColor Red }
            'WARN'          { Write-Host "  [WARN] $Message" -ForegroundColor Yellow }
            'APPLIED'       { Write-Host "  [SET]  $Message" -ForegroundColor Green }
            'SKIP'          { Write-Host "  [SKIP] $Message" -ForegroundColor DarkGray }
            'SKIP_MANIFEST' { Write-Host "  [DIS]  $Message" -ForegroundColor DarkYellow }
            'DEBUG'         { Write-Host "  [DBG]  $Message" -ForegroundColor DarkGray }
            default         { Write-Host "  [INFO] $Message" -ForegroundColor White }
        }
    }
}

function Write-LogSection {
    <#
    .SYNOPSIS
        Writes a section header to log and console.
    #>
    param([Parameter(Mandatory)][string]$Title)

    if ($script:LogFile) {
        $now = Get-Date
        $time = $now.ToString('HH:mm:ss.fff') + '+000'
        $date = $now.ToString('MM-dd-yyyy')
        $cmLine = "<![LOG[== $Title ==]LOG]!><time=`"$time`" date=`"$date`" component=`"$($script:Component)`" context=`"`" type=`"1`" thread=`"$PID`" file=`"`">"
        try { $cmLine | Out-File -FilePath $script:LogFile -Append -Encoding utf8 } catch { }
    }

    if (-not $script:QuietMode) {
        Write-Host ''
        Write-Host "  -- $Title --" -ForegroundColor Cyan
    }
}

function Write-LogSummary {
    <#
    .SYNOPSIS
        Writes a summary block with counters. Call at script end.
    #>
    param([Parameter(Mandatory)][string]$ScriptName)

    $summary = @"

================================================================================
  $ScriptName - Complete
  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Applied  : $($script:Counters.Applied)
  Skipped  : $($script:Counters.Skipped) (already set or not found)
  Disabled : $($script:Counters.SkippedByManifest) (disabled in manifest)
  Warnings : $($script:Counters.Warned)
  Errors   : $($script:Counters.Errors)
================================================================================
"@
    if ($script:LogFile) {
        try { $summary | Out-File -FilePath $script:LogFile -Append -Encoding utf8 } catch { }

        # Sidecar JSON consumed by Invoke-HardeningOrchestrator.ps1 to avoid having
        # to scrape the CMTrace log for per-script counters. Overwritten on
        # every run; no rotation.
        $sidecar = $script:LogFile -replace '\.log$', '.summary.json'
        $payload = [ordered]@{
            ScriptName   = $ScriptName
            Component    = $script:Component
            FinishedUtc  = (Get-Date).ToUniversalTime().ToString('o')
            LogFile      = $script:LogFile
            ChangesFile  = $script:ChangesFile
            Counters     = @{
                Applied           = $script:Counters.Applied
                Skipped           = $script:Counters.Skipped
                SkippedByManifest = $script:Counters.SkippedByManifest
                Warned            = $script:Counters.Warned
                Errors            = $script:Counters.Errors
            }
        }
        try { ($payload | ConvertTo-Json -Depth 3) | Out-File -FilePath $sidecar -Encoding utf8 -Force } catch { }
    }

    # Console summary - always shown even in quiet mode
    Write-Host ''
    Write-Host "  $ScriptName - Complete" -ForegroundColor Cyan
    Write-Host '  +---------------------------------+'
    Write-Host "  | Applied : $($script:Counters.Applied.ToString().PadLeft(5))                   |" -ForegroundColor Green
    Write-Host "  | Skipped : $($script:Counters.Skipped.ToString().PadLeft(5))                   |" -ForegroundColor DarkGray
    Write-Host "  | Disabled: $($script:Counters.SkippedByManifest.ToString().PadLeft(5))                   |" -ForegroundColor $(if ($script:Counters.SkippedByManifest -gt 0) { 'DarkYellow' } else { 'DarkGray' })
    Write-Host "  | Warnings: $($script:Counters.Warned.ToString().PadLeft(5))                   |" -ForegroundColor $(if ($script:Counters.Warned -gt 0) { 'Yellow' } else { 'DarkGray' })
    Write-Host "  | Errors  : $($script:Counters.Errors.ToString().PadLeft(5))                   |" -ForegroundColor $(if ($script:Counters.Errors -gt 0) { 'Red' } else { 'DarkGray' })
    Write-Host '  +---------------------------------+'
    if ($script:LogFile) {
        Write-Host "  Log: $($script:LogFile)" -ForegroundColor DarkGray
    }
    Write-Host ''
}

# ===============================================================================
# MANIFEST HELPERS
# ===============================================================================

function Read-HardeningManifest {
    <#
    .SYNOPSIS
        Loads a JSON manifest, validates required top-level fields, and
        returns the parsed object. Throws on malformed JSON or missing
        metadata. Per-entry validation is the caller's responsibility
        (each script knows its own schema).
    .PARAMETER Path
        Absolute path to the manifest JSON file.
    .PARAMETER RequiredSections
        String array of top-level keys that must exist in the manifest.
        Each must be a non-null array (may be empty).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$RequiredSections = @()
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Manifest not found: $Path"
    }

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse manifest '$Path': $($_.Exception.Message)"
    }

    $fields = @($manifest.PSObject.Properties.Name)
    foreach ($f in @('name','version')) {
        if ($fields -notcontains $f) {
            throw "Manifest '$Path' missing required field: $f"
        }
    }
    foreach ($s in $RequiredSections) {
        if ($fields -notcontains $s) {
            throw "Manifest '$Path' missing required section: $s"
        }
    }

    return $manifest
}

function Skip-ByManifest {
    <#
    .SYNOPSIS
        Records a control intentionally disabled in the manifest.
        Increments the SkippedByManifest counter and emits a
        SKIPPED_BY_MANIFEST ledger event. Distinct from SKIP (which means
        "already at target") and NOT_APPLICABLE (object does not exist).
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [string]$Category = 'Registry',
        [string]$Target,
        [string]$CISRef,
        [hashtable]$Details
    )
    $label = if ($CISRef) { "[$CISRef] $Description" } else { $Description }
    Write-Log "$label - disabled in manifest" -Level SKIP_MANIFEST
    if (-not $Details) { $Details = @{} }
    if ($CISRef -and -not $Details.ContainsKey('CISRef')) { $Details['CISRef'] = $CISRef }
    Write-ChangeEvent -Action 'SKIPPED_BY_MANIFEST' -Category $Category `
        -Target $Target -Description $Description -Details $Details
}

# ===============================================================================
# REGISTRY HELPERS
# ===============================================================================

function Set-HardenedRegistry {
    <#
    .SYNOPSIS
        Idempotent registry write with logging.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [string]$Type = 'DWord',
        [string]$CISRef,
        [string]$Description
    )

    $label = if ($CISRef) { "[$CISRef] $Description" } else { $Description }

    # Key names containing '/' (SCHANNEL 'DES 56/56', 'AES 128/128', etc.) are
    # not traversable via the PS registry provider — fall back to .NET API.
    # Split-Path -Leaf can't detect this because it normalizes '/' as a
    # separator, so check the raw string. '/' never appears in valid path
    # prefixes (HKLM:\) or standard hive names.
    if ($Path.Contains('/')) {
        Set-HardenedRegistryNet -Resolved $Path -Name $Name -Value $Value -Type $Type -Label $label
        return
    }

    try {
        $keyExisted = Test-Path $Path
        if (-not $keyExisted) {
            if ($PSCmdlet.ShouldProcess($Path, 'Create registry key')) {
                New-Item -Path $Path -Force | Out-Null
            }
        }

        $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        $oldValue = if ($null -ne $current) { $current.$Name } else { $null }
        $regDetails = @{
            Path      = $Path
            Name      = $Name
            OldValue  = $oldValue
            NewValue  = $Value
            ValueType = $Type
            CISRef    = $CISRef
        }
        if ($null -ne $current -and $current.$Name -eq $Value) {
            Write-Log "$label" -Level SKIP
            Write-ChangeEvent -Action 'VERIFIED' -Category 'Registry' -Target "$Path\$Name" `
                -Description $Description -Details $regDetails
            return
        }

        if ($PSCmdlet.ShouldProcess("$Path\$Name = $Value", "Set ($label)")) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Log "$label -> $Value" -Level APPLIED
            Write-ChangeEvent -Action 'APPLIED' -Category 'Registry' -Target "$Path\$Name" `
                -Description $Description -Details $regDetails
        }
    }
    catch {
        Write-Log "FAILED: $label - $($_.Exception.Message)" -Level ERROR
    }
}

function Set-HardenedRegistryNet {
    <#
    .SYNOPSIS
        .NET Registry API fallback for key names the PS provider cannot traverse
        (notably names containing '/'). Called by Set-HardenedRegistry; not a
        public entry point.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Resolved,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [string]$Type = 'DWord',
        [string]$Label
    )

    $hive = $null; $sub = $null
    switch -Regex ($Resolved) {
        '^HKLM:\\(.+)$' { $hive = [Microsoft.Win32.Registry]::LocalMachine; $sub = $Matches[1] }
        '^HKCU:\\(.+)$' { $hive = [Microsoft.Win32.Registry]::CurrentUser;  $sub = $Matches[1] }
        default {
            Write-Log "FAILED: $Label - unsupported root for .NET fallback: $Resolved" -Level ERROR
            return
        }
    }

    # DWord comparison: 0xFFFFFFFF (uint32) and -1 (int32) are the same 32-bit
    # pattern. Normalize the incoming value via BitConverter so idempotency works.
    $storedValue = if ($Type -eq 'DWord') {
        [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$Value), 0)
    } else { $Value }

    $key = $null
    try {
        $key = $hive.OpenSubKey($sub, $true)
        $current = $null
        if ($null -ne $key) {
            $current = $key.GetValue($Name, $null)
            if ($null -ne $current -and $current -eq $storedValue) {
                Write-Log "$Label" -Level SKIP
                Write-ChangeEvent -Action 'VERIFIED' -Category 'Registry' -Target "$Resolved\$Name" `
                    -Description $Label -Details @{
                        Path      = $Resolved
                        Name      = $Name
                        OldValue  = $current
                        NewValue  = $Value
                        ValueType = $Type
                    }
                return
            }
        }
        if (-not $PSCmdlet.ShouldProcess("$Resolved\$Name = $Value", "Set via .NET Registry ($Label)")) {
            return
        }
        if ($null -eq $key) {
            $key = $hive.CreateSubKey($sub, $true)
        }
        $kind = switch ($Type) {
            'DWord'        { [Microsoft.Win32.RegistryValueKind]::DWord }
            'QWord'        { [Microsoft.Win32.RegistryValueKind]::QWord }
            'String'       { [Microsoft.Win32.RegistryValueKind]::String }
            'ExpandString' { [Microsoft.Win32.RegistryValueKind]::ExpandString }
            'MultiString'  { [Microsoft.Win32.RegistryValueKind]::MultiString }
            'Binary'       { [Microsoft.Win32.RegistryValueKind]::Binary }
            default        { [Microsoft.Win32.RegistryValueKind]::Unknown }
        }
        $key.SetValue($Name, $storedValue, $kind)
        Write-Log "$Label -> $Value" -Level APPLIED
        Write-ChangeEvent -Action 'APPLIED' -Category 'Registry' -Target "$Resolved\$Name" `
            -Description $Label -Details @{
                Path      = $Resolved
                Name      = $Name
                OldValue  = $current
                NewValue  = $Value
                ValueType = $Type
            }
    }
    catch {
        Write-Log "FAILED: $Label - $($_.Exception.Message)" -Level ERROR
    }
    finally {
        if ($null -ne $key) { $key.Close() }
    }
}