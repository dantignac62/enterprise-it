<#
.SYNOPSIS
    Runs the imaging Pester suite and returns a CI-friendly exit code.

.DESCRIPTION
    Requires Pester 5.x and (for the static-analysis tests) PSScriptAnalyzer.
    Install once per machine:
        Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -Force -SkipPublisherCheck
        Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck

    Exit codes:
        0  all tests passed
        1  one or more tests failed
        2  Pester 5.x not available

.PARAMETER Path
    Run only test files matching this path/pattern. Default: all *.Tests.ps1
    in this directory.

.PARAMETER Output
    Pester output verbosity: None, Normal, Detailed, Diagnostic. Default Normal
    (one line per test file). Use Detailed for a per-test breakdown.

.PARAMETER CI
    Emit NUnit + JaCoCo result files under tests\results\ for pipeline ingestion.

.EXAMPLE
    pwsh -NoProfile -File .\Invoke-Tests.ps1

.EXAMPLE
    pwsh -NoProfile -File .\Invoke-Tests.ps1 -Path *Lib* -Output Diagnostic
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,
    [ValidateSet('None','Normal','Detailed','Diagnostic')][string]$Output = 'Normal',
    [switch]$CI
)

# This suite requires PowerShell 7+ (the manifest tests use Test-Json -Schema,
# which does not exist in Windows PowerShell 5.1). If launched under 5.1,
# transparently re-invoke under pwsh so `.\Invoke-Tests.ps1` works from any
# shell. Fail with a clear message only if pwsh is genuinely absent.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $pwshExe = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwshExe) {
        Write-Host 'This suite requires PowerShell 7+ (pwsh). Windows PowerShell 5.1 lacks Test-Json -Schema.' -ForegroundColor Red
        Write-Host 'Install PowerShell 7: https://aka.ms/install-powershell' -ForegroundColor Yellow
        exit 2
    }
    Write-Host 'Relaunching under PowerShell 7 (pwsh)...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-File', $PSCommandPath)
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) {
            if ($kv.Value) { $argList += "-$($kv.Key)" }
        } else {
            $argList += "-$($kv.Key)"; $argList += [string]$kv.Value
        }
    }
    & $pwshExe.Source @argList
    exit $LASTEXITCODE
}

$pester = Get-Module -ListAvailable Pester |
    Where-Object { $_.Version.Major -ge 5 } |
    Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) {
    Write-Host 'Pester 5.x is required. Install with:' -ForegroundColor Red
    Write-Host '  Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0 -Force -SkipPublisherCheck' -ForegroundColor Yellow
    exit 2
}
Import-Module $pester -MinimumVersion 5.0.0 -Force

$config = New-PesterConfiguration
$config.Run.Path        = $Path
$config.Run.PassThru    = $true
$config.Output.Verbosity = $Output

if ($CI) {
    $resultsDir = Join-Path $PSScriptRoot 'results'
    if (-not (Test-Path $resultsDir)) { New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null }
    $config.TestResult.Enabled      = $true
    $config.TestResult.OutputPath   = Join-Path $resultsDir 'testResults.xml'
    $config.TestResult.OutputFormat = 'NUnitXml'
}

$result = Invoke-Pester -Configuration $config
exit ([int]($result.FailedCount -gt 0))
