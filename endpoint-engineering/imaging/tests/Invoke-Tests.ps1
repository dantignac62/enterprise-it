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
    Pester output verbosity: None, Normal, Detailed, Diagnostic. Default Detailed.

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
    [ValidateSet('None','Normal','Detailed','Diagnostic')][string]$Output = 'Detailed',
    [switch]$CI
)

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
