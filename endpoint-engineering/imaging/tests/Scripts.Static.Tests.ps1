#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Repo-wide static checks that give every .ps1 file baseline coverage without
    executing it. Four guarantees, one It per file via -ForEach:

      1. Parses cleanly (no syntax errors)             -- catches "unrunnable"
      2. No Error-severity PSScriptAnalyzer findings   -- catches broken refs
      3. (imaging only) ASCII punctuation only         -- em-dash regression
      4. (imaging only) dot-sourced library path resolves

    (1) and (4) directly guard the failure class the last commit fixed
    ("Fix unrunnable Edge scripts and purge em-dashes from imaging/").
#>

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:AllScripts     = @(Get-RepoPowerShellFile     | ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } })
    $script:ImagingScripts = @(Get-ImagingPowerShellFile  | ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } })
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:HasAnalyzer = [bool](Get-Module -ListAvailable PSScriptAnalyzer)
    if ($script:HasAnalyzer) { Import-Module PSScriptAnalyzer }
    $script:AnalyzerSettings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
}

Describe 'Static analysis: <Name>' -ForEach $script:AllScripts {

    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors) | Out-Null
        # Surface the actual parse error text on failure rather than just a count.
        $detail = if ($errors) { ($errors | ForEach-Object { "L$($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ' } else { '' }
        @($errors).Count | Should -Be 0 -Because $detail
    }

    It 'has no Error-severity PSScriptAnalyzer findings' {
        if (-not $script:HasAnalyzer) {
            Set-ItResult -Skipped -Because 'PSScriptAnalyzer is not installed'
            return
        }
        $findings = Invoke-ScriptAnalyzer -Path $Path -Severity Error -Settings $script:AnalyzerSettings
        $detail = ($findings | ForEach-Object { "L$($_.Line) $($_.RuleName): $($_.Message)" }) -join ' | '
        @($findings).Count | Should -Be 0 -Because $detail
    }
}

Describe 'Imaging hygiene: <Name>' -ForEach $script:ImagingScripts {

    It 'contains no em-dash, en-dash, smart quotes, or ellipsis (ASCII punctuation only)' {
        $text = Get-Content -LiteralPath $Path -Raw
        $matches = [regex]::Matches($text, "[–—‘’“”…]")
        $detail = ($matches | ForEach-Object { "U+{0:X4}" -f [int][char]$_.Value } | Select-Object -Unique) -join ', '
        @($matches).Count | Should -Be 0 -Because "found: $detail"
    }

    It 'resolves its dot-sourced ImageHardeningLib.ps1 path when it uses one' {
        $text = Get-Content -LiteralPath $Path -Raw
        if ($text -notmatch 'ImageHardeningLib\.ps1') {
            Set-ItResult -Skipped -Because 'script does not dot-source the library'
            return
        }
        # The scripts dot-source via "$PSScriptRoot\ImageHardeningLib.ps1"; the
        # library is a sibling, so it must exist next to the script.
        $sibling = Join-Path (Split-Path -Parent $Path) 'ImageHardeningLib.ps1'
        Test-Path -LiteralPath $sibling | Should -BeTrue
    }
}
