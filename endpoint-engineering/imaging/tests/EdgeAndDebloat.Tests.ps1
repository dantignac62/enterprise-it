#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Behavioral tests for functions that live INSIDE executable scripts:
      - Set-EdgeUrlListKey   (Set-EdgeUrlPolicy.ps1)
      - Test-AppxPatternMatch (Invoke-Win11Debloat.ps1)

    These scripts run top-level code (CIM user lookups, hive checks, registry
    writes) the instant they are dot-sourced, so we cannot load them directly.
    Import-ScriptFunctionText (see TestHelpers.ps1) parses the file and returns
    just the named function's source, which we dot-source in isolation. The
    Edge function's registry calls are mocked; the debloat matcher is pure.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    . ([scriptblock]::Create(
        (Import-ScriptFunctionText -Path (Get-ImagingScript 'Set-EdgeUrlPolicy.ps1') -Name 'Set-EdgeUrlListKey')))
    . ([scriptblock]::Create(
        (Import-ScriptFunctionText -Path (Get-ImagingScript 'Invoke-Win11Debloat.ps1') -Name 'Test-AppxPatternMatch')))
}

Describe 'Set-EdgeUrlListKey' {
    BeforeEach {
        Mock Test-Path     { $false }
        Mock Remove-Item   { }
        Mock New-Item      { }
        Mock New-ItemProperty { }
    }

    It 'creates the policy key and one String value per URL, indexed from 1' {
        Set-EdgeUrlListKey -SID 'S-1-5-21-X' -PolicyName 'URLAllowlist' -Urls @('a.com','b.com','c.com')

        Should -Invoke New-Item -Times 1 -Exactly
        Should -Invoke New-ItemProperty -Times 3 -Exactly
        # First entry is named "1" with the first URL as a String value.
        Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq '1' -and $Value -eq 'a.com' -and $PropertyType -eq 'String'
        }
        Should -Invoke New-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Name -eq '3' -and $Value -eq 'c.com'
        }
    }

    It 'targets the per-user Edge policy path under the supplied SID' {
        Set-EdgeUrlListKey -SID 'S-1-5-21-ABC' -PolicyName 'URLBlocklist' -Urls @('*')
        Should -Invoke New-Item -Times 1 -Exactly -ParameterFilter {
            $Path -eq 'Registry::HKEY_USERS\S-1-5-21-ABC\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
        }
    }

    It 'removes a pre-existing key before recreating it (idempotent reset)' {
        Mock Test-Path { $true }   # key already present
        Set-EdgeUrlListKey -SID 'S-1-5-21-X' -PolicyName 'URLAllowlist' -Urls @('a.com')
        Should -Invoke Remove-Item -Times 1 -Exactly
        Should -Invoke New-Item    -Times 1 -Exactly
    }

    It 'honors -WhatIf: no key removal, creation, or value writes' {
        Mock Test-Path { $true }
        # Note: -WhatIf prints two "What if:" preview lines to the host. That
        # text is written by PowerShell's ShouldProcess machinery directly to
        # the console and cannot be redirected by any stream (*>$null, 6>$null,
        # etc. all leave it). It is harmless informational output -- in fact it
        # confirms the safety gate fired -- and is expected in this one test.
        Set-EdgeUrlListKey -SID 'S-1-5-21-X' -PolicyName 'URLAllowlist' -Urls @('a.com') -WhatIf
        Should -Invoke Remove-Item    -Times 0 -Exactly
        Should -Invoke New-Item       -Times 0 -Exactly
        Should -Invoke New-ItemProperty -Times 0 -Exactly
    }
}

Describe 'Test-AppxPatternMatch' {
    It 'matches when the package name contains the pattern' {
        Test-AppxPatternMatch -PackageName 'Microsoft.BingNews_8wekyb3d8bbwe' -Patterns @('BingNews') |
            Should -BeTrue
    }

    It 'treats a trailing wildcard as a contains-match (wildcard is trimmed)' {
        Test-AppxPatternMatch -PackageName 'Microsoft.XboxGamingOverlay' -Patterns @('Xbox*') |
            Should -BeTrue
    }

    It 'returns false when no pattern is contained in the package name' {
        Test-AppxPatternMatch -PackageName 'Microsoft.WindowsCalculator' -Patterns @('Xbox','BingNews') |
            Should -BeFalse
    }

    It 'returns false for an empty pattern set' {
        Test-AppxPatternMatch -PackageName 'Anything' -Patterns @() | Should -BeFalse
    }

    It 'matches if any one of several patterns is contained' {
        Test-AppxPatternMatch -PackageName 'Microsoft.ZuneMusic' -Patterns @('Xbox','Zune','Bing') |
            Should -BeTrue
    }

    It 'is case-insensitive (PowerShell -like semantics)' {
        Test-AppxPatternMatch -PackageName 'Microsoft.BINGWEATHER' -Patterns @('bingweather') |
            Should -BeTrue
    }
}
