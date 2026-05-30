#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Behavioral tests for the revert helpers in Remove-CISL1Hardening.ps1
    (Remove-HardenedRegistryValue, Restore-ServiceStartType). The script runs
    top-level code on load (Initialize-HardeningLog, manifest read, snapshots),
    so the functions are AST-extracted and dot-sourced in isolation. The
    library is dot-sourced for Write-Log/Write-ChangeEvent, and registry/service
    cmdlets are mocked -- no machine state is touched.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Get-ImagingScript 'ImageHardeningLib.ps1')
    . ([scriptblock]::Create(
        (Import-ScriptFunctionText -Path (Get-ImagingScript 'Remove-CISL1Hardening.ps1') `
            -Name 'Remove-HardenedRegistryValue','Restore-ServiceStartType')))

    function Read-Ledger {
        param([string]$LogPath)
        $changes = $LogPath -replace '\.log$', '.changes.jsonl'
        # [IO.File]::Exists, not Test-Path: some tests mock Test-Path, which
        # would otherwise make this helper misreport the ledger as missing.
        if (-not [System.IO.File]::Exists($changes)) { return @() }
        Get-Content -LiteralPath $changes | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    }
}

Describe 'Remove-HardenedRegistryValue' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("rev_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'RevertTest' -Quiet
    }

    It 'removes the value when present (APPLIED)' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ NoConnectedUser = 3 } }
        Mock Remove-ItemProperty { }

        Remove-HardenedRegistryValue -Path 'HKLM:\SOFTWARE\X' -Name 'NoConnectedUser' -Description 'Block MSA'

        Should -Invoke Remove-ItemProperty -Times 1 -Exactly
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'APPLIED'
    }

    It 'is a no-op (NOT_APPLICABLE) when the key is absent' {
        Mock Test-Path { $false }
        Mock Remove-ItemProperty { }

        Remove-HardenedRegistryValue -Path 'HKLM:\SOFTWARE\Missing' -Name 'V' -Description 'x'

        Should -Invoke Remove-ItemProperty -Times 0 -Exactly
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'NOT_APPLICABLE'
    }

    It 'is a no-op when the key exists but the value does not' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ SomethingElse = 1 } }
        Mock Remove-ItemProperty { }

        Remove-HardenedRegistryValue -Path 'HKLM:\SOFTWARE\X' -Name 'NoConnectedUser' -Description 'Block MSA'

        Should -Invoke Remove-ItemProperty -Times 0 -Exactly
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'NOT_APPLICABLE'
    }

    It 'honors -WhatIf: no removal' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ V = 1 } }
        Mock Remove-ItemProperty { }

        Remove-HardenedRegistryValue -Path 'HKLM:\SOFTWARE\X' -Name 'V' -Description 'x' -WhatIf

        Should -Invoke Remove-ItemProperty -Times 0 -Exactly
    }

    It 'logs an ERROR (not a throw) when removal fails' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ V = 1 } }
        Mock Remove-ItemProperty { throw 'access denied' }

        { Remove-HardenedRegistryValue -Path 'HKLM:\SOFTWARE\X' -Name 'V' -Description 'x' } |
            Should -Not -Throw
        Write-LogSummary -ScriptName 'RevertTest' 6>$null
        $sidecar = $script:Log -replace '\.log$', '.summary.json'
        (Get-Content $sidecar -Raw | ConvertFrom-Json).Counters.Errors | Should -Be 1
    }
}

Describe 'Restore-ServiceStartType' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("svc_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'RevertTest' -Quiet
    }

    It 'sets the start type when it differs (APPLIED)' {
        Mock Get-Service { [pscustomobject]@{ Name = 'WpnService'; StartType = 'Disabled'; Status = 'Stopped' } }
        Mock Set-Service { }

        Restore-ServiceStartType -Name 'WpnService' -StartType 'Automatic' -Description 'Push Notifications'

        Should -Invoke Set-Service -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'WpnService' -and $StartupType -eq 'Automatic'
        }
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'APPLIED'
    }

    It 'is a no-op (NOT_APPLICABLE) when the service is not installed' {
        Mock Get-Service { $null }
        Mock Set-Service { }

        Restore-ServiceStartType -Name 'sshd' -StartType 'Manual' -Description 'OpenSSH Server'

        Should -Invoke Set-Service -Times 0 -Exactly
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'NOT_APPLICABLE'
    }

    It 'is idempotent (VERIFIED) when already at the target start type' {
        Mock Get-Service { [pscustomobject]@{ Name = 'LxssManager'; StartType = 'Manual'; Status = 'Stopped' } }
        Mock Set-Service { }

        Restore-ServiceStartType -Name 'LxssManager' -StartType 'Manual' -Description 'WSL'

        Should -Invoke Set-Service -Times 0 -Exactly
        (@(Read-Ledger -LogPath $script:Log))[-1].Action | Should -Be 'VERIFIED'
    }

    It 'honors -WhatIf: no change' {
        Mock Get-Service { [pscustomobject]@{ Name = 'WpnService'; StartType = 'Disabled'; Status = 'Stopped' } }
        Mock Set-Service { }

        Restore-ServiceStartType -Name 'WpnService' -StartType 'Automatic' -Description 'Push Notifications' -WhatIf

        Should -Invoke Set-Service -Times 0 -Exactly
    }
}
