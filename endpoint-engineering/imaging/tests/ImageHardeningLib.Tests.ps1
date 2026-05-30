#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Unit tests for ImageHardeningLib.ps1.

    The library only defines functions and module-scoped state at load time
    (no top-level side effects), so it is safe to dot-source directly. All
    functions share $script:-scoped state (LogFile, Counters, ChangesFile,
    SnapshotStamp); tests that touch that state call Initialize-HardeningLog
    in a BeforeEach to reset it, and use $TestDrive for any file output.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Get-ImagingScript 'ImageHardeningLib.ps1')

    # Read the counters/sidecar a run produced. Write-LogSummary emits
    # <stem>.summary.json next to the log; we assert against that rather than
    # the private $script:Counters.
    function Read-Summary {
        param([string]$LogPath)
        $sidecar = $LogPath -replace '\.log$', '.summary.json'
        Get-Content -LiteralPath $sidecar -Raw | ConvertFrom-Json
    }
    function Read-Ledger {
        param([string]$LogPath)
        $changes = $LogPath -replace '\.log$', '.changes.jsonl'
        if (-not (Test-Path $changes)) { return @() }
        Get-Content -LiteralPath $changes | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
    }
}

Describe 'ConvertTo-FlatDict' {
    It 'flattens a nested dictionary into dotted paths' {
        $r = ConvertTo-FlatDict -Obj ([ordered]@{ a = [ordered]@{ b = 1; c = 2 } })
        $r['a.b'] | Should -Be 1
        $r['a.c'] | Should -Be 2
    }

    It 'suffixes array elements with [i]' {
        $r = ConvertTo-FlatDict -Obj ([ordered]@{ list = @('x','y') })
        $r['list[0]'] | Should -Be 'x'
        $r['list[1]'] | Should -Be 'y'
    }

    It 'maps a null object to a single null leaf at the prefix' {
        $r = ConvertTo-FlatDict -Obj $null -Prefix 'root'
        $r.ContainsKey('root') | Should -BeTrue
        $r['root'] | Should -BeNullOrEmpty
    }

    It 'treats a string as a scalar, not an enumerable of chars' {
        $r = ConvertTo-FlatDict -Obj 'hello' -Prefix 'k'
        $r['k'] | Should -Be 'hello'
        $r.Keys.Count | Should -Be 1
    }
}

Describe 'Get-StateDelta' {
    It 'returns no deltas for identical state' {
        $s = [ordered]@{ a = 1; b = [ordered]@{ c = 2 } }
        $d = Get-StateDelta -Before $s -After $s
        @($d).Count | Should -Be 0
    }

    It 'reports a changed leaf with old and new values' {
        $before = [ordered]@{ a = 1 }
        $after  = [ordered]@{ a = 2 }
        $d = @(Get-StateDelta -Before $before -After $after)
        $d.Count | Should -Be 1
        $d[0].Path | Should -Be 'a'
        $d[0].OldValue | Should -Be 1
        $d[0].NewValue | Should -Be 2
    }

    It 'surfaces an added leaf as OldValue=null' {
        $d = @(Get-StateDelta -Before ([ordered]@{}) -After ([ordered]@{ x = 5 }))
        $d.Count | Should -Be 1
        $d[0].Path | Should -Be 'x'
        $d[0].OldValue | Should -BeNullOrEmpty
        $d[0].NewValue | Should -Be 5
    }

    It 'always returns an array, even for a single delta (comma operator)' {
        $d = Get-StateDelta -Before ([ordered]@{ a = 1 }) -After ([ordered]@{ a = 9 })
        ,$d | Should -BeOfType [System.Object[]]
    }
}

Describe 'Read-HardeningManifest' {
    It 'throws when the file does not exist' {
        { Read-HardeningManifest -Path (Join-Path $TestDrive 'nope.json') } |
            Should -Throw -ExpectedMessage '*not found*'
    }

    It 'throws on malformed JSON' {
        $p = Join-Path $TestDrive 'bad.json'
        '{ this is not json' | Set-Content -LiteralPath $p
        { Read-HardeningManifest -Path $p } | Should -Throw -ExpectedMessage '*Failed to parse*'
    }

    It 'throws when a required top-level field is missing' {
        $p = Join-Path $TestDrive 'noversion.json'
        '{ "name": "x" }' | Set-Content -LiteralPath $p
        { Read-HardeningManifest -Path $p } | Should -Throw -ExpectedMessage '*missing required field: version*'
    }

    It 'throws when a required section is missing' {
        $p = Join-Path $TestDrive 'nosection.json'
        '{ "name": "x", "version": "1.0.0" }' | Set-Content -LiteralPath $p
        { Read-HardeningManifest -Path $p -RequiredSections 'registrySettings' } |
            Should -Throw -ExpectedMessage '*missing required section: registrySettings*'
    }

    It 'returns the parsed object for a valid manifest' {
        $p = Join-Path $TestDrive 'good.json'
        '{ "name": "x", "version": "2.0.0", "registrySettings": [] }' | Set-Content -LiteralPath $p
        $m = Read-HardeningManifest -Path $p -RequiredSections 'registrySettings'
        $m.name    | Should -Be 'x'
        $m.version | Should -Be '2.0.0'
    }
}

Describe 'Logging: counters and levels' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("log_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'Test' -Quiet
        Set-HardeningDebug -Enabled $false
    }

    It 'tallies APPLIED, SKIP, SKIP_MANIFEST, WARN, and ERROR independently' {
        Write-Log 'a' -Level APPLIED
        Write-Log 'b' -Level APPLIED
        Write-Log 'c' -Level SKIP
        Write-Log 'd' -Level SKIP_MANIFEST
        Write-Log 'e' -Level WARN
        Write-Log 'f' -Level ERROR
        Write-LogSummary -ScriptName 'Test' 6>$null  # 6>$null: silence the console summary box (still written to the log + sidecar)

        $c = (Read-Summary -LogPath $script:Log).Counters
        $c.Applied           | Should -Be 2
        $c.Skipped           | Should -Be 1
        $c.SkippedByManifest | Should -Be 1
        $c.Warned            | Should -Be 1
        $c.Errors            | Should -Be 1
    }

    It 'drops DEBUG entries unless debug logging is enabled' {
        Write-Log 'hidden' -Level DEBUG
        (Get-Content -LiteralPath $script:Log -Raw) | Should -Not -Match 'hidden'

        Set-HardeningDebug -Enabled $true
        Write-Log 'shown' -Level DEBUG
        (Get-Content -LiteralPath $script:Log -Raw) | Should -Match 'shown'
    }

    It 'resets counters on each Initialize-HardeningLog call' {
        Write-Log 'x' -Level APPLIED
        $log2 = Join-Path $TestDrive 'fresh.log'
        Initialize-HardeningLog -LogPath $log2 -Component 'Test' -Quiet
        Write-LogSummary -ScriptName 'Test' 6>$null  # 6>$null: silence the console summary box (still written to the log + sidecar)
        (Read-Summary -LogPath $log2).Counters.Applied | Should -Be 0
    }

    It 'writes CMTrace-formatted lines to the log file' {
        Write-Log 'hello world' -Level INFO
        (Get-Content -LiteralPath $script:Log -Raw) | Should -Match '<!\[LOG\[\[INFO\] hello world\]LOG\]!>'
    }
}

Describe 'Write-ChangeEvent and the JSONL ledger' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("evt_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'Test' -Quiet
    }

    It 'appends one parseable JSON object per event' {
        Write-ChangeEvent -Action APPLIED -Category Registry -Target 'HKLM:\X\Y' -Description 'set y' -Details @{ NewValue = 1 }
        Write-ChangeEvent -Action VERIFIED -Category Registry -Target 'HKLM:\X\Z' -Description 'z ok'
        $events = @(Read-Ledger -LogPath $script:Log)
        $events.Count | Should -Be 2
        $events[0].Action  | Should -Be 'APPLIED'
        $events[0].Details.NewValue | Should -Be 1
        $events[1].Action  | Should -Be 'VERIFIED'
    }

    It 'starts each run with an empty ledger' {
        @(Read-Ledger -LogPath $script:Log).Count | Should -Be 0
    }
}

Describe 'Skip-ByManifest' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("skip_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'Test' -Quiet
    }

    It 'increments the SkippedByManifest counter and emits a SKIPPED_BY_MANIFEST event' {
        Skip-ByManifest -Description 'Disable Copilot' -Category 'Registry' -Target 'HKLM:\...\Copilot' -CISRef '1.2.3'
        Write-LogSummary -ScriptName 'Test' 6>$null  # 6>$null: silence the console summary box (still written to the log + sidecar)

        (Read-Summary -LogPath $script:Log).Counters.SkippedByManifest | Should -Be 1

        $evt = @(Read-Ledger -LogPath $script:Log)
        $evt.Count | Should -Be 1
        $evt[0].Action | Should -Be 'SKIPPED_BY_MANIFEST'
        $evt[0].Details.CISRef | Should -Be '1.2.3'
    }
}

Describe 'Set-HardenedRegistry (mocked registry provider)' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("reg_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'Test' -Quiet
    }

    It 'writes the value when the current value differs (APPLIED)' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ MySetting = 0 } }
        Mock Set-ItemProperty { }
        Mock New-Item { }

        Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Test' -Name 'MySetting' -Value 1 -Type DWord -Description 'enable'

        Should -Invoke Set-ItemProperty -Times 1 -Exactly
        $evt = @(Read-Ledger -LogPath $script:Log)
        $evt[-1].Action | Should -Be 'APPLIED'
    }

    It 'is idempotent: no write when the value already matches (VERIFIED)' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ MySetting = 1 } }
        Mock Set-ItemProperty { }
        Mock New-Item { }

        Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Test' -Name 'MySetting' -Value 1 -Type DWord -Description 'enable'

        Should -Invoke Set-ItemProperty -Times 0 -Exactly
        $evt = @(Read-Ledger -LogPath $script:Log)
        $evt[-1].Action | Should -Be 'VERIFIED'
    }

    It 'creates the key first when it does not exist' {
        Mock Test-Path { $false }
        Mock Get-ItemProperty { $null }
        Mock Set-ItemProperty { }
        Mock New-Item { }

        Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\New' -Name 'V' -Value 3 -Type DWord -Description 'create'

        Should -Invoke New-Item -Times 1 -Exactly
        Should -Invoke Set-ItemProperty -Times 1 -Exactly
    }

    It 'routes key paths containing "/" to the .NET fallback' {
        Mock Set-HardenedRegistryNet { }
        Mock Set-ItemProperty { }

        Set-HardenedRegistry -Path 'HKLM:\SYSTEM\...\Ciphers\DES 56/56' -Name 'Enabled' -Value 0 -Description 'disable DES'

        Should -Invoke Set-HardenedRegistryNet -Times 1 -Exactly
        Should -Invoke Set-ItemProperty -Times 0 -Exactly
    }

    It 'logs an ERROR (not a throw) when the registry write fails' {
        Mock Test-Path { $true }
        Mock Get-ItemProperty { [pscustomobject]@{ V = 0 } }
        Mock Set-ItemProperty { throw 'access denied' }
        Mock New-Item { }

        { Set-HardenedRegistry -Path 'HKLM:\SOFTWARE\Test' -Name 'V' -Value 1 -Description 'x' } |
            Should -Not -Throw
        Write-LogSummary -ScriptName 'Test' 6>$null  # 6>$null: silence the console summary box (still written to the log + sidecar)
        (Read-Summary -LogPath $script:Log).Counters.Errors | Should -Be 1
    }
}

Describe 'Set-HardenedRegistryNet' {
    BeforeEach {
        $script:Log = Join-Path $TestDrive ("net_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'Test' -Quiet
    }

    It 'logs an ERROR for a root other than HKLM:/HKCU: instead of throwing' {
        { Set-HardenedRegistryNet -Resolved 'HKCR:\Some/Key' -Name 'V' -Value 1 -Type DWord -Label 'bad root' } |
            Should -Not -Throw
        Write-LogSummary -ScriptName 'Test' 6>$null  # 6>$null: silence the console summary box (still written to the log + sidecar)
        (Read-Summary -LogPath $script:Log).Counters.Errors | Should -Be 1
    }
}

Describe 'Get-RegValue' {
    It 'returns the value when the property exists' {
        Mock Get-ItemProperty { [pscustomobject]@{ Target = 42 } }
        Get-RegValue -Path 'HKLM:\X' -Name 'Target' | Should -Be 42
    }

    It 'returns $null (never throws) when the path is absent' {
        Mock Get-ItemProperty { throw 'Cannot find path' }
        Get-RegValue -Path 'HKLM:\Missing' -Name 'Target' | Should -BeNullOrEmpty
    }
}

Describe 'Save-HardeningSnapshot (mocked state readback)' {
    BeforeEach {
        $script:Log  = Join-Path $TestDrive ("snap_{0}.log" -f ([guid]::NewGuid().ToString('n')))
        $script:Root = Join-Path $TestDrive ("Snapshots_{0}" -f ([guid]::NewGuid().ToString('n')))
        Initialize-HardeningLog -LogPath $script:Log -Component 'SnapTest' -Quiet
    }

    It 'writes pre.snapshot.json on the Pre phase' {
        Mock Get-SystemStateSnapshot { [ordered]@{ UAC = [ordered]@{ EnableLUA = 1 } } }
        $file = Save-HardeningSnapshot -Phase Pre -SnapshotRoot $script:Root
        $file | Should -Not -BeNullOrEmpty
        Test-Path $file | Should -BeTrue
        (Split-Path $file -Leaf) | Should -Be 'pre.snapshot.json'
    }

    It 'writes post.snapshot.json plus a delta.json reflecting the changed leaf' {
        # Pre returns EnableLUA=0, Post returns 1. A reference-type queue keeps
        # the two readbacks deterministic regardless of mock-scope quirks.
        $script:snapStates = [System.Collections.Queue]::new()
        $script:snapStates.Enqueue([ordered]@{ UAC = [ordered]@{ EnableLUA = 0 } })
        $script:snapStates.Enqueue([ordered]@{ UAC = [ordered]@{ EnableLUA = 1 } })
        Mock Get-SystemStateSnapshot { $script:snapStates.Dequeue() }
        Save-HardeningSnapshot -Phase Pre  -SnapshotRoot $script:Root | Out-Null
        $post = Save-HardeningSnapshot -Phase Post -SnapshotRoot $script:Root
        $deltaFile = Join-Path (Split-Path $post -Parent) 'delta.json'
        Test-Path $deltaFile | Should -BeTrue
        $delta = Get-Content -LiteralPath $deltaFile -Raw | ConvertFrom-Json
        $delta.ChangedLeafCount | Should -Be 1
        $delta.Changes[0].Path | Should -Be 'UAC.EnableLUA'
    }
}
