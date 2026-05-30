#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Validates every *.manifest.json against the JSON Schema named in its own
    "$schema" property, using Test-Json -Schema (PowerShell 6+). This is the
    cheapest high-value coverage in the suite: it catches manifest drift
    (renamed/removed required fields, wrong value types, typo'd enum values)
    the moment a manifest is hand-edited, before any script consumes it.

    Data-driven via -ForEach so each manifest gets its own It result line.
#>

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Pairs = Get-ManifestSchemaPair
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    # Recompute at run time: BeforeDiscovery variables are not visible here.
    $script:RuntimePairs = Get-ManifestSchemaPair
}

Describe 'Manifest inventory' {
    It 'discovers at least one manifest to validate' {
        @($script:RuntimePairs).Count | Should -BeGreaterThan 0
    }
}

Describe 'Manifest <Name>' -ForEach $script:Pairs {

    It 'is well-formed JSON' {
        { Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'declares a $schema reference' {
        $SchemaRef | Should -Not -BeNullOrEmpty -Because 'each manifest should point at the schema that governs it'
    }

    It 'references a schema file that exists on disk' -Skip:(-not $SchemaRef) {
        $SchemaExists | Should -BeTrue -Because "referenced schema '$SchemaRef' should resolve next to the manifest"
    }

    It 'has a schema that is itself well-formed JSON' -Skip:(-not $SchemaExists) {
        { Get-Content -LiteralPath $Schema -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'validates against its declared schema' -Skip:(-not $SchemaExists) {
        $manifestJson = Get-Content -LiteralPath $Manifest -Raw
        $schemaJson   = Get-Content -LiteralPath $Schema   -Raw
        # Test-Json throws (not returns $false) on schema-validation failure,
        # surfacing the offending path/keyword in the message.
        { $manifestJson | Test-Json -Schema $schemaJson -ErrorAction Stop } |
            Should -Not -Throw
    }
}
