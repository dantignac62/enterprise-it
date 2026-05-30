<#
.SYNOPSIS
    Shared helpers for the imaging Pester suite.

.DESCRIPTION
    Two jobs:
      1. Path discovery - locate the imaging directory and the repo root from
         wherever a test file lives, so tests are runnable from any CWD.
      2. Function extraction - several functions under test (Set-EdgeUrlListKey,
         Test-AppxPatternMatch, ...) live inside executable scripts that run
         top-level code (CIM lookups, registry writes) the moment they are
         dot-sourced. We cannot dot-source those scripts in a test without
         side effects, so Import-ScriptFunctionText parses the file and returns
         the source text of just the named function definitions. The caller
         dot-sources that text via [scriptblock]::Create so the functions land
         in the test scope with nothing else executed.
#>

Set-StrictMode -Version Latest

# tests/ -> imaging/ -> imaging/.. (endpoint-engineering) -> repo root
$script:ImagingDir = Split-Path -Parent $PSScriptRoot
$script:RepoRoot   = (Resolve-Path (Join-Path $script:ImagingDir '..\..')).Path

function Get-ImagingDir { $script:ImagingDir }
function Get-RepoRoot   { $script:RepoRoot }

function Get-ImagingScript {
    <#
    .SYNOPSIS
        Absolute path to a script in the imaging directory by file name.
    #>
    param([Parameter(Mandatory)][string]$Name)
    Join-Path $script:ImagingDir $Name
}

function Import-ScriptFunctionText {
    <#
    .SYNOPSIS
        Returns the source text of the named function definition(s) found in a
        PowerShell file, WITHOUT executing any of the file's top-level code.
    .DESCRIPTION
        Parses the file to an AST, finds FunctionDefinitionAst nodes at any
        depth, and concatenates the .Extent.Text of the ones whose name matches
        -Name. Dot-source the result with:
            . ([scriptblock]::Create((Import-ScriptFunctionText -Path $p -Name 'Foo')))
        Throws if the file has parse errors or a requested function is absent,
        so a renamed/removed function fails the test loudly instead of silently
        testing nothing.
    .PARAMETER Path
        Absolute path to the .ps1 file.
    .PARAMETER Name
        One or more function names to extract.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Script not found: $Path" }

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw "Parse errors in '$Path': $(( $errors | ForEach-Object { $_.Message }) -join '; ')"
    }

    $found = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
        $true)

    $texts = New-Object System.Collections.Generic.List[string]
    foreach ($wanted in $Name) {
        $match = $found | Where-Object { $_.Name -eq $wanted } | Select-Object -First 1
        if (-not $match) {
            throw "Function '$wanted' not found in '$Path'. Present: $(($found.Name) -join ', ')"
        }
        $texts.Add($match.Extent.Text)
    }
    return ($texts -join "`n`n")
}

function Get-RepoPowerShellFile {
    <#
    .SYNOPSIS
        All tracked .ps1 files under the repo root (recursive), excluding the
        tests directory itself. Used by the repo-wide static analysis tests.
    #>
    Get-ChildItem -Path $script:RepoRoot -Recurse -File -Filter '*.ps1' |
        Where-Object { $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar)tests$([IO.Path]::DirectorySeparatorChar)*" } |
        Sort-Object FullName
}

function Get-ImagingPowerShellFile {
    <#
    .SYNOPSIS
        All .ps1 files directly in the imaging directory (the hardening
        scripts + library), excluding tests.
    #>
    Get-ChildItem -Path $script:ImagingDir -File -Filter '*.ps1' | Sort-Object Name
}

function Get-ManifestSchemaPair {
    <#
    .SYNOPSIS
        Pairs every *.manifest.json under the imaging manifests tree with the
        schema file named in its own "$schema" property (resolved relative to
        the manifest). Returns hashtables (so Pester -ForEach binds the keys as
        $Name/$Manifest/$Schema/... variables) with Manifest, Schema, and
        SchemaExists. Manifests with no "$schema" field are returned with
        Schema = $null so the test can report them rather than silently skipping.
    #>
    $manifestRoot = Join-Path $script:ImagingDir 'manifests'
    $pairs = New-Object System.Collections.Generic.List[object]
    Get-ChildItem -Path $manifestRoot -Recurse -File -Filter '*.manifest.json' |
        Sort-Object FullName | ForEach-Object {
            $m = $_
            $schemaRef = $null
            try {
                $json = Get-Content -LiteralPath $m.FullName -Raw | ConvertFrom-Json
                $schemaRef = $json.'$schema'
            } catch { }
            $schemaPath = $null
            if ($schemaRef) {
                # Strip any leading ./ and resolve relative to the manifest dir.
                $rel = $schemaRef -replace '^\./', ''
                $schemaPath = Join-Path (Split-Path -Parent $m.FullName) $rel
            }
            $pairs.Add(@{
                Name         = $m.Name
                Manifest     = $m.FullName
                SchemaRef    = $schemaRef
                Schema       = $schemaPath
                SchemaExists = [bool]($schemaPath -and (Test-Path -LiteralPath $schemaPath))
            })
        }
    return $pairs.ToArray()
}
