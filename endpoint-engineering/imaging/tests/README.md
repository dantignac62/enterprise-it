# Imaging hardening test suite

Pester 5 tests for the Windows 11 25H2 image-hardening scripts in
`endpoint-engineering/imaging/`.

## Prerequisites

Install once per machine (PowerShell 7 / `pwsh` recommended):

```powershell
Install-Module Pester          -Scope CurrentUser -MinimumVersion 5.0.0 -Force -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -SkipPublisherCheck
```

## Running

```powershell
# All tests, from this directory:
pwsh -NoProfile -File .\Invoke-Tests.ps1

# One file / pattern, more detail:
pwsh -NoProfile -File .\Invoke-Tests.ps1 -Path .\ImageHardeningLib.Tests.ps1 -Output Diagnostic

# CI mode (writes NUnit XML to .\results\):
pwsh -NoProfile -File .\Invoke-Tests.ps1 -CI
```

`Invoke-Tests.ps1` exits `0` when all tests pass, `1` on any failure, `2` if
Pester 5.x is missing — suitable as a pipeline gate.

## What is covered

| File | Scope | What it checks |
| --- | --- | --- |
| `ImageHardeningLib.Tests.ps1` | The shared library (15 functions) | Pure transforms (`ConvertTo-FlatDict`, `Get-StateDelta`), manifest parsing/validation, logging counters & DEBUG gating, JSONL change ledger, **idempotent** registry writes (APPLIED vs VERIFIED, `/`-path .NET fallback routing, error-not-throw), and pre/post snapshot + delta — all with the registry and state readback **mocked**, so no machine state is touched. |
| `Manifests.Schema.Tests.ps1` | Every `*.manifest.json` | Validates each manifest against the JSON Schema named in its own `$schema` field via `Test-Json`. Catches manifest drift before a script consumes it. Data-driven — add a manifest, it's tested automatically. |
| `EdgeAndDebloat.Tests.ps1` | `Set-EdgeUrlListKey`, `Test-AppxPatternMatch` | Behavior of functions that live inside executable scripts. The Edge function's registry calls are mocked (correct path/SID, indexed values, idempotent reset, `-WhatIf` honored); the AppX matcher is tested as a pure predicate. |
| `Scripts.Static.Tests.ps1` | **All** `.ps1` in the repo | Parses without syntax errors; no Error-severity PSScriptAnalyzer findings; (imaging only) ASCII-punctuation-only and a resolvable dot-sourced library path. Guards the "unrunnable script / em-dash" regression class directly. |

## Design notes

- **Functions inside executable scripts.** Several scripts (`Set-EdgeUrlPolicy.ps1`,
  `Invoke-Win11Debloat.ps1`) run top-level code — CIM user lookups, hive checks,
  registry writes — the instant they are dot-sourced, so they cannot be loaded
  in a test. `TestHelpers.ps1::Import-ScriptFunctionText` parses the file to an
  AST and returns just the named function's source, which the test dot-sources
  in isolation. A renamed/removed function makes the test fail loudly rather
  than silently testing nothing.

- **No real system mutation.** Every registry/CIM/state call is mocked or
  routed through `$TestDrive`. The suite is safe to run on a developer machine.

- **Analyzer scope.** `PSScriptAnalyzerSettings.psd1` excludes two rules that
  are deliberate design choices here (`PSAvoidUsingWriteHost` — these are
  operator-facing console tools; `PSAvoidUsingEmptyCatchBlock` — the readback
  helpers are documented best-effort). The test gates on **Error** severity;
  warnings are reported but do not fail the build.

## Known advisory findings (not failures)

Surfaced by the analyzer, left for the maintainer to decide on — none break a run:

- `Invoke-HardeningOrchestrator.ps1`: `$skippedStages` is assigned but never
  used (orphaned when the reboot/skip logic was removed in v2.0.0).
- `identity-access/.../Convert-EntitlementSnapshot.ps1`: a few `OutputType`
  / singular-noun style warnings.

## Extending

- **New library function** → add a `Describe` to `ImageHardeningLib.Tests.ps1`.
- **New manifest** → nothing to do; it's picked up automatically.
- **New function inside a script** → extract it with `Import-ScriptFunctionText`
  and test in isolation (see `EdgeAndDebloat.Tests.ps1` for the pattern).
- **New script anywhere** → automatically gets parse + analyzer coverage.
