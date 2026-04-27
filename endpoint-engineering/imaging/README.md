# imaging

Scripts and supporting artifacts for building and hardening the Windows gold image.

## Layout

- `*.ps1` — hardening scripts and the orchestrator. Each manifest-driven script has a sibling JSON manifest in `manifests/`.
- `ImageHardeningLib.ps1` — shared library: CMTrace logging, change ledger, idempotent registry write helper, manifest loader, manifest-skip helper.
- `Invoke-HardeningOrchestrator.ps1` — top-level runner. Executes the hardening stages in order, captures pre/post state snapshots, and emits the HITRUST evidence artifact (`Evidence/<timestamp>/report.{json,md}`).
- `manifests/` — JSON manifests and JSON Schemas for the manifest-driven hardening scripts.

## Conventions

- Hardening runs **online** against the live OS, intended for execution inside an audit-mode VM before `sysprep /generalize /oobe /shutdown` and DISM capture. Offline image servicing (mounted-WIM hardening, DISM slipstream patching) is not supported.
- **Patching is a manual precondition.** The operator runs Windows Update via the Settings UI before invoking `Invoke-HardeningOrchestrator.ps1`. The orchestrator does not install updates and does not survive reboots — bring the OS to the desired Build.UBR first.
- All scripts log to `$LogPath` (defaults to `.\Logs\` next to the script) and emit progress to the console. Each script also writes a `<stem>.summary.json` sidecar and `<stem>.changes.jsonl` ledger consumed by the orchestrator's evidence artifact.
- No Unicode in string literals — PowerShell 5.1 cannot parse non-ASCII characters under ANSI codepage. Use ASCII equivalents (`->` not `→`, `--` not `—`).

## Manifests

Manifest-driven hardening scripts read their controls from a sibling JSON file in `manifests/`. The manifest is the operator's source of truth for *what* the script does; the script is just the engine.

- **Switch-style.** Every control has an `"enabled": true|false` flag. `false` skips the control while preserving it in the audit trail (logged as `SKIPPED_BY_MANIFEST` in the change ledger). Add or remove entries to widen or narrow the universe of controls considered.
- **JSON Schema.** Each manifest references a sibling `*.manifest.schema.json` via the `$schema` field. VS Code (and any editor with JSON Schema support) gives autocomplete on field names, type validation, registry-path prefix checks, and red squiggles on missing required fields. No tooling install needed.
- **Distinct audit actions** in the change ledger:
  - `APPLIED` — control was applied (state transition).
  - `VERIFIED` — control was already at target.
  - `NOT_APPLICABLE` — target object does not exist on this image.
  - `SKIPPED_BY_MANIFEST` — control intentionally disabled in the manifest.

## Image lineage

Document each gold image release as a tagged commit. Image metadata (build date, source ISO version, applied baselines) belongs in the manifest workbook checked in alongside the scripts.
