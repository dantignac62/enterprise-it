# lifecycle

Scripts that manage account state transitions after initial provisioning.

## What goes here

- **Leave of absence** — `Set-UserOnLeave.ps1`: disable account, remove from sensitive groups while preserving role membership for restoration, set descriptive attribute, escrow any required keys.
- **Return from LOA** — `Set-UserReturnFromLOA.ps1`: re-enable, restore group memberships from the user's role definition, force password change at next logon.
- **Termination** — `Invoke-ADUserTermination.ps1`: disable, remove from all groups, move to a terminated-users OU, hide from GAL, set termination metadata, trigger downstream offboarding (mailbox conversion, license release, BitLocker key retention check).
- **Role changes** — scripts that swap a user from one role definition to another, removing old entitlements and applying new ones in a single atomic operation.
- **Password policy enforcement** — bulk password resets, expiry sweeps, policy compliance reports.

## Conventions

- Every lifecycle script captures a "before" state snapshot to a structured log so the action is reversible (or at least auditable).
- Termination scripts run with explicit confirmation prompts unless invoked with a `-Confirm:$false` flag, which itself should require an `-OperatorTicket <id>` parameter for traceability.
- LOA and termination both rely on the role definitions in `../entitlements/` — the "before" group set should match the user's assigned role; deviations are flagged for manual review.

## Audit trail

Lifecycle actions are high-impact and high-scrutiny. Logs from these scripts should be written to a tamper-evident location (e.g., a write-only share, SIEM forwarder) in addition to the local log path.
