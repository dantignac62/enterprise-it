# entitlements

Role definitions, group entitlements, and the governance layer that keeps them honest.

## What goes here

- **Role definitions** — structured files (JSON, YAML, or PSD1) declaring the canonical set of group memberships, license SKUs, and access grants for each role. The source of truth for what a role *is*.
- **Role-to-group mappings** — the human-readable matrix view of role definitions, useful for review and recertification.
- **Exception tracking** — documented deviations from baseline role definitions (time-bounded access grants, one-off entitlements).
- **Recertification** — scripts or reports that compare current user group memberships against their assigned role baseline and flag drift.

## Governance

- Role definitions are the source of truth. Manual group additions outside these definitions are considered drift.
- Changes to role definitions should go through PR review with justification.
- Exception grants should include an expiry date and a linked ticket/approval reference.

## Naming Conventions

- Security groups: `G_` prefix (e.g., `G_VPN_Standard`)
- Distribution lists: `DL_` prefix (e.g., `DL_Finance_All`)
- Role groups (if using nested RBAC model): `Role_` prefix (e.g., `Role_Helpdesk_L1`)
