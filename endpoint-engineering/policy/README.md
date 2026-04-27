# policy

Configuration policy applied to endpoints via Group Policy (Active Directory) and Intune (Entra).

## What goes here

- **GPO exports** — `Backup-GPO` output, organized by GPO name. Include `gpreport.xml` for human-readable diffs.
- **Intune profiles** — exported configuration profiles (JSON via Graph), compliance policies, security baselines.
- **CIS / HITRUST mappings** — spreadsheets or markdown tables linking control IDs to specific GPO settings or Intune profile values.
- **OU and assignment documentation** — which GPOs link to which OUs, which Intune profiles target which groups, and the precedence rules between them.

## Conventions

- GPO backups: one directory per GPO, named after the GPO display name (sanitized). Include the GPO GUID in a `metadata.txt` rather than as a directory name — GUIDs are environment-specific and complicate cross-environment restoration.
- Intune profiles exported as JSON, prettified for diff-friendliness.
- Document the policy source-of-truth boundary: settings managed by GPO must not also be set by Intune (and vice versa) to avoid conflict-induced drift. Maintain a settings matrix if the line is non-obvious.

## Restoring a GPO

GPO backup GUIDs contain machine-specific data and are gitignored by default. To intentionally version a GPO backup, force-add it (`git add -f`) and document the import procedure in the GPO's directory README.
