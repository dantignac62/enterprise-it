# identity-access

Identity & Access Management (IAM) and Identity Governance & Administration (IGA) for the enterprise.

## Scope

Answers the question: **who is this person and what can they access?**

Anything that creates, modifies, or removes a user account — or grants/revokes access via group membership — belongs here. This spans Active Directory, Microsoft Entra, and any downstream system whose access is provisioned via group entitlement.

## Subdirectories

- **`provisioning/`** — New user creation, role assignment at hire, template-based account setup.
- **`lifecycle/`** — Leave of absence, return from LOA, role changes, termination, recertification.
- **`entitlements/`** — Role definitions, role-to-group mappings, exception tracking, recertification reports.

## What does NOT go here

- Workstation configuration, image hardening, software deployment → `endpoint-engineering/`
- BitLocker recovery key escrow *policy* → `endpoint-engineering/policy/`
  *(Recovery key retrieval as part of an offboarding workflow may live in `lifecycle/` if it is a step in the termination procedure.)*

## Multi-domain considerations

Operational tooling that spans multiple AD domains (e.g., PowerShell profile functions for cross-domain user lookups) lives in `provisioning/` if it acts on accounts, or as a top-level helper module if it is purely diagnostic.
