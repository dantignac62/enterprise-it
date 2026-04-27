# endpoint-engineering

The discipline of defining, building, and maintaining the standard operating environment (SOE) for Windows endpoints — from base image through policy through software delivery.

## Scope

Answers the question: **what does the machine look like?**

Anything that changes the configuration, hardening posture, or installed software of a workstation belongs here. This includes both Active Directory (GPO) and Microsoft Entra (Intune) policy artifacts, since both target endpoint state.

## Subdirectories

- **`imaging/`** — Gold image construction and hardening (CIS-aligned baselines, debloat, cipher/TLS hardening, BitLocker configuration). Reusable hardening library if shared across scripts.
- **`policy/`** — GPO exports/backups, Intune configuration profiles, compliance baselines, and CIS/HITRUST control mappings.
- **`software/`** — Win32App packaging pipeline, application install scripts, deployment manifests for Intune.

## What does NOT go here

- User account creation, role definitions, group entitlements → `identity-access/`
- BitLocker recovery key escrow *policy* lives here; *recovery key retrieval scripts* for support staff are operational tooling and may live in `identity-access/lifecycle/` if tied to user offboarding.
