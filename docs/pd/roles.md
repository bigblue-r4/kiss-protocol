# Harborlight PD — Roles and Permissions

## Role definitions

| Role | Description |
|------|-------------|
| `chief` | Full access — all operations including destroy and node admin |
| `evidence_clerk` | Day-to-day evidence operations — intake, transfer, holds |
| `tech_admin` | System administration — node config, audit read, no evidence mutation |
| `officer` | Intake and read-only status — cannot transfer, hold, or export |
| `auditor` | Read-only — full audit trail access, no mutations |

## Permission matrix

| Permission | Chief | Evidence Clerk | Tech Admin | Officer | Auditor |
|------------|:-----:|:--------------:|:----------:|:-------:|:-------:|
| `intake` | ✓ | ✓ | | ✓ | |
| `transfer` | ✓ | ✓ | | | |
| `hold:set` | ✓ | ✓ | | | |
| `hold:release` | ✓ | ✓ | | | |
| `export` | ✓ | | | | |
| `destroy` | ✓ | | | | |
| `audit:read` | ✓ | | ✓ | | ✓ |
| `node:admin` | ✓ | | ✓ | | |
| `status` | ✓ | ✓ | ✓ | ✓ | ✓ |

## Implementation

Role checking is implemented in `internal/pd/roles`. The `Can(role, perm)` function is used by API handlers to gate operations.

The dashboard token (`WITNESS_PD_TOKEN`) grants full access to the HTTP API. For role-scoped access, use the `witness-pd` CLI with a role flag (planned for future releases) or implement a reverse proxy that issues per-role tokens.

## Escalation on violation

Any attempt to perform a prohibited action (transfer under hold, destroy under hold) is rejected with an error and logged as a `WARN` event. These events accumulate toward the escalation threshold defined in the soul file.
