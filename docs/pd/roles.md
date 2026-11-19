# Harborlight PD — Roles and Permissions

> **Not enforced yet.** The roles and permissions below are defined in
> `internal/pd/roles`, but no command takes a role or checks one: anyone who can
> run `witness-pd` can run every command. The HTTP API described here was removed
> with the dashboard.

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

Role checking is implemented in `internal/pd/roles` as `Can(role, perm)`, but nothing calls it yet.

The dashboard token (`WITNESS_PD_TOKEN`) grants full access to the HTTP API. For role-scoped access, use the `witness-pd` CLI with a role flag (planned for future releases) or implement a reverse proxy that issues per-role tokens.

## Escalation on violation

A transfer under legal hold is rejected with an error. It is not yet logged as a `WARN` event, so it does not count toward the escalation threshold in the soul file. Destroy has no command yet.
