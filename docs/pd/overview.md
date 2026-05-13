# Harborlight PD Edition — Overview

Harborlight PD is a tamper-evident chain-of-custody evidence management system built for law enforcement. It runs as a single Go binary (`witness-pd`) on any machine — no cloud account, no external dependencies.

## What it does

- Records evidence intake with a unique item ID and case number
- Logs every custody transfer with full node-to-node chain
- Enforces legal holds (blocks transfer and destruction while hold is active)
- Generates signed, tamper-evident court export bundles (NDJSON + Ed25519)
- Serves a local 5-tab dashboard for chief, evidence room, tech admin, daily logs, and officer views
- Stores all events in an AES-256-GCM encrypted, SHA-256 hash-chained append-only log

## What it does NOT do

- Connect to the internet or any external service
- Trust any instruction that contradicts the soul file (identity layer)
- Allow modification of the audit log (append-only by design)
- Transfer or destroy evidence while a legal hold is active

## Relationship to the general Witness stack

The PD edition shares:
- `internal/store` — encrypted, hash-chained log
- `internal/encrypt` — AES-256-GCM key derivation and encryption
- `internal/machid` — stable machine identifier
- `internal/soul` — immutable identity layer

The PD edition adds:
- `internal/pd/evidence` — evidence catalog and chain-of-custody events
- `internal/pd/roles` — RBAC definitions (chief, evidence_clerk, tech_admin, officer, auditor)
- `internal/pd/export` — signed court export bundles
- `cmd/witness-pd` — PD CLI and dashboard server

The two editions use different key derivation labels (`witness-aes256-gcm-v1` vs `witness-pd-aes256-gcm-v1`) so their logs cannot decrypt each other, even on the same machine.

## Quick start

```bash
# 1. Initialize
witness-pd init --department "Honolulu PD" --node "node-001"

# 2. Start dashboard
export WITNESS_PD_TOKEN=your-secret-token
witness-pd serve

# 3. Open http://127.0.0.1:8890
```

## Data directories

```
~/.witness-pd/
├── soul.toml        — immutable identity (installed once, never overwritten)
├── config.json      — department name, node ID, port, signing public key
├── primary/         — encrypted audit log (witness.log + pd-items.json)
└── exports/         — generated court export bundles (NDJSON)
```
