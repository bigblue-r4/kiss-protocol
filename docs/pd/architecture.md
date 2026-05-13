# Harborlight PD — Architecture

## Component map

```
cmd/witness-pd/main.go
│
├── internal/pd/evidence   — Item catalog + audit event recording
│   └── → internal/store   — Encrypted, hash-chained append-only log
│       └── → internal/encrypt — AES-256-GCM (machine-ID-derived key, PD label)
│
├── internal/pd/roles      — RBAC definitions and permission checks
│
├── internal/pd/export     — Court export bundle generation and Ed25519 signing
│   └── → internal/store   — Read log entries for bundle
│
├── internal/soul          — Identity verification (pd soul.toml)
└── internal/machid        — Stable machine identifier for key derivation
```

## Key derivation

The PD edition derives its AES-256-GCM log key from the machine ID using HKDF-SHA256 with a PD-specific label:

```
key = HKDF-SHA256(
    secret = machine_id,
    salt   = "witness-pd-kdf-salt-2026",
    info   = "witness-pd-aes256-gcm-v1"
)
```

This produces a different key from the general Witness edition (which uses `"witness-aes256-gcm-v1"`). The two logs cannot be cross-decrypted.

## Evidence storage

Two storage layers work together:

**Encrypted audit log** (`~/.witness-pd/primary/witness.log`):
- Append-only, AES-256-GCM encrypted, SHA-256 hash-chained
- Each record is a `store.Entry` with `seq`, `ts`, `level`, `event`, `source`, `prev_hash`, `data`
- `data` field contains a `CustodyEvent` JSON payload
- Cannot be truncated or modified without breaking the hash chain

**Evidence catalog** (`~/.witness-pd/primary/pd-items.json`):
- Mutable JSON file — current state of all evidence items
- Written atomically after each mutation
- Provides fast item lookup without replaying the entire log
- Protected by an in-memory mutex

Together: the catalog is the current state, the log is the tamper-evident proof.

## Log wire format

Each log entry is: `[uint32 big-endian length][AES-256-GCM encrypted JSON]`

The encrypted payload is a `store.Entry` JSON object. The nonce is prepended to the ciphertext (standard GCM format). The SHA-256 hash chain links each entry to the previous one via `prev_hash`.

## Dashboard security

- Dashboard served only on `127.0.0.1` (loopback — not exposed to the network by default)
- All `/api/*` routes require `Authorization: Bearer <WITNESS_PD_TOKEN>`
- Token must be set as an environment variable before `witness-pd serve` — the server refuses to start without it
- HTTPS termination is left to a local proxy (nginx, Caddy) if remote access is needed
