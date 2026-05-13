# Harborlight PD — Court Export Bundles

## Purpose

Court export bundles are tamper-evident packages of the complete chain of custody for a case, suitable for disclosure in legal proceedings.

## Format

Bundles are written as **NDJSON** (newline-delimited JSON):

- **Line 1**: Bundle header (metadata, SHA-256 chain hash, optional signature)
- **Lines 2–N**: One log entry per line (each a `store.Entry` JSON object)

Example header:

```json
{
  "bundle_id":    "BUNDLE-20260512-a3b2c1d0",
  "generated_at": "2026-05-12T14:30:00Z",
  "case_number":  "CASE-2026-0042",
  "department":   "Honolulu PD",
  "node_id":      "node-001",
  "entry_count":  7,
  "sha256_chain": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "signature":    "ed25519-hex-signature-if-signed"
}
```

## Generating a bundle

```bash
# Without signature
witness-pd export --case CASE-2026-0042 --actor "Evidence Clerk"

# With Ed25519 signature
export WITNESS_PD_SIGN_KEY=<private-key-hex>
witness-pd export --case CASE-2026-0042 --actor "Evidence Clerk" --sign
```

Or from the dashboard: **Tech / Admin** → **Export Court Bundle**.

Bundles are saved to `~/.witness-pd/exports/BUNDLE-YYYYMMDD-XXXXXXXX.ndjson`.

## SHA-256 chain hash

The `sha256_chain` field is the SHA-256 of all included entry JSON payloads concatenated in order. Verifying this hash confirms the bundle was not altered after generation.

## Ed25519 signing

Generate a signing key pair:

```bash
witness-pd keygen
```

Store the **public key** in `config.json`. Keep the **private key** as `WITNESS_PD_SIGN_KEY`.

To verify a signed bundle:

```go
// In Go:
err := export.Verify(bundle, publicKeyHex)
```

The signature covers all bundle fields except `signature` itself (which is zeroed before signing).

## What is included

Only log entries whose `data.case_number` field matches the requested case number are included. This filters custody events, not system events.

Each exported bundle automatically generates a `pd/export` event in the audit log, recording who generated the bundle and its bundle ID.

## Retention

Bundles are plain files. Back them up using standard filesystem backup. The audit log itself is the authoritative source; bundles are derived exports.
