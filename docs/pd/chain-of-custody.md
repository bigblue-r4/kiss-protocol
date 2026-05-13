# Harborlight PD — Chain of Custody

## What is recorded

Every state change to an evidence item generates a `CustodyEvent` written to the tamper-evident log:

| Event type | Trigger | Level |
|------------|---------|-------|
| `intake` | New item recorded | INFO |
| `transfer` | Custody transferred to new node/location | INFO |
| `access` | Item examined or accessed | INFO |
| `hold_set` | Legal hold placed | WARN |
| `hold_release` | Legal hold removed | INFO |
| `export` | Court export bundle generated | INFO |
| `destroyed` | Item marked as destroyed | WARN |

## CustodyEvent structure

```json
{
  "item_id":    "EV-20260512-a3b2c1d0",
  "case_number": "CASE-2026-0042",
  "event_type": "transfer",
  "timestamp":  "2026-05-12T14:23:01Z",
  "actor":      "Officer Smith",
  "from_node":  "evidence-room-1",
  "to_node":    "forensics-lab",
  "notes":      "Transfer for DNA analysis"
}
```

The `case_number` field is embedded in every event so the chain can be extracted by case without replaying the entire log.

## Item ID format

```
EV-YYYYMMDD-XXXXXXXX
```

Where `XXXXXXXX` is 4 bytes of cryptographic random hex. Example: `EV-20260512-a3b2c1d0`.

## Legal hold enforcement

Legal holds are hard-blocked in code — not policy:

- `RecordTransfer` returns an error if `item.LegalHold == true`
- `RecordDestroyed` returns an error if `item.LegalHold == true`
- The hold state is stored in the catalog (`pd-items.json`) and written to the log as `hold_set` / `hold_release` events

A hold cannot be bypassed by writing directly to the log because the catalog is the authority on current item state. Any discrepancy between catalog and log constitutes a tamper event.

## Verifying integrity

The log is hash-chained: each entry includes `prev_hash`, which is the SHA-256 of the previous entry's plaintext JSON. A break in the chain (unexpected `prev_hash` value) indicates tampering or log corruption.

Future: `witness-pd verify` command to walk the chain and report integrity status.
