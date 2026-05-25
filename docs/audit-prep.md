# Audit Preparation

This document is a checklist and orientation guide for external security reviewers.

## Scope of Review

A full audit should cover:

| Area | Location | Priority |
|------|----------|----------|
| Merkle log integrity | `internal/store/store.go`, `internal/merkle/` | High |
| Tree-head signing (ed25519 + BLAKE3 MAC) | `internal/store/store.go:288–400` | High |
| Soul file signature verification | `internal/soul/verify.go` | High |
| Gossip wire format and anti-replay | `internal/gossip/heartbeat.go` | High |
| AWS Sig V4 implementation | `internal/mirror/s3.go` | Medium |
| Pipelock bridge event forwarding | `internal/pipelock_bridge/bridge.go` | Medium |
| Capability drops and seccomp profile | `packaging/systemd/witness.service`, `packaging/seccomp/witness.json` | Medium |
| Install scripts | `install.sh`, `harborlight-install.sh` | Medium |
| PIV/YubiKey signer | `internal/signer/dev.go` (software dev signer) | Low — PIV not yet shipped |

Out of scope (per threat model):

- Physical token extraction
- Kernel-level attacks
- Side-channel attacks

## Setup for Reviewers

```bash
git clone https://github.com/bigblue-r4/kiss-protocol.git
cd kiss-protocol

# Build and test
go test ./...
go vet ./...

# Run fuzz tests (short pass)
go test -fuzz=FuzzLoad         -fuzztime=60s ./internal/soul/
go test -fuzz=FuzzAppend       -fuzztime=60s ./internal/store/
go test -fuzz=FuzzDecodePacket -fuzztime=60s ./internal/gossip/
go test -fuzz=FuzzPushJSON     -fuzztime=60s ./internal/mirror/

# Verify reproducible build
make verify-reproducible
```

## Key Invariants to Verify

### 1. Merkle log append-only guarantee
- Every `store.Append` call adds a leaf to the Merkle tree.
- The tree head is written atomically (rename) after each append.
- `VerifyIntegrity` walks all leaves and recomputes the root.
- A truncated or reordered log must cause `VerifyIntegrity` to return an error.

Relevant test: `internal/store/log_test.go` — `TestTamper*`, `TestTruncate*`.

### 2. Tree-head dual-MAC authentication
- The tree head carries both an ed25519 signature (operator key) and a BLAKE3 HMAC
  (machine-derived key). Both are verified on `store.Open`.
- `verifyTreeHead` uses the public key embedded in `tree-head.json`, not the signer
  passed at open time — this is intentional and documented in `store.go`.

### 3. Soul file hash check
- `soul.Load` computes a SHA-256 over the file content (with the `hash` field zeroed)
  and compares against the embedded `hash` field.
- A soul file with a tampered `hash` field or tampered body must cause `Load` to fail.

### 4. Gossip anti-replay
- `heartbeat.go:handlePacket` checks `hdr.Seq > st.lastSeq` before accepting any packet.
- A replayed packet (same or lower seq) must be silently dropped.
- Unknown peers (not in the peer store) must be rejected before signature verification.

### 5. Mirror audit (witness audit)
- Exit 0: mirror agrees or is behind (push pending).
- Exit 1: mirror ahead of local, or same size with root mismatch — investigate tampering.
- Exit 2: mirror unreachable or unparseable.

### 6. Capability drop
- On Linux (when systemd unit is used), `CapEff` should read `0` from `/proc/self/status`.
- `internal/sandbox/sandbox_test.go` verifies this if run under the hardened systemd unit.

## Known Limitations and Honest Gaps

- **Ring-0 attacker:** A kernel rootkit can forge in-memory state. Only durable storage
  and the external mirror remain tamper-evident in that scenario. This is documented
  explicitly and not claimed otherwise.

- **macOS hardening parity:** Linux has capability drops + seccomp. macOS has neither
  (Seatbelt is not shipped). The macOS launchd plist (`packaging/launchd/`) provides
  process limits and `_witness` user isolation but no syscall filtering.

- **SGAIL sync is deprecated:** `internal/sgail/` remains functional for one release
  (deprecated in v2, removed in v2.1). It is not a security boundary.

- **PIV signer:** The hardware PIV signer (`internal/signer/`) is designed and interfaced
  but the concrete `piv-go` implementation is not yet wired. The software dev signer
  (`internal/signer/dev.go`) should never be used in production.

- **Pipelock library API:** Pipelock is currently integrated via subprocess. The bridge
  (`internal/pipelock_bridge/`) is the stable seam; when the library API ships, only that
  package changes.

## Files of Highest Security Interest

```
internal/store/store.go          Merkle log + dual tree-head authentication
internal/merkle/tree.go          RFC 6962 tree hashing
internal/merkle/proof.go         Inclusion proof generation and verification
internal/soul/verify.go          Soul file signature verification
internal/soul/soul.go            TOML parse + hash self-check
internal/gossip/heartbeat.go     Wire format, anti-replay, heartbeat state machine
internal/gossip/peer.go          Peer store (allowlist model)
internal/mirror/s3.go            AWS Sig V4 in-tree implementation
internal/signer/dev.go           Software ed25519 signer (dev only)
packaging/systemd/witness.service Systemd hardening unit
packaging/seccomp/witness.json   Seccomp OCI profile (container reference)
```

## Submitting Findings

See `SECURITY.md` for the responsible disclosure process and timeline.
Please do not open public GitHub issues with exploit details.
