# Changelog

All notable changes to Harborlight / kiss-protocol are documented here.

---

## [3.2.0] — 2026-06-30

### Added
- `docs/prior-art.md` — curated architectural prior art for Sentinel/Witness/Bigblue: agent-governance-toolkit (policy gate), OpenFang (Merkle chain diff target), AgentSeal (MCP audit adapter), LlamaFirewall (SBIR citation baseline)

---

## [3.1.0] — 2026-06-28

### Added
- SBH forge audit integration — split-brain-harness forge events are now recorded as signed Merkle leaves in the witness log

### Fixed
- `store.Append`: sanitize invalid UTF-8 bytes before hashing to prevent Merkle hash drift between platforms

---

## [3.0.0] — 2026-06-14

### Changed (breaking)
- **Hard process boundary**: `witness` (kiss-core) and `enforcer` (kiss-enforcer) are now two separate binaries
  - `witness` — incorruptible local observer; writes the Merkle log, drift detection, soul verification, mirror push; **no network listeners**
  - `enforcer` — distributed enforcement layer; reads the core log read-only, cannot write to it; gossip mesh, cross-node death alerts, loyalty policy evaluation
  - A compromised enforcer cannot falsify the core witness record

### Why
- Conflating observation and enforcement in a single process creates a single point of compromise: an attacker who controls the enforcer could silence the witness
- The new architecture enforces this invariant at the OS process boundary

---

## [2.0.0] — 2026-05-24

### Added
- **Phase 1**: Merkle log replaces 3-tier backup — every append is a signed leaf; the tree head is published and verifiable
- **Phase 2**: Hardware signer + soul signing — machine-derived AES-256 key; soul file is BLAKE3-signed on every load
- **Phase 3**: systemd/launchd hardening — dedicated `witness` OS user; seccomp profile; `ProtectSystem=strict`
- **Phase 4**: Stdlib gossip mesh — UDP/9273 signed heartbeats, liveness tracking; SGAIL sync deprecated
- **Phase 5**: Transparency mirror + `witness audit` command — append-only JSONL push to configurable mirror endpoint; `audit` subcommand verifies the full Merkle chain
- **Phase 6**: Surface reduction — Pipelock bridge replaces direct HTTP listener; dashboard HTML generation removed from witness process
- **Phase 7**: Credibility and supply chain — `witness verify` checks cosign-signed release artifacts; supply chain attestation embedded in binary

### Changed (breaking)
- Soul file format v2 — includes BLAKE3 signature field; v1 souls rejected at load
- Config schema updated for gossip, mirror, and seccomp settings

---

## [1.0.0] — 2026-05-12

### Added
- `witness` binary — tamper-evident machine-state witness daemon
- Append-only encrypted log (`~/.witness/primary/witness.log`) with signed Merkle tree head (`tree-head.json`)
- Soul verification — identity hash derived from machine state, recomputed on every startup; mismatch triggers DEATH event
- Drift detection — filesystem and process state snapshotted before AI agent install; anomalies logged as signed events
- Network traffic logging — all requests routed through Pipelock auditing proxy; each request is a signed Merkle leaf
- `witness-pd` — Police Department Edition with chain-of-custody event types and court-ready log export
- Dashboard HTML generation (removed in v2.0.0)
- CI workflow
