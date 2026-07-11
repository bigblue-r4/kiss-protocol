# Changelog

All notable changes to Harborlight / kiss-protocol are documented here.

---

## [Unreleased]

Fixes from @luckyPipewrench's live interoperability test (kiss-protocol v3.2.1 ↔ Pipelock v3.0.0) on issue #10.

### Fixed
- **Flight-recorder receipt classification**: `classifyReceipt` checked the generic top-level `type` before `event_kind`, so a real `type: action_receipt, event_kind: write` receipt was logged as `pipelock_receipt:action_receipt` — losing the read/write distinction. Classification now follows the Pipelock v3 envelope (most specific first): `detail.action_record.session_control.kind` for lifecycle receipts (session_open/heartbeat/session_close), then the canonical top-level `event_kind`, then legacy `detail.action_record.action_type`, then `type`. A blocking/warning `verdict` now elevates an INFO row to WARN.
- **Clean-shutdown records lost**: the bridge stopped its log/evidence tailers *before* stopping Pipelock, so Pipelock's final `transcript_root` and shutdown checkpoint were never read into the witness log. `Bridge.Stop` now stops Pipelock first, and the tailers drain to EOF (with a bounded deadline) before exiting; the forwarder flushes any buffered events on the way out.
- **Genesis flagged tampered when agents present at init**: `AgentsAtGenesis` was assigned *after* the snapshot hash was computed, but the hash covers that field — so a genesis taken with agents present recomputed a different hash on `witness start` and was rejected as tampered. `genesis.Take` now takes the agent list and folds it in before hashing.
- **No evidence emitted without a signing key**: Pipelock's `flight_recorder` is inert without `signing_key_path` and writes nothing, so the evidence leg silently produced no receipts. Witness now provisions a Pipelock-format Ed25519 signing key by default (under `<primary>/pipelock-keys/`, generated natively — see `EnsureSigningKey` — and overridable via `PIPELOCK_SIGNING_KEY`), so evidence is always emitted and signed. Corrected the earlier "unsigned evidence is still hash-chained and ingested" wording.

---

## [3.2.2] — 2026-07-10

### Changed
- CI workflow (`ci.yml`) modernized to Node 24-native action majors (`actions/checkout` v5, `actions/setup-go` v6), dropping the `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround and clearing the Node 20 deprecation warning. The release workflow also bumps checkout/setup-go to v5/v6 but intentionally keeps `sigstore/cosign-installer` v3 and `softprops/action-gh-release` v2 — their next majors are breaking (cosign v3 changed `sign-blob` to a bundle format), so they retain the force-node24 shim. No functional change to the `witness` / `enforcer` binaries.

---

## [3.2.1] — 2026-07-10

### Added
- **Flight-recorder receipts folded into the witness log (issue #10 follow-up)**: the Pipelock bridge now tails the `flight_recorder` evidence directory and forwards every signed, hash-chained decision receipt into the witness Merkle log as `pipelock_receipt` events, alongside the raw NDJSON audit stream. New `pipelock.EvidenceTailer` discovers rotating `evidence-*.jsonl` files (following pre-existing files from the end, new files from the start). Receipt signing is configured via `PIPELOCK_SIGNING_KEY` / `Config.SigningKeyPath`. (Correction, superseded in Unreleased: a signing key is in fact **required** — Pipelock's recorder is inert without one and writes no evidence at all — so the "without a key the evidence is still hash-chained and ingested" note here is inaccurate; witness now provisions a key by default.)

### Fixed
- **Pipelock config schema (issue #10)**: the generated Pipelock config used invented top-level keys (`proxy`, `audit`, `policy`, `response_scan`, `behavioral`, `mcp`) that Pipelock rejects at startup with unknown-field errors, so the process exited immediately and the network audit leg silently no-op'd. Rewrote the template against the Pipelock v3 schema (`mode: audit`, `fetch_proxy`/`forward_proxy`, `logging`, `mcp_input_scanning`/`mcp_tool_scanning`, `behavioral_baseline`, `flight_recorder`) and added a regression test that runs `pipelock check` against the generated config when the binary is present. Thanks to @luckyPipewrench (Pipelock author) for the report and corrected config.
- **Silent Pipelock startup failure**: `Runner.Start` now health-checks the proxy port before reporting success, and captures the subprocess's stderr into the witness log (as `pipelock_stderr` events) so a config rejection or crash is recorded instead of masked by a false "proxy running" message.

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
