# Changelog

All notable changes to Harborlight / kiss-protocol are documented here.

---

## [Unreleased]

### Added
- **Time the witness was not running is recorded.** At start, the witness records `witness_downtime` with the gap since its last record and whether the stop was recorded. An unrecorded stop (crash, `kill -9`, power loss) is **CRITICAL** however short; a recorded stop longer than `downtime_alert_minutes` (default 10) is WARN; the first start after `witness init` is INFO.
- **Mirror problems are recorded, not just printed.** No `mirror_url` is **CRITICAL** `mirror_not_configured` at every start (WARN in `--dev`), a mirror that won't open is `mirror_misconfigured`, and pushes record the first failure (WARN `mirror_push_failed`), the point the mirror counts as unreachable (CRITICAL `mirror_unreachable`, after `mirror_escalate_after` failures, default 3) and the recovery (INFO `mirror_push_recovered`), without repeating every failure in between.
- The enforcer handles the new CRITICAL level (printed; alerting and agent containment will hook in there).
- `store.Last()`; `docs/hardening-test.md`, the root-only checks for the hardened install.

### Fixed
- **The installers never produced a working service.** `install.sh` took the genesis snapshot as root *before* creating the `witness` user, so the hardened service (`HOME=/var/lib/witness`) found no config or genesis and exited; neither installer signed the soul, and production mode exits without a signed soul; the USB installer wrote its own unit that ran the witness **as root** with no hardening. Both installers now share `packaging/witness-service.sh`: create the `witness` user (or stop: never fall back to root), copy any existing witness into `/var/lib/witness` (the original is left in place), install the soul, write a config with `signer: software`, take genesis **only if none exists** (re-running `witness init` replaces the baseline), sign the soul, hand everything to `witness`, and install the hardened unit — or refuse; there is no weaker fallback. Tested without root in CI (`packaging/witness-service_test.sh`, root-only steps stubbed); the root checks are in `docs/hardening-test.md`.
- **`--sgail` removed from both installers.** It called `witness enable-sync`, removed in v2.1.

### Added (signing)
- **`"signer": "software"`** in `config.json`: an on-disk ed25519 key at `~/.witness/signing.key` for installs without a YubiKey, with production checks on (unlike `--dev`) and an honest "pilot grade" notice. The installers set it up; when they see a YubiKey they say hardware signing needs the PIV build, which isn't in this release.

### Changed
- **The hardened unit grants one capability, `CAP_DAC_READ_SEARCH`** (read any file, write none), so the unprivileged witness can still fingerprint root-only files such as `/etc/shadow` and `/etc/sudoers`. Without it they read as removed on every drift check. The witness clears the inherited (ambient) copy at start, so nothing it launches (Pipelock, `ps`, its watchdog) inherits it; if that fails it records WARN `ambient_caps_not_cleared`.
- **Release binaries are built static (`CGO_ENABLED=0`) on every platform**, as the cross-compiled ones already were. Required for the process-wide capability clear.

---

## [3.3.3] — 2026-10-06

### Security
- **`witness audit` could pass a rewritten history.** When the transparency mirror was behind the local log, audit compared only sizes and reported "eventual consistency lag". Someone holding the machine's keys could change a past record, re-sign the head, append one more record, and audit would exit 0. Audit now checks that the local log, cut to the mirror's size, still has exactly the root the mirror holds, and fails (exit 1) if not. **Affected:** every release with a mirror before 3.3.3. **Action:** upgrade, then run `witness audit` once against your mirror; a failure on a log you haven't changed means its history before the mirror's head was altered. Found by the Proof-of-Control C07 self-assessment (attack class described in C7.3.5).
- **An interrupted write could leave the log permanently unopenable.** A record's length and body were written separately, and a kill or power loss between them (or between a record and its signed head) left a partial or uncommitted record at the end. Later records then sat behind it unreadable, and the daemon refused to start with a root mismatch, so a crash looked like tampering and stopped all recording. Each record is now one write, and on open a true crash tail (a partial record and/or exactly one record the head doesn't yet cover) is moved to `witness.log.crash-tail-<time>` beside the log, never deleted and never signed. The daemon records **WARN `log_crash_tail_recovered`**, and `witness verify` prints a note. Anything else beyond the head still fails as tampering, and a refused log is never modified. **Affected:** all earlier releases. **Action:** upgrade. A log already stuck this way opens again on 3.3.3, with the stuck bytes kept in the quarantine file.

### Added
- `store.Recovered()` and `store.RootAt(size)`.

---

## [3.3.2] — 2026-10-05

### Security
- **A tree head re-signed with someone else's key passed verification.** The head's ed25519 signature was checked against the `signer_key` written in the head file itself, so anyone holding the machine key (for the MAC) could rewrite the log, sign the head with a key of their own and pass `store.Open`. When the store is opened with a signer (the daemon), the head must now be signed by that signer or by a key in the trust allowlist (`store.OpenTrusting`); otherwise it is rejected with `ErrUnexpectedSigner`. The allowlist keeps key rotation working: the old key is already listed, and the daemon's first entry re-signs the head with the new one.
- **Stripping the signature is recorded.** An unsigned head still opens (logs from before signing was configured must), but the daemon now records **WARN** `tree_head_unsigned` and signs the next head. Seen once when signing is first turned on; any other time, someone removed the signature.
- Unchanged limit: commands that open the log without a signer (`witness verify`, `audit`, `prove`) have no key to pin to. Someone with full control of the machine can still use its own signer; the transparency mirror (`witness audit`) catches that.

---

## [3.3.1] — 2026-10-02

### Security
- **A truncated log verified cleanly if the signed head file was deleted too.** `verifyTreeHead` treated a missing `tree-head.json` as a fresh store, so cutting the end off `witness.log` and removing the head passed both `store.Open` and `witness verify`. A log with entries and no head is now reported as tampering (`ErrMissingTreeHead`); an empty store still opens. No log in this format has ever existed without a head (heads arrived with the Merkle log itself, 2026-05-24), so there is nothing to migrate. Remaining limit, unchanged: the head is signed on the same machine, so someone with full control of it can rewrite and re-sign — the transparency mirror (`witness audit`) catches that.

### Fixed
- **The silent-source alarm flagged event-driven sources.** A door reader or the records office reports only when something happens, so after the threshold it was wrongly flagged as silent. A farm source is now watched only once it sends a `heartbeat` or a `reading` (the kinds that arrive on a schedule); any report from a watched source counts as a sign of life.

### Added
- **Poultry house demo** (`examples/poultry-demo`): a self-contained 30-second run of the witness against a simulated poultry operation — normal logging, a witness outage and catch-up, a house controller going quiet, and three tampering attempts that verification catches. It also prints its limits. Its fourth tampering attempt (cut the log and delete the signed head) is caught since the fix above.
- `farm.Bridge.SetCheckEvery` to change how often silence is checked.

---

## [3.3.0] — 2026-10-02

### Fixed
- **Events written while the witness was down were never recorded.** The NDJSON tailer seeked to the end of an existing file on every start, so a witness restart silently dropped everything a feed logged in the meantime — a gap in the record nobody could see. Tailers now save their read position under `<primary>/tail-state/` and resume from it (Pipelock audit log, and all three split-brain-harness logs). The position advances only past entries the store accepted, so a crash re-reads rather than skips: delivery is at-least-once, and a repeated entry is visible where a missing one would not be.
- **Each (re)open is now recorded:** `tail_fresh`, `tail_resumed` (with `catch_up_bytes`), `tail_rotated`, and **WARN** `tail_restarted` when a feed's file was replaced or truncated while the witness was down — whatever was unread in the old file is gone, and the record now says so.
- **Half-written lines were dropped.** A line the tailer caught mid-write was discarded and its remainder failed to parse; the tailer now rewinds and reads it once it is complete.
- **Lines at the start of a rotated file were skipped.** After rotation the tailer reopened the new file at its end; it now reads it from the start. Rotation is also detected by file identity, not only by the file shrinking.

### Added
- **Farm automation feed and a "silent house" alarm** (`internal/farm`, docs/farm-events.md). Point `farm_events_path` (or `FARM_EVENTS_PATH`) at an NDJSON feed of readings, alarms, setting changes, door access and health records, and each event is recorded in the Merkle log as source `farm`: alarms as WARN `farm_alarm:<alarm>`, setting changes with who made them, unknown kinds still recorded as `farm_event`. Every source that has reported is watched: quiet longer than `farm_silence_minutes` (default 10) gives one WARN `farm_source_silent`, and `farm_source_resumed` when it reports again. Silence is measured from each event's own timestamp, so events caught up after a restart cannot mask an outage. The feed resumes across witness restarts like the others. It detects and records; it does not control anything.
- **Every split-brain-harness verdict is now witnessed, not only forge runs.** The SBH bridge tailed only `SBH_AUDIT_PATH`, the forge (tool-generation) log, so the harness's actual decisions never reached the Merkle log. Two more SBH logs are now tailed into it as source `sbh`:
  - `SBH_DECISION_LOG` (split-brain-harness ≥ 1.6.0): one line per request `sbh serve` analysed. Event `sbh_decision:stop_and_ask` or `sbh_decision:pass`; WARN when the gate stopped, the risk was high, or the turn escalated.
  - `SBH_SESSION_LOG`: multi-turn slow-boil escalations, as WARN `sbh_escalation`.
  Configure with `sbh_decision_log_path` / `sbh_session_log_path` in config.json or the SBH env vars. No SBH log carries raw input, so neither does the witness record.

### Tests
- The SBH bridge had no tests. Fixtures for all three logs are now generated by split-brain-harness's own serializers (`tests/witness_fixture.rs` there) and driven through the real tailer and store: classification, payload integrity and post-ingestion `VerifyIntegrity`. Readiness is probed rather than slept on, since the tailer seeks to the end of an existing file.

---

## [3.2.4] — 2026-10-02

### Fixed
- **Live Pipelock decision verdicts not elevated** (#14, #15): a live Pipelock v3.1.0 proxy dual-emits every decision, and the v2 `evidence_receipt` (`event_kind: proxy_decision`, `record_type: evidence_receipt_v2`) carries its verdict at `detail.payload.verdict`, which the bridge did not read. A blocked live decision now raises the witness entry to WARN. Verdict precedence: `detail.action_record.verdict` → `detail.payload.verdict` → `detail.verdict` → `verdict`. `session_control` lifecycle classification is confirmed correct against live v3.1.0 output. Thanks to @luckyPipewrench for the signed capture.
- **Installer could source the wrong `_core.sh`** (#18): both installer entry points ran an unchecked `cd "$(dirname "$0")"` before `source ./_core.sh`. If the `cd` failed, the installer kept running in the current directory and sourced whatever `_core.sh` was there. Finder starts the `.command` launcher in the user's home directory, exactly where a stray file would be. Both now resolve the script directory once, fail loudly if it or `_core.sh` cannot be found, and source by absolute path. Checksum verification (`VERIFY.txt`, payload only) is unaffected.

### Tests
- Real signed Pipelock v3.1.0 flight-recorder capture (17 receipts: session lifecycle and proxy decisions) committed as a fixture, with a classification test over every row (#15).
- HIFAS fraud verdicts driven through the real tailer: entries classify as `hifas_verdict` with payloads intact, and the HIFAS BLAKE3 hash chain is shown to survive ingestion from genesis (#17).

### Docs
- README release/Go badges and a table of contents (#16); v3.2.3 changelog date corrected to its publish date.

---

## [3.2.3] — 2026-07-12

Fixes from @luckyPipewrench's live interoperability test (kiss-protocol v3.2.1 ↔ Pipelock v3.0.0) on issue #10.

### Fixed
- **Flight-recorder receipt classification**: `classifyReceipt` checked the generic top-level `type` before `event_kind`, so a real `type: action_receipt, event_kind: write` receipt was logged as `pipelock_receipt:action_receipt` — losing the read/write distinction. Classification now follows the Pipelock v3 recorder envelope (verified against the v3.0.0 source), most specific first: `detail.action_record.session_control.kind` for lifecycle receipts (forward-compat — not emitted by the v3.0.0 tag), then the canonical top-level `event_kind` (action verb on `action_receipt` rows, `proxy_decision` on `decision` rows, `checkpoint` on checkpoints), then legacy `detail.action_record.action_type`, then `type`. A blocking/warning verdict now elevates an INFO row to WARN, read from `detail.action_record.verdict` (action receipts) or `detail.verdict` (decision rows).
- **Clean-shutdown records lost**: the bridge stopped its log/evidence tailers *before* stopping Pipelock, so Pipelock's final `transcript_root` and shutdown checkpoint were never read into the witness log. `Bridge.Stop` now stops Pipelock first, and the tailers drain to EOF (with a bounded deadline) before exiting; the forwarder flushes any buffered events on the way out.
- **Genesis flagged tampered when agents present at init**: `AgentsAtGenesis` was assigned *after* the snapshot hash was computed, but the hash covers that field — so a genesis taken with agents present recomputed a different hash on `witness start` and was rejected as tampered. `genesis.Take` now takes the agent list and folds it in before hashing.
- **No evidence emitted without a signing key**: Pipelock's `flight_recorder` is inert without `signing_key_path` and writes nothing, so the evidence leg silently produced no receipts. Witness now provisions a Pipelock-format Ed25519 signing key by default (under `<primary>/pipelock-keys/`, generated natively — see `EnsureSigningKey` — and overridable via `PIPELOCK_SIGNING_KEY`), so evidence is always emitted and signed. Corrected the earlier "unsigned evidence is still hash-chained and ingested" wording.

### Tests
- Added a schema-faithful Pipelock v3.0.0 evidence fixture (`testdata/pipelock_v3_evidence.jsonl`, matching the real `recorder.Entry` / receipt / decision / checkpoint shapes) and drove it through `classifyReceipt`, replacing the earlier hand-authored `decision` envelopes flagged in the live test.
- Added an end-to-end clean-shutdown ingestion test: the final checkpoint written just before stop must reach the witness log via the real `EvidenceTailer → forward → store` path (regression guard for the shutdown-drain fix).
- Added drain-on-stop and final-scan tests for both tailers, genesis round-trip-with-agents, and signing-key format/idempotency/default-provisioning tests.

> **Open item for @luckyPipewrench**: the v3.0.0 *tag* source has no `session_control` field (the lifecycle `kind` path is kept as forward-compat per your guidance but is currently a no-op), and decision-row verdicts live at `detail.verdict` rather than under `action_record`. Confirmation of the canonical field mapping against a live v3 emitter would let us lock these down.

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
