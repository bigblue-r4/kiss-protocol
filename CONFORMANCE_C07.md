# Witness self-assessment: Proof-of-Control C07 "Evidence Generation and Properties"

**Assessed:** the Harborlight Witness (`cmd/witness`, `internal/store`, `internal/merkle`, `internal/mirror`) at **kiss-protocol v3.3.2** (`7f9328c`), **re-run on v3.3.3** (`830e21f`, 2026-10-06), which fixes the two defects this assessment found (see "Update" below).
**Against:** Proof-of-Control **0.1** (`0.1/en/0x10-C07-Evidence-Generation-and-Properties.md`, fetched 2026-10-06 from `LFDT-ProofOfControl/ov-poc-standard@master`). The v1.0 comment draft was not available to this assessment; version-sensitive points are flagged.
**Assessed 2026-10-06.** Self-assessment, not third-party. No Witness production code was changed; every test is new and lives in `tests/poc_c07/`.

**Scope notes**

- **This Witness is not a NATS subscriber.** It ingests events by tailing files (Pipelock audit log and evidence receipts, HIFAS, split-brain-harness logs, farm NDJSON feed) and records its own drift and anomaly events. A NATS ingest path was planned for a separate server and never built. Bus-level suppression attacks were therefore tested at the equivalent seam: the feed file, before an event reaches the Witness.
- **The Witness is the evidence writer, not an Action Interception Gateway.** In this stack, Pipelock is the gateway. Gateway requirements (C7.1.x, 7.6.3) are marked N/A for the Witness; a system-level claim needs the gateway assessed separately.
- **The log is an RFC 6962 Merkle tree (BLAKE3), not a hash chain.** C7.3.1 allows either.

---

## Update: v3.3.3 (2026-10-06)

The assessment found two defects, both fixed and released in **v3.3.3** with a public security notice in the release notes:

1. **`witness audit` passed a rewritten history** (rewrite + re-sign + append one record → exit 0). Audit now requires the local root at the mirror's size to equal the mirror's root (`store.RootAt`). `TestC07_7_3_5_Probe_AuditCatchesRewriteThenAppend` now **passes**.
2. **A torn write made the log permanently unopenable.** Records are now one write, and a true crash tail is moved to a quarantine file on open. `TestC07_Crash_TornWriteDoesNotLoseLaterRecords` now **passes**.

Re-run on v3.3.3: **31 tests, 17 pass, 14 fail** (all 14 are open gap probes). **No requirement changes status:**
- 7.3.5 stays NOT MET, because the fix uses the full local log, not a consistency *proof* a third party could check.
- 7.6.1 stays PARTIAL, because there's still no secondary failure log or alert sink.

## Update: published verifiers pin the signer (PR #33, unreleased, 2026-10-19)

`witness verify`, `audit` and `prove` used to open the log with no signer, so they checked the head's signature against the key named in the head file itself, which an attacker can rewrite. They now take `--pubkey HEX` / `--pubkey-file PATH` and refuse a head that is unsigned or signed by any other key (`store.OpenPinned`). Without a pin they behave as before and print a note saying the signer was not checked. `TestC07_7_3_2_PublishedVerifierPinsTheSigner` now **passes** (it was a failing probe). **7.3.2 stays PARTIAL:** the MAC/encryption key is still derived from world-readable `/etc/machine-id`, which needs a migration.

Re-run with PR #33: **31 tests, 18 pass, 13 fail** (all 13 are open gap probes).

The rest of this document is the original v3.3.2 assessment, with the rows above updated.

## 1. Summary

**C07 tier the Witness achieves today: T2 (Attestation) at best for the integrity mechanism, and strictly below a complete Tier 1 for the section.**

- **Mechanism.** An assessor *with the machine key* can confirm that records weren't modified, inserted, reordered or deleted, and that the head was signed by the witness's key. That's Level 2 evidence. A third party with no privileged access can't do this, because the records are encrypted under a key derived from the machine, so Tier 3 isn't reached.
- **Strict cumulative grading.** Levels are cumulative (`0x03` §Requirement Levels). Two Level 1 items are unmet: the claims review (7.5.2) and stated retention (7.6.5), both process or documentation work. Three more Level 1 items are partial. So C07 is not complete even at Tier 1.
- **T3 is blocked by more than anchoring.** The known gap (no external anchor) is real, but so are three others found here:
  1. **Consistency checking:** a re-signed history rewrite followed by one more record passed `witness audit` (fixed in v3.3.3 for the operator's own audit; third parties still have no consistency proof).
  2. **Verifiability without the machine key.**
  3. **Equivocation resistance.**

| Status | Count | Requirements |
|---|:-:|---|
| MET | 0 | — |
| PARTIAL | 10 | 7.2.1, 7.3.1, 7.3.2, 7.3.4, 7.4.1, 7.5.1, 7.6.1, 7.6.2, 7.6.4, 7.6.6 |
| NOT MET | 10 | 7.2.2, 7.3.3, 7.3.5, 7.5.2, 7.6.5, 7.7.1, 7.7.2, 7.7.3, 7.7.4, 7.7.5 |
| N/A | 6 | 7.1.1, 7.1.2, 7.1.3, 7.1.4, 7.1.5, 7.6.3 |
| AMBIGUOUS | 2 | 7.2.3, 7.2.4 |
| **Total** | **28** | |

**Test run on v3.3.2** (`go test -tags poc_c07 -v ./tests/poc_c07/`, 2026-10-06): **31 tests, 16 pass, 15 fail.** On v3.3.3: **17 pass, 14 fail.** With PR #33: **18 pass, 13 fail.**

- Every one of the 16 passing tests is a property the Witness claims, and none of them was downgraded.
- 14 of the 15 failures are gap probes, written to fail while a gap is open.
- 1 failure is a defect found by an adversarial test (torn write, §3 G4).

The repository's normal suite (`go test ./...`) is unaffected: the new tests are behind the `poc_c07` build tag.

---

## 2. Conformance matrix

The spec's own keyword for every row is "**Verify that**". C07 uses no RFC 2119 keywords, so each row is read as mandatory at its Level, and Level N gates Tier N.

| Req | Keyword | Requirement (paraphrase) | Lvl | Status | Evidence (file:line / test) | Tier impact | Gap & minimal fix |
|---|---|---|:-:|---|---|---|---|
| 7.1.1 | Verify that | All tool and effect calls routed through a separate-process gateway, no bypass | 3 | N/A | The Witness ingests after the fact (`internal/pipelock/tailer.go:217`), it isn't in the call path | System T3 depends on the gateway | Assess the gateway (Pipelock) separately |
| 7.1.2 | Verify that | Signed before/during/after records per action, one action ID | 3 | N/A | Gateway duty. The Witness records whatever receipts the gateway writes (`internal/pipelock_bridge/bridge.go:135`) | System T3 | Gateway must emit the three records; the Witness can then check the triple is complete |
| 7.1.3 | Verify that | Action not forwarded until the *before* record is durable | 3 | N/A | Gateway duty | System T3 | Gateway |
| 7.1.4 | Verify that | Effect channel mediated in the policy trust boundary (a/b/c), named in claim | 3 | N/A | Gateway duty | System T3 | Gateway |
| 7.1.5 | Verify that | Don't claim "executed actions" unless 7.1.4 is met | 1 | N/A | No PoC claim exists yet. README wording claims logging, not mediated execution | Any future claim | Word any claim as Tier 1–2 for executed actions until a gateway meets 7.1.4 |
| 7.2.1 | Verify that | Written within the action's transaction, not batched, with the event's capture timestamp | 1 | PARTIAL | Capture ts kept in the payload: `TestC07_7_2_1_SourceCaptureTimestampIsPreserved` ✅. Record ts is ingest time: `internal/store/store.go:170`. Catch-up after restart is a batch: `TestC07_7_2_1_Probe_EvidenceIsNotBatchReconstructed` ❌ (1.2 s after the action) | Blocks full T1 | Structural: the Witness is an async reader. Fix belongs at the gateway (write-before-forward). Additive: keep capture ts as a first-class field |
| 7.2.2 | Verify that | Timestamps anchored outside operator control every interval | 3 | NOT MET | Only time source is the local clock (`store.go:170`, `:352`). Mirror is operator-controlled (`docs/threat-model.md:92`) | Blocks T3 | See §4 |
| 7.2.3 | Verify that | Declared hardware-attestation refresh interval, enforced | 3 | AMBIGUOUS | No TEE or hardware measurement. The YubiKey is key custody, not attestation (`internal/signer/piv.go`) | T3 if mandatory | Spec unclear whether TEE attestation is required at L3 or only when used (§5 F2) |
| 7.2.4 | Verify that | Attestation binds the evidence signing key | 3 | AMBIGUOUS | As 7.2.3 | T3 if mandatory | As 7.2.3 |
| 7.3.1 | Verify that | Merkle/hash-chain so modify/insert/reorder breaks it, plus scheduled verification with recorded results | 2 | PARTIAL | **Detection holds:** `store.go:384` verifyTreeHead, `internal/merkle/tree.go:43`. Passing tests: `TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected` (modify, insert, reorder, delete, replay), `TestC07_7_3_1_FlippedCiphertextByteIsDetected`, `TestC07_7_3_1_PublishedVerifierCatchesAModifiedRecord` (real `witness verify`). **No schedule:** the daemon verifies only at open (`cmd/witness/main.go:321`). The drift tick (`main.go:469`) doesn't verify. The enforcer recomputes leaves without checking the head (`internal/enforcer/reader.go:111`) | Blocks full T2 | S, additive: run `VerifyIntegrity` on the drift tick and Append the result as an event |
| 7.3.2 | Verify that | Signed by mechanism-held keys the operator and agent can't access | 3 | PARTIAL | Signature pinned to the witness key since v3.3.2 (`store.go:453`): `TestC07_7_3_2_HeadSignedByAnotherKeyIsRejected` ✅. But the MAC/encryption key = HKDF(world-readable `/etc/machine-id`) (`internal/encrypt/encrypt.go:23`, `internal/machid/machid.go:15`): `Probe_MACKeyInputIsNotSecret` ❌. Published verifiers opened with no signer and accepted any signing key on v3.3.3; **fixed in PR #33** (`--pubkey`, `store.OpenPinned`): `TestC07_7_3_2_PublishedVerifierPinsTheSigner` ✅. Dev key lives in the operator's home | Blocks T3 | Done: pin a published public key in verify/audit/prove (PR #33). Still M: separate signing custody from the operator (PIV with a non-operator PIN, or a TEE). Don't derive the MAC key from a public identifier (touches existing code) |
| 7.3.3 | Verify that | Equivocation resistance (gossip, witness quorum, or ledger), named | 3 | NOT MET | Gossip carries heartbeats only, no roots (`internal/gossip/heartbeat.go:51`). The mirror is one operator-controlled copy (`internal/mirror/mirror.go`) | Blocks T3 | M, additive: put signed tree heads in the gossip payload and cross-check, or anchor to a single-history log (§4) |
| 7.3.4 | Verify that | Single-record inclusion proof against a published root; proof, size and root obtainable | 3 | PARTIAL | Structure holds: `internal/merkle/proof.go:13`. `TestC07_7_3_4_InclusionProofVerifiesWithIndependentTooling` ✅ (verified with RFC 9162 code written independently of the Witness). `TestC07_7_3_4_ProofSizeIsLogarithmic` ✅ (≤ ⌈log₂ n⌉ up to n = 4096). **Not obtainable by a third party:** proofs come only from `witness prove` with the machine key (`prove.go:41`), records are encrypted, the mirror publishes the head only: `TestC07_T3_Probe_ThirdPartyRecomputesRootWithoutMachineKey` ❌ (reads 0 of 5) | Blocks T3 | M: publish proofs plus the disclosed leaf (or leaf hash) per record through a verifier-facing endpoint. Additive |
| 7.3.5 | Verify that | Append-only consistency vs earlier roots; compare to the anchored root, not a count | 3 | NOT MET | No consistency proof exists (`internal/merkle/` has inclusion only). `witness audit` compares roots only at equal size; when the mirror is behind it compares sizes only (`cmd/witness/audit.go:123`–`134`). **Attack A9 succeeded on v3.3.2:** rewrite + re-sign + append 1 → audit exit 0, "eventual consistency lag". **Fixed in v3.3.3:** audit checks `store.RootAt(mirror.size)` (`cmd/witness/audit.go`, default branch), and `TestC07_7_3_5_Probe_AuditCatchesRewriteThenAppend` ✅. Still no consistency *proof* a third party can check. Also `Probe_LocalVerifierRejectsReSignedRewrite` ❌ and `Probe_LocalVerifierRejectsRollback` ❌. Mitigations that do work: `TestC07_7_6_6_MirrorCatchesTruncateAndReSign` ✅, `TestC07_7_6_6_MirrorCatchesSameSizeRewrite` ✅ | **Blocks T3**, contradicts `docs/threat-model.md:51` (A1/A2 guarantee) | M, additive: RFC 6962 consistency proofs in `merkle`. Audit requires `ConsistencyProof(mirror.size → local.size)` whenever sizes differ |
| 7.4.1 | Verify that | Disclosure lists every party, hardware element and math assumption per mechanism | 1 | PARTIAL | `docs/threat-model.md:67` (Trust Roots), `:88` (Operational Assumptions), `:58` (Non-Goals): `TestC07_7_4_1_TrustRootsAndAssumptionsArePublished` ✅. Missing BLAKE3, AES-256-GCM, HKDF, machine-id: `Probe_MathematicalAssumptionsAreDisclosed` ❌. Not in C10.2 form | Blocks full T1 | S, docs only: a C10.2-format disclosure per mechanism |
| 7.5.1 | Verify that | Every schema field is an execution fact | 1 | PARTIAL | Top-level fields `seq, ts, level, event, source, data` (`store.go:44`): `TestC07_7_5_1_EntrySchemaIsExecutionFactsOnly` ✅ (pins the field set). `data` is free-form source payload; `level` is a classification | Blocks full T1 | S: publish a per-source `data` schema that admits only fact fields |
| 7.5.2 | Verify that | Claims describe execution facts only; documented legal/compliance review | 1 | NOT MET | No claims-review record exists | Blocks T1 | S, process: review README and site claims, file the sign-off |
| 7.6.1 | Verify that | Pipeline failures alert and are written to a secondary durable log | 2 | PARTIAL | Storage probe → anomaly → death broadcast: `internal/anomaly/detector.go:67`, `:80`; `cmd/witness/main.go:464`. But 15 call sites discard `Append` errors (e.g. `main.go:445`, `internal/farm/farm.go:223`), mirror-push failure is a stderr warning only (`main.go:434`), no secondary failure log: `Probe_WriteFailureIsRecordedElsewhere` ❌. **Defect on v3.3.2:** a torn write left the log unopenable and later records unreadable (length and record were separate writes). **Fixed in v3.3.3:** one write per record, crash tail quarantined on open (`store.Recovered`): `TestC07_Crash_TornWriteDoesNotLoseLaterRecords` ✅ | Blocks full T2 | M: a secondary failure log plus alert sink (additive); handle every Append error; torn-tail recovery on open (truncate a trailing partial frame, touches `store.go`) |
| 7.6.2 | Verify that | Per-source monotonic sequence numbers; gap detectable from the sequence alone | 2 | PARTIAL | `store.go:163` `seq++`: `TestC07_7_6_2_SequenceIsMonotonicFromOne` ✅, `TestC07_7_6_2_DeletionLeavesADetectableGap` ✅ (survives a re-signed deletion). But the verifier never checks continuity: `Probe_PublishedVerifierFlagsSequenceGaps` ❌. Sequence is per log, not per source: `Probe_SequenceIsPerSource` ❌. Upstream suppression of one event is invisible: `TestC07_Completeness_Probe_SingleSuppressedEventIsDetectable` ❌. Silence of a periodic source is caught: `TestC07_Completeness_SilencedPeriodicSourceIsFlagged` ✅ (`farm.go:89`) | Blocks full T2 | S, additive: check seq continuity in verify. M: per-source counters, and require source-side sequence numbers in feed formats |
| 7.6.3 | Verify that | Fail closed: gateway refuses in-scope actions while evidence can't be generated | 4 | N/A | Gateway duty. The Witness is out of the action path and cannot gate | System T4 | Gateway: refuse actions while the evidence sink is unavailable |
| 7.6.4 | Verify that | Role-based access to the store; every read logged | 2 | PARTIAL | Owner-only files (`store.go:106` 0700, `:134` 0600): `TestC07_7_6_4_StoreFilesAreOwnerOnly` ✅. No roles, no read-access records | Blocks full T2 | M: a read API that Appends an access event; separate reader role (the enforcer user already reads) |
| 7.6.5 | Verify that | Retention stated, configured, at least the claim period | 1 | NOT MET | No retention setting in `internal/config/config.go`; the log grows unbounded | Blocks T1 | S: state retention in the claim; add a configured value (no deletion before it) |
| 7.6.6 | Verify that | Root anchored externally within a declared interval; missed deadline alerts | 3 | PARTIAL | Head pushed to the mirror at start and every drift tick (`main.go:424`, `:469`; 30 s default, `config.go:51`). Audit catches truncation and same-size rewrite (tests above ✅). But the mirror is operator-controlled, no interval is declared in a claim, a failed push only warns (`main.go:434`), and A9 escapes (7.3.5) | Blocks T3 | See §4 |
| 7.7.1 | Verify that | Published machine-readable schema; real output validates | 2 | NOT MET | Schema is the Go struct only (`store.go:44`, `:66`) | Blocks T2 | S: JSON Schema or CDDL for Entry and TreeHead, plus a validation test |
| 7.7.2 | Verify that | Single declared canonical serialization; exact bytes covered | 2 | NOT MET | Implicit: Go `encoding/json` struct order (`store.go:329`), signature over `size_be8‖root` (`:466`). Neither is written down; `data` re-encoding differs by source | Blocks T2 | S/M: specify (e.g. RFC 8785 JCS) and document the signed bytes |
| 7.7.3 | Verify that | Algorithm identifier on every digest and signature; reject unidentified | 2 | NOT MET | Tree head keys: `size, root, prev_root, ts, mac, sig, signer_key`: `Probe_HeadNamesItsAlgorithms` ❌ | Blocks T2 | S: add `alg` fields; verifiers reject when absent (format change) |
| 7.7.4 | Verify that | Published test vectors incl. negatives, each rejected for its stated reason | 3 | NOT MET | None published | Blocks T3 | S/M: vectors from the existing tamper tests (each with its expected error) |
| 7.7.5 | Verify that | Duplicate object keys rejected, not last-wins | 2 | NOT MET | Feed lines decoded with `encoding/json` (`internal/pipelock/tailer.go:344`): `Probe_DuplicateKeysAreRejected` ❌ (kept the last `kind`) | Blocks T2 | S: duplicate-key-rejecting decoder at ingest and in verify |

---

## 3. Gap list, by tier impact

Effort: S = days, M = 1–3 weeks, L = more. "Additive" means new code or files only; "touches" means a change to existing behaviour.

**Blocking T3 (trust-minimized)**

| # | Gap | Reqs | Effort | Kind |
|---|---|---|:-:|---|
| G1 | **No append-only consistency proof.** The operator's own `witness audit` now checks the prefix root (fixed in v3.3.3), but a third party with only published roots still can't. Implement RFC 6962 consistency proofs and publish them alongside anchored roots | 7.3.5, 7.6.6 | M | Additive (new `merkle` function) |
| G2 | **Third parties can't verify without the machine key.** Records are encrypted and proofs come only from `witness prove` | 7.3.4, T3 | M | Additive: a verifier export of leaf data (or leaf hash plus a disclosure policy) and proofs |
| G3 | **No anchor outside operator control**, and no equivocation resistance | 7.2.2, 7.6.6, 7.3.3 | M | Additive (§4) |
| G4 | **Key custody.** MAC/encryption key derived from world-readable `/etc/machine-id` (verifier pinning **fixed in PR #33**) | 7.3.2 | M | Key derivation touches existing code and needs a migration |
| G5 | **Interoperability at Level 3:** no published test vectors | 7.7.4 | S/M | Additive |
| G6 | **TEE attestation**, if the spec makes it mandatory at L3 | 7.2.3, 7.2.4 | L | Additive, hardware-dependent |

**Blocking T4 (self-enforcing)**

| # | Gap | Reqs | Effort | Kind |
|---|---|---|:-:|---|
| G7 | **No gating.** The Witness is out of the action path. T4 needs the gateway to refuse in-scope actions while the Witness can't record | 7.6.3, 7.1.3 | L | Gateway work, outside this repo |
| G8 | **Write failures are silent.** Handle every Append error and add a secondary failure log and alert (torn-tail recovery shipped in v3.3.3) | 7.6.1 | M | Touches callers |

**Below T3 (complete T1/T2 for C07)**: these are cheap.

| # | Gap | Reqs | Effort | Kind |
|---|---|---|:-:|---|
| G9 | Scheduled verification with recorded results; seq-continuity check in verify | 7.3.1, 7.6.2 | S | Additive |
| G10 | Published schema, canonical form, algorithm IDs, duplicate-key rejection | 7.7.1–7.7.3, 7.7.5 | S/M | Mostly additive; alg IDs change the head format |
| G11 | Disclosure (C10.2 form), claims review, retention | 7.4.1, 7.5.2, 7.6.5 | S | Docs and process |
| G12 | Per-source sequence numbers; source-side sequence numbers required in feed formats | 7.6.2 | M | Touches feed formats |

---

## 4. Chain-head anchoring

**What C07 0.1 requires of anchoring.**

- **7.6.6:** the chain root is anchored externally within a **declared maximum interval** stated in the claim, which bounds the window in which head truncation is undetectable, and a **missed anchoring deadline raises an alert**.
- **7.2.2:** evidence timestamps are anchored to a source **outside the operator's control** (an RFC 3161 TSA, a transparency-log inclusion proof, or consensus time) at least once per interval.
- **7.3.5:** each newly published root is checked for append-only consistency against the **anchored** value, not a count.
- **7.3.3:** equivocation resistance by gossip, a witness quorum, or a single-history ledger, named in the claim.

An anchor that only stores heads satisfies none of these on its own unless the verifier also proves consistency between anchored roots (G1).

**Today:** the Witness pushes its signed head to an operator-configured mirror every drift tick (30 s default) and `witness audit` compares against it. That's external *storage*, but it isn't external *trust*, since the operator controls the mirror. No interval is declared, and a failed push only warns.

**Candidate approaches** (no implementation). Each would anchor `H = (size, root, sig)` every interval *I* and alert when *I* is missed.

1. **RFC 3161 timestamp authority.** Submit a hash of `H` to one or more TSAs and store the signed timestamp token next to the head.
   - *Trust:* the TSA's key and clock are honest, and the TSA certificate chain is valid.
   - *Gives:* 7.2.2 (time outside operator control) and proof that `H` existed by time *t*.
   - *Doesn't give:* equivocation resistance (7.3.3). The operator can timestamp two different heads.
   - *Cost:* low, and works offline-ish with batching.
   - Two independent TSAs reduce single-authority risk.
2. **Public transparency log (Sigstore Rekor-style, or a CT-style log).** Log `H` as a signed entry. The log returns an inclusion proof and its own signed tree head, and gossiping that head gives single-history.
   - *Trust:* the log operator plus the log's own witness or gossip ecosystem, and its signing key.
   - *Gives:* 7.2.2 (inclusion-proof time), 7.3.3 (a single public history is hard to fork unnoticed when log heads are witnessed), and a public place for verifiers to fetch anchored roots for 7.3.5.
   - *Cost:* moderate; the log may be public, so publish only the head, never record contents.
3. **Public-chain anchor** (e.g. commit a hash of `H` in a Bitcoin `OP_RETURN` via an aggregation service such as OpenTimestamps, or an Ethereum event).
   - *Trust:* the chain's consensus (economic security) and the aggregator only for liveness, since the proof is self-verifying once confirmed.
   - *Gives:* consensus time (7.2.2) and the strongest single-history property (7.3.3).
   - *Costs:* confirmation latency (minutes to hours) sets a floor on *I*, fees, and a public, permanent record.

Recommended shape: **(2) at a short interval for single-history and verifier access, plus (1) or (3) at a longer interval as an independent time anchor.** All of them must be paired with G1, or a verifier holding an anchored root still can't prove the current log extends it.

---

## 5. Draft comments for the PoC public comment window (closes 2026-10-30)

Critique and proposed text only. These contain no implementation detail.

**F1. C7.6.2 / C7.6: completeness attacks upstream of the evidence writer.**
*Section:* C7.6 (introductory text) and 7.6.2.
*Issue:* C7.6 rightly says tamper-evidence doesn't make omission detectable, but 7.6.2 only addresses records lost *after* the evidence writer assigned them a sequence number. An event suppressed before it reaches the writer (dropped by a compromised gateway, an intercepting bus, or a filtering adapter) never receives a sequence number, so no gap appears. A periodic-liveness check catches a silenced source, but not a single suppressed event from a source that keeps reporting.
*Proposed text (new 7.6.7, Level 3):* "**Verify that** each event source assigns its own monotonic sequence number at the point of origin, before the event leaves the source's trust boundary, and that the evidence record preserves it; that the verifier checks per-source continuity; and that for sources that cannot sequence at origin, the conformance claim states that single-event suppression between the source and the evidence writer is undetectable."
*Add to Auditor evidence:* "Suppress one event between source and evidence writer while the source continues to emit, and confirm the gap is reported."

**F2. C7.2.3 / C7.2.4: does Tier 3 require hardware attestation?**
*Issue:* Both are Level 3, but they are phrased as conditions on "the hardware attestation", without saying whether a system with no TEE fails them or they don't apply. That decides whether a software-only mechanism can ever reach Tier 3.
*Proposed text:* add to C7.2: "7.2.3 and 7.2.4 apply when the conformance claim relies on hardware attestation. A claim that does not shall state so in its trust-assumption disclosure (C10.2), and shall not claim that the evidence attests the execution environment." Alternatively, state explicitly that hardware attestation is mandatory at Level 3.

**F3. C7.3.5: "consistency" must cover a verifier that is behind.**
*Issue:* The rationale covers a verifier that compares only counts. A subtler failure: a verifier that compares roots only at equal size, and treats a newer, larger root as benign "lag". A rewritten history plus one appended record then passes, because the earlier anchored root is never proven to be a prefix of the new one.
*Proposed text (append to 7.3.5):* "Whenever the anchored root and the presented root differ in tree size, the verifier shall obtain and check a consistency proof between them; a size difference shall never by itself be treated as benign lag."
*Add to Auditor evidence:* "Rewrite and re-sign a historical record, append one further record, and confirm the verifier rejects the result."

**F4. C7.6.1: crash consistency of the evidence store.**
*Issue:* 7.6.1 covers write errors that the pipeline sees. A process killed mid-write (or a power loss) may leave a partially written record that the pipeline never sees fail, and depending on the store format it can make later records unreadable or the store unopenable.
*Proposed text (append to 7.6.1):* "…and that an interruption at any byte of a record write leaves every previously committed record verifiable and lets subsequent writes proceed; a partially written record is detected and reported as a failure event, not silently discarded."
*Add to Auditor evidence:* "Kill the evidence writer mid-write; restart; confirm earlier records verify and new records are accepted."

**F5. C7.3.4 / C7.1: verifiability of encrypted or confidential evidence.**
*Issue:* Level 3 requires verification "by any external party … with no privileged access", while many deployments must keep record contents confidential. The standard doesn't say whether publishing roots, proofs and leaf *hashes* (with contents disclosed per record on request) satisfies Level 3, or whether contents must be public.
*Proposed text (new note in C7.3):* "Evidence contents may be confidential. Level 3 is met when a verifier without privileged access can (a) obtain the published roots and their anchors, (b) obtain an inclusion proof and leaf hash for any record, and (c) verify a disclosed record against its leaf hash. The disclosure policy for record contents shall be stated in the claim."

**F6. Version consistency: four properties or five.**
*Issue:* The control objective names four properties (binary, contemporaneous, tamper-evident, transparent), but the section defines a fifth, C7.7 "The Interoperable Property", and C7.4 flags a possible sixth (continuity across boundaries). "Binary" has no section of its own.
*Proposed text:* update the control objective to "…must satisfy the evidence properties: binary, contemporaneous, tamper-evident, transparent, and interoperable (C7.2–C7.7)", and either give "binary" a numbered requirement or state where it is verified.

**F7. C7.3.1: what "a defined schedule" must achieve.**
*Issue:* "Runs on a defined schedule with results recorded" sets no bound and no reaction requirement. A yearly check with results filed would conform.
*Proposed text:* "…on a schedule stated in the claim, not longer than the anchoring interval of 7.6.6; each result is itself recorded as evidence, and a failed verification raises the alert of 7.6.1."

**F8. Normative keyword.**
*Issue:* The references cite RFC 2119/8174, but the requirement rows use "Verify that" with no MUST/SHOULD, so implementers can't tell mandatory from recommended within a level.
*Proposed text:* "Each requirement row is mandatory (MUST) for a claim at or above its Level, unless the row says otherwise."

---

## Reproducing

```sh
go test -tags poc_c07 -v ./tests/poc_c07/      # builds cmd/witness and runs it in a sandboxed HOME
```

The tests need `/etc/machine-id` (Linux) for the published-tooling tests, and no network.
