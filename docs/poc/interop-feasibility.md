# Interoperability feasibility (black-box)

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · 2026-11-24

**Method:**
- Upstream tools were executed, not studied.
- The upstream evidence format is described from `schema/README.md`, `schema/canonicalization.md`, `schema/poc-evidence.cddl`, `schema/poc-evidence.schema.json` and the vector files (spec artifacts).
- `impl/` source was not read.

**Overall status:** interoperability is **currently incompatible**, and **feasible but untested** through a native emitter (§5). Nothing has been demonstrated.

## 1. Vector results

`python -I schema/validate.py --vectors`, isolated venv (`jsonschema 4.26.0`, `cryptography 50.0.2`), exit 0:

| Set | Vectors | Result |
|---|---|---|
| Positive | allow-read, deny-path-composition, hardware-attested, modify-bound | 4/4 accepted |
| Negative | missing-policy-bundle-hash, untagged-digest, digest-alg-width-mismatch, wrong-profile, bad-interception-point (all: schema); tree-size-too-small (tree-size); modify-unbound; uppercase-hex-extension (hex-case); float-timestamp (float-in-claims); bad-signature (signature); duplicate-key | 11/11 rejected for the stated reason |
| Canonical | tricky-strings, nonbmp-key-ordering | 2/2 bytes reproduced |
| **Total** | **17** | **"17 passed, 0 failed"** |

**The 16 versus 17 mismatch reproduces.**
- `README.md:143`: "**16 signed test vectors** — four positive, ten negative, two…".
- `schema/README.md` "Current state": `16 passed … (4 positive, 10 negative, 2 canonical-form)`.
- The negative-vector table in `schema/README.md` lists 10 names. `digest-alg-width-mismatch` is the unlisted eleventh.
- The baseline also mentions a `CONTRIBUTING` reference; `CONTRIBUTING.md` at this SHA contains no vector count. The mismatch is in the two READMEs.

**Reference-vector defect (#170) reproduced.**
- In `positive/modify-bound.json` (verdict `MODIFY`, `tree_size` 1), `merkle_root` equals the leaf computed with verdict `ALLOW`, not `MODIFY`.
- The validator accepts the vector.
- A second verifier that checks the leaf-to-root binding would **reject** a published positive vector. Any Witness verifier we build will hit this until PR #169 merges.

## 2. Upstream attack inventory (black-box run)

`python -I impl/attacks/run_attacks.py` gives **11 scenarios, all PASS**. The output is byte-identical to the published `impl/results/attacks.json`. The script's own docstring lists only A1–A8.

Witness categories are those of our own test suites:
- **INT** (integrity: modification, signature, truncation, rewrite);
- **CMP** (completeness: gaps, omission, silence);
- **EQV** (equivocation);
- **MED** (mediation / binding at the effect);
- **AUTHZ** (authorization logic);
- **FC** (fail-closed).

| ID | Attack (upstream name) | Targets | Witness category | Witness equivalent today |
|---|---|---|---|---|
| A1 | Snapshot substitution | C7.1.4 complete mediation | MED | **Partial:** `gateenforce` refuses a token for a different action (`ActionMismatch`; `TestAcceptance05ReplayAndDifferentAmount`). Gate classes only. |
| A2 | Log alteration | C7.3.1 chain + signatures | INT | **Yes:** C07 `ModifyInsertReorderDelete…` (modify/insert/reorder/delete), `FlippedCiphertextByteIsDetected`, `PublishedVerifierCatchesAModifiedRecord` |
| A3 | Omission of an inconvenient step | C7.6.2 sequence continuity | CMP | **Partial:** an inside-log deletion leaves a detectable gap (`DeletionLeavesADetectableGap`). Omission before ingestion: **none** (`Probe_SingleSuppressedEventIsDetectable` fails). |
| A4 | Head truncation | C7.6.6 bounded anchoring | INT | **Yes, against the operator's own mirror:** `MirrorCatchesTruncateAndReSign`. No independent anchor. |
| A5 | Split-view / equivocation | C7.3.3 gossip / witness quorum | EQV | **None.** |
| A6 | Path-composition escalation | C4.1.7 path-aware authorization | AUTHZ | **None** for information flow. Budgets only (`TestAcceptance02TenAssetBurst`). |
| A7 | Capability replay | nonce freshness | MED | **Yes:** `TokenReplayed` (`TestAcceptance05ReplayAndDifferentAmount`) |
| A8 | Evidence-pipeline failure | C7.6.1/C7.6.3 fail closed | FC | **Yes, gate classes:** `TestAcceptance15UnwritableFeed`. The witness itself does not fail closed (by design). |
| A9 | Mid-history rewrite by a key-holding operator | C7.3.5 anchored root, consistency proof | INT | **Yes for audit and leaf holders:** `AuditCatchesRewriteThenAppend`, the leaf-feed tests. **No** for the local verifier (`LocalVerifierRejectsReSignedRewrite` and `…Rollback` fail). |
| A10 | Substitution past an unconfigured mediation check | C7.1.4 binding check fails closed | MED | **Partial:** `gateenforce` has no "unconfigured = accept" path, because the action hash is always compared (`gateenforce.go:181`). No dedicated test. |
| A11 | Capability paired with the wrong evidence record | C7.1.4 capability cross-bound to its record | MED | **Partial:** commit-wait proofs bind the token to the `gate_request` record's action hash (`witnessproof.Verify`, `TestAcceptance16CommitProofAndForgedHead`). No explicit wrong-record pairing test. |

**No Witness equivalent:** A5 and A6. **Partial:** A1, A3, A10, A11.

**Witness adversarial cases with no upstream counterpart:**
- torn-write / crash-tail (`TestC07_Crash_TornWriteDoesNotLoseLaterRecords`, `internal/store/crash_tail_test.go`);
- signer substitution against an unpinned verifier;
- concurrent budget exhaustion (`TestAcceptance18ConcurrentBudget`);
- quorum reset;
- restart while tripped.

## 3. Upstream evidence format (from spec artifacts)

**Token** (JSON; a CBOR/CWT rendering exists in `cbor_profile.py`):
- Top level: `eat_profile` (URI; unknown profile ⇒ reject), `iss`, `iat` (int seconds), `nonce`, `poc_claims`, `submods.attestation{platform, measurement}`, `signature`.
- `poc_claims`:
  - `agent_id`, `initiating_user`, `agbom_digest`;
  - `interception_point`, one of `TASK_INITIALIZATION, CONTEXT_ASSEMBLY, PLAN_GENERATION, PRE_CALL_TOOL_INVOCATION, POST_CALL_TOOL_RESULT, MEMORY_WRITE, SUBAGENT_DELEGATION, TASK_COMPLETION`;
  - `step_index` (per agent, from 0, no gaps);
  - `chain_head`, `merkle_root`, `tree_size`;
  - `policy_bundle_hash`, `target_resource`, `canonical_snapshot_hash`, `path_summary_hash`, `verdict`, `reason`;
  - `dispatched_snapshot_hash` (required for MODIFY);
  - `alg`.
- **Capability** (C7.1.4(b)): `{snapshot_hash, resource, nonce (8–64 bytes), measurement, alg, expiry?}`.
- **Anchor** (C7.6.6): `{agent_id, index, root, iat, alg}`.

**Signature:**
- `alg: "EdDSA"` (Ed25519), hex.
- Covers `canonical(token \ {signature})`: the member is removed, not emptied.

**Digests:**
- Algorithm-tagged lowercase strings, `sha-256:<hex>`.
- Allowed algorithms: `sha-256, sha-384, sha-512, sha3-256` (`poc-evidence.cddl:54`). **BLAKE3 is not in the set.**
- An untagged digest must be rejected.

**Canonicalization (claim set):**
- UTF-8, keys sorted, no whitespace, **no floats**, minimal string escaping, absent ≠ empty, **duplicate keys rejected**.
- Snapshots use full RFC 8785.

**Tree:**
- `leaf = SHA-256(0x00 ‖ canonical({"snapshot": <untagged hex>, "verdict": <verdict>}))`, `node = SHA-256(0x01 ‖ l ‖ r)`: RFC 6962 domain separation.
- The leaf commits to the snapshot digest and verdict, not the whole token.

## 4. Field-by-field comparison with Witness

Witness formats:
- **Record:** `store.Entry`.
- **Head:** `store.TreeHead`.
- **Gate:** `proto.ActionRequest` and `proto.Token`.

| PoC field / property | Witness counterpart | Gap |
|---|---|---|
| `eat_profile` | none | Add a profile URI to emitted tokens |
| `iss` | `TreeHead.SignerKey` (key, not issuer URI) | Issuer identity URI |
| `iat` (int s) | `Entry.ts` (RFC 3339 nano string), `TreeHead.ts` (string, **unsigned**) | Integer seconds; sign it |
| `nonce` | `ActionRequest.request_nonce` (gate only) | Per-token nonce for witness records |
| `agent_id` | `Entry.source` (feed source, not agent); gate `origin_host` | Agent instance identity |
| `initiating_user` | gate `principal` | Witness records lack it |
| `agbom_digest` | none (genesis has file hashes, not an AgBOM) | AgBOM digest |
| `interception_point` | `Entry.event` (free-form names like `pipelock_receipt`, `gate_request`) | Map events to the 8-value enum; most Witness events (drift, lifecycle) have **no** enum value |
| `step_index` (per agent, gapless) | `Entry.seq` (global across all sources) | Per-agent sequence (see 7.6.2) |
| `chain_head` | none (v1 `PrevHash` decode-only) | Hash chain head per agent |
| `merkle_root`, `tree_size` | `TreeHead.root`, `TreeHead.size` (**BLAKE3**, untagged hex) | SHA-256 tree, tagged digests |
| `policy_bundle_hash` | gate `policy_hash` (hex SHA-256, untagged) | Tag; witness-only records have no policy |
| `target_resource` | gate `target` | Witness-only records: none |
| `canonical_snapshot_hash` | gate `action_hash` (SHA-256 of the canonical ActionRequest) | Semantically close for gate actions; the snapshot definition differs |
| `path_summary_hash` | none | Path summary (C4.1.7) |
| `verdict` / `reason` | gate decision outcome / reasons; `Entry.level` (not a verdict) | Map allow/deny; no MODIFY concept |
| `alg` | implicit (Ed25519, BLAKE3, SHA-256) | Explicit identifiers (7.7.3) |
| `submods.attestation` | none (`SOFTWARE` would be the only honest value) | `platform: SOFTWARE` + measurement |
| Signature input | Head: `size_be8 ‖ root`. Gate: `"<domain>\n" ‖ canonical(value \ sig)` | Upstream: `canonical(token \ signature)`, **no domain prefix**. Gate formats are close but domain-separated. |
| Canonical JSON | Gate: Go struct order (not sorted keys), byte-identical re-encode required, no floats, unknown fields rejected. Witness leaf: `json.Marshal(Entry)` (struct order, Go escaping, `omitempty`) | Sorted keys; RFC 8785 escaping (Go escapes `<>&` by default unless disabled: off in gate, **on in `store.leafHash`**) |
| Duplicate keys | Gate decoders reject (tested); Witness head and records: not rejected (probe fails) | Reject everywhere |
| Leaf preimage | Witness: whole record JSON. PoC: `{snapshot, verdict}` only | Different commitment semantics (below) |
| Records at rest | AES-256-GCM encrypted; a verifier needs the operator's export | PoC tokens are plaintext signed objects |
| Capability | `proto.Token`: action hash, epoch, policy hash, expiry, witnessed proof | No `measurement`; nonce is the token id (16 B, within 8–64); `resource` is inside the action hash, not a separate field |
| Anchor | Mirror `tree-head.json` (size, root, prev_root, ts, mac, sig) | PoC anchor is per `agent_id`; Witness heads are per host log |

### Semantic differences that format conversion alone cannot solve [INFERENCE]

1. **Unit of evidence.**
   - PoC: one token per *agent step at an interception point*, with a verdict.
   - Witness: one record per *observed event* (drift, receipts, lifecycle, gate decisions).
   - Only gate decisions and Pipelock receipts map naturally to PoC steps. Drift and lifecycle events have no `interception_point`, and inventing one would misstate what they are.
2. **Leaf commitment.**
   - The PoC leaf commits to `{snapshot, verdict}`.
   - The Witness leaf commits to the whole record.
   - A Witness root cannot be re-expressed as a PoC root without rebuilding the tree over different preimages. A converter cannot preserve the original signatures.
3. **Hash function.**
   - BLAKE3 is not an allowed `hash-alg`. Every existing Witness root is unverifiable by an upstream verifier.
   - Changing it means a new log format, a new epoch, and loss of continuity with existing evidence.
4. **Per-agent versus per-host chains.**
   - PoC `step_index` and `chain_head` are per agent; the Witness log is per host and interleaves sources.
5. **Encryption.**
   - Upstream verification assumes the verifier holds the token.
   - Witness evidence is confidential by default (#152). A third party needs an operator export, which is itself a privileged step.

## 5. What a converter or native emitter would need

### (a) Upstream verifier accepts Witness evidence

A **converter of existing logs is not viable**: different leaves and hash, and original signatures can't be preserved. The feasible path is a **native emitter**. [PROPOSAL]

1. A new evidence stream (a gateway or gate-side emitter) that writes **PoC tokens** for each mediated step:
   - `eat_profile` v0.1, Ed25519 `EdDSA`;
   - RFC 8785 or claim-set canonical form with sorted keys;
   - tagged `sha-256` digests;
   - integer `iat`;
   - the 8-value `interception_point`;
   - per-agent `step_index` and `chain_head`;
   - a SHA-256 RFC 6962 tree over `{snapshot, verdict}` leaves;
   - `submods.attestation.platform = SOFTWARE`.
2. The PoC tree lives **beside** the Witness log. Each emitted token is also appended to the Witness log as an `event_feeds` record, so Witness keeps host-level tamper evidence over the PoC stream (defence in depth).
3. `gateenforce` gains a PoC-capability mode: `snapshot_hash`, `resource`, `nonce` and `measurement` fields, `alg`.
4. Run upstream `validate.py` on emitted tokens in CI: the black-box conformance check. Run our own verifier on the upstream vectors (b).

**Estimate: 2–4 engineer-weeks after the gateway (T3-5) defines snapshots.**

### (b) Witness verifier accepts upstream evidence

1. A strict PoC parser:
   - duplicate-key rejection;
   - profile check;
   - tagged-digest enforcement;
   - float rejection;
   - RFC 8785 implementation for snapshots, including the non-BMP ordering case.
2. Ed25519 verification over `canonical(token \ signature)`.
3. SHA-256 RFC 6962 leaf and inclusion checking, plus a **leaf-to-root binding check**. That check will flag `modify-bound.json` until upstream PR #169 lands: record it as an expected disagreement, not a bug.
4. Pass all 17 vectors for the stated reasons.

**Estimate: 1–2 engineer-weeks; independent of the gateway.**

## 6. Would a second, independent verifier add assurance? [INFERENCE]

**Yes, measurably:**
- A spec-only second verifier (#170) already found a reference-vector defect that the reference validator accepts.
- A Go verifier built clean-room from the spec text would:
  1. test that the spec is implementable without the reference code;
  2. catch validator-specific acceptances like `modify-bound`;
  3. give a relying party a non-Python implementation;
  4. as an independent implementation, help the standard meet its own Tier 3 "published tooling" expectation.

**Limits:**
- It adds no assurance about any *deployment's* evidence beyond what the tokens contain.
- If both verifiers share a misreading of an ambiguous rule (see spec-defects.md), it can agree with the reference on a wrong answer.

**Recommended:** build (b) before (a). It's cheaper, has no dependency on the gateway, and its result is publishable evidence of independent implementation.
