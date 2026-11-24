# Draft specification defects (internal; not filed)

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` (Working Draft v0.1) · prepared during the Witness Phase 1 assessment, 2026-11-24.

**These are drafts for SGAIL review. Do not file, post or paraphrase them upstream without a separate decision.** Where an SGAIL issue already exists, that is noted, and these drafts would be follow-ups, not new filings.

**Severity scale:**
- **High:** blocks a conformance decision or allows a false PASS.
- **Medium:** two honest implementers would grade differently.
- **Low:** editorial or documentation.

Paths below are relative to `0.1/en/` unless they start with `schema/`, `impl/` or the repository root. Line numbers are at the pinned SHA.

---

### SD-01 · All rows · No normative keyword (existing: #155) · **High**
- **Text:** every row begins "**Verify that** …"; Appendix A: "A conformance claim is assessed against the MUST and MUST NOT requirements".
- **Location:** `0x90-Appendix-A_Glossary.md:7`; `0x03-Using-Proof-of-Control.md:28` ("Levels are cumulative — a claim at Tier N must satisfy every requirement at Level N and below", lowercase, in a "Using" chapter).
- **Ambiguity:** read literally, no row is a MUST, so a claim could be assessed against nothing.
- **Security consequence:** an assessor can treat any failed row as advisory.
- **Blocks the implementer:** we can't tell mandatory from recommended within a Level. Our matrix assumes every row is mandatory at its Level.
- **Proposed wording:** "Each requirement row is mandatory (MUST) for any claim at or above its Level, unless the row states a condition under which it does not apply."
- **Suggested test:** the intake review rejects a statement that marks any in-Level row "not applicable" without citing the row's own condition.

### SD-02 · C7 control objective · Four properties or five (existing: #153) · **Low**
- **Text:** "must satisfy the four evidence properties: binary, contemporaneous, tamper-evident, and transparent" (C07 objective); C7.7 defines "Interoperable".
- **Ambiguity:** whether interoperability is an evidence property gating the binary threshold; "binary" has no numbered row.
- **Blocks the implementer:** we can't map "binary" to a test.
- **Proposed wording:** "…the evidence properties: binary (C8), contemporaneous (C7.2), tamper-evident (C7.3), transparent (C7.4–C7.5) and interoperable (C7.7)."
- **Suggested test:** none (editorial).

### SD-03 · 7.2.3, 7.2.4 · Conditional or mandatory hardware attestation (existing: #149) · **High**
- **Text:** 7.2.4: "the hardware attestation cryptographically binds the evidence signing key …" (Level 3).
- **Ambiguity:** whether a software-only mechanism fails these rows or is exempt from them.
- **Security consequence:** without a decision, software-only Tier 3 claims are either impossible or unbounded.
- **Blocks the implementer:** decides whether Witness can reach Tier 3 without a TEE. Both rows are UNCLEAR in our matrix.
- **Proposed wording:** "7.2.3 and 7.2.4 apply when the conformance claim relies on hardware attestation. A claim that does not shall say so in its trust-assumption disclosure (C10.2) and shall not claim that its evidence attests the execution environment."
- **Suggested test:** an assessor recomputes the claim's Tier with and without the attestation dependency.

### SD-04 · 7.3.5 · Verifier behind the presented tree (existing: #150) · **High**
- **Text:** "a published root is checked for append-only consistency against previously published roots, by a consistency proof or equivalent".
- **Ambiguity:** says nothing about the case the A9 attack uses, where sizes differ; "or equivalent" is undefined.
- **Security consequence:** a verifier that accepts a size gap as lag passes rewritten history. Witness had this defect before v3.3.3; the reference implementation had it as A9.
- **Blocks the implementer:** we can't tell whether `verify-leaves` (recomputing from held leaves) counts as "equivalent".
- **Proposed wording:** append: "Whenever the anchored and presented roots differ in tree size, the verifier obtains and checks a consistency proof (RFC 6962 §2.1.2) or recomputes the anchored root from leaves it already holds; a size difference is never by itself treated as benign lag."
- **Suggested test:** rewrite and re-sign one record, append one, and present the result to a verifier holding the earlier root. It must reject.

### SD-05 · 7.3.4, 2.3.1, Level 3 definition · Confidential evidence and guessable leaves (existing: #152) · **High**
- **Text:** Level 3 = "verifiable by any external party with published tooling and no privileged access" (`0x03-Using-Proof-of-Control.md:34`); 2.3.1 requires substitution "where evidence at Tier 3 would re-leak protected inputs".
- **Ambiguity:**
  - whether publishing leaf hashes, roots and proofs is enough for Level 3 when contents are confidential;
  - whether a leaf hash over **plaintext** content counts as "re-leaking", since a low-entropy record can be confirmed by guessing.
- **Security consequence:** an implementer can publish leaves that allow confirming guessed records (Witness does today; `docs/mirror-setup.md` documents it) and still believe they meet 2.3.1.
- **Blocks the implementer:** we can't choose between plaintext leaves (verifiable, guessable) and salted or committed leaves (private, needing a disclosure step).
- **Proposed wording:** "Level 3 is met for confidential evidence when a verifier without privileged access can obtain roots, anchors and an inclusion proof for any record, and can verify a disclosed record against its leaf. Leaves over confidential content shall commit with a per-record secret salt (or equivalent hiding commitment) so that undisclosed records cannot be confirmed by guessing. The disclosure policy is stated in the claim."
- **Suggested test:** given a published leaf feed and a guessed record, the assessor must be unable to confirm the guess without the disclosed salt.

### SD-06 · 7.3.1 · Unbounded verification schedule (existing: #154) · **Medium**
- **Text:** "chain verification runs on a defined schedule with results recorded".
- **Ambiguity:** no maximum interval and no required response; a yearly check conforms.
- **Proposed wording:** "…on a schedule stated in the claim, no longer than the anchoring interval of 7.6.6; each result is recorded as evidence, the completed verification horizon is reported, and a failed or stalled verification raises the alert of 7.6.1."
- **Suggested test:** stall a scheduled check. The recorded horizon must not advance, and the alert must fire within the stated bound.

### SD-07 · 7.6.2 · Completeness upstream of the writer (existing: #148) · **High**
- **Text:** "evidence records carry per-source monotonic sequence numbers … so a verifier can detect a missing record from the sequence gap alone".
- **Ambiguity:** doesn't say where the sequence is assigned. A writer-assigned sequence can't reveal an event dropped before the writer, and a source restart can reset counters.
- **Security consequence:** a compromised gateway or bus can drop single events undetectably.
- **Proposed wording:** "…assigned by the source at the point of origin and preserved in the record; a restart begins a new, signed source epoch linked to the previous one. Where a source cannot sequence at origin, the claim states that single-event suppression between source and writer is undetectable."
- **Suggested test:** (Hauge, #148) suppress one event, restart the source with a reset counter, and deliver later records. The verifier must report the interval as unreconciled.

### SD-08 · 7.6.1 · Interrupted writes, and replayed tails (existing: #151) · **Medium**
- **Text:** "evidence-pipeline failures (write errors, signing errors, store unavailability) raise a monitored alert and are themselves written as failure events to a secondary durable log."
- **Ambiguity:**
  - interrupted writes aren't "failures the pipeline sees";
  - it's unclear whether quarantining a single record beyond the head (crash tail) satisfies the row, or must be treated as tampering. Phase 1 found Witness quarantines a *replayed* record that way.
- **Proposed wording:** append "…and an interruption at any byte of a record write leaves every committed record verifiable and lets later writes proceed; material beyond the last committed head is preserved, reported as a failure event, and never silently discarded or committed."
- **Suggested test:** (Hauge's paired case) an interrupted write versus an altered earlier record. Both must be reported; only the first may be recovered.

### SD-09 · 0x03 Requirement Levels · Which cross-cutting rows apply to a domain-scoped claim? · **High**
- **Text:** "Meeting all Level 1–3 requirements in the claimed domains is the minimum" (`0x03-Using-Proof-of-Control.md:34`). Domains are C1–C6 (10.1.2), but C7–C10 are not domains.
- **Ambiguity:** whether every C7–C10 row at Level ≤ N applies to every claim, or only those relevant to the claimed domain's mechanisms.
- **Blocks the implementer:** our matrix assumes all C7–C10 rows apply. That makes 7.1.1 (a gateway) mandatory for any Tier 3 claim, including a host-integrity claim with no agent actions.
- **Proposed wording:** "Chapters C7–C10 apply to every claim. Rows in C7.1 apply to claims about agent actions; a claim that evidences no agent action states so and is assessed against C7.2–C7.7."
- **Suggested test:** the intake review checks the stated applicability against the claim register's mechanism mapping (8.2.1).

### SD-10 · 7.1.1–7.1.5 versus README "Not runtime enforcement" · **Medium** (related: #78, closed and logged)
- **Text:** README.md:191 lists "Not runtime enforcement"; 7.1.1 and 7.1.3 require a gateway that withholds actions (Level 3); 7.1.5 limits claims to Tier 1–2 without 7.1.4.
- **Ambiguity:** whether a PoC claim requires a preventive component. The threat appendix still has no gateway-compromise or bypass rows (PR #120 closed unmerged).
- **Security consequence:** the strongest claims rest on the least-modelled component.
- **Proposed wording:** "Proof-of-Control does not define the policy an agent is held to; at Level 3 it requires an enforcement point whose release of an action depends on the existence of its evidence (C7.1). Appendix C models the compromise and bypass of that enforcement point."
- **Suggested test:** an action through a path that bypasses the gateway must be absent from the claimed scope or detected (7.1.1 auditor evidence).

### SD-11 · C8 · When is a Merkle log no longer "centralized"? · **High** (related: #123, #114)
- **Text:** "A centralized Merkle tree is cryptographic and sits at Tier 2" (`0x10-C08-Verifiability-Tiers.md:71`); 8.1.2: "any single trusted party caps the claim at Tier 2."
- **Ambiguity:** how many independent co-signers or monitors, and what "independent" means (one company running many witnesses?), turn an operator-run log into Tier 3.
- **Blocks the implementer:** we can't size the witness-quorum work (T3-3), or say whether one external co-signer plus the operator is enough.
- **Proposed wording:** "A log reaches Tier 3 for tamper-evidence when its checkpoints are co-signed or monitored by at least two operators independent of the log operator and of each other (all keys of one operator count as one), and any verifier can obtain those co-signatures."
- **Suggested test:** the assessor recomputes the Tier from the operator-grouped co-signer list.

### SD-12 · Repository documentation · Vector count · **Low**
- **Text:** `README.md:143`: "16 signed test vectors — four positive, ten negative, two"; `schema/README.md`: "16 passed, 0 failed (4 positive, 10 negative, 2 canonical-form)".
- **Observed:** `validate.py --vectors` reports **17 passed**, with 11 negative. `digest-alg-width-mismatch.json` is missing from both READMEs and from the schema README's negative-vector table.
- **Proposed fix:** update both counts and add the missing row ("digest length must match its algorithm tag").

### SD-13 · 7.3.4, 7.7.3, `schema/poc-evidence.cddl:54` · Hash agility and "or equivalent" · **Medium** (related: #177)
- **Text:** 7.3.4: "an inclusion proof against an append-only Merkle tree (RFC 6962) or equivalent"; CDDL: `hash-alg = &( sha-256: 1, sha-384: 2, sha-512: 3, sha3-256: 4 )`.
- **Ambiguity:** whether a tree with RFC 6962 structure but a non-listed hash (BLAKE3, as Witness uses) is "equivalent", and whether 7.7.3's identifiers must come from the CDDL set.
- **Blocks the implementer:** decides between keeping the BLAKE3 log with a mapping, or a new SHA-256 log format and epoch.
- **Proposed wording:** "The tree uses a hash algorithm from the registered set (C7.7.3); other algorithms may be registered with a stated security level. Structure equivalent to RFC 6962 means: distinct leaf and node domain separation, the RFC 6962 split rule, and append order."
- **Suggested test:** the negative vector "unregistered hash algorithm" must be rejected for that reason.

### SD-14 · `schema/vectors/positive/modify-bound.json` · Root commits to ALLOW (existing third-party: #170, PR #169 open) · **High**
- **Observed (reproduced at the pinned SHA):** for tree_size 1 the root equals `SHA-256(0x00‖{"snapshot":…,"verdict":"ALLOW"})`; the token's verdict is MODIFY. `validate.py` accepts it.
- **Security consequence:** the reference validator doesn't check leaf-to-root binding for single-leaf trees, so verdict substitution passes, which 7.1.4 relies on not happening.
- **Proposed fix:** regenerate the vector, and add a negative vector whose root commits to a different verdict.

### SD-15 · `schema/canonicalization.md:120` · Wrong path · **Low**
- **Text:** "`vectors/negative/nonbmp-key-ordering.json` exhibits the ordering case".
- **Observed:** the file is `schema/vectors/canonical/nonbmp-key-ordering.json`.
- **Proposed fix:** correct the path.

### SD-16 · C4, C8 Tier 4 · Decision-gate assurance is not testable · **Medium** (related: #145, #146)
- **Text:** 4.1.2 "every action is evaluated against the granted permission set … names the permission matched (or the denial reason)".
- **Ambiguity:** rows require that evaluation is *recorded*, not that its verdicts are *correct*. No row asks for an adversarial verdict battery or independent reproduction.
- **Security consequence:** a gate that records every decision, and gets some wrong, passes C4.
- **Proposed wording (new C4 row, Level 3):** "The authorization decision function is exercised against a published adversarial test battery (allow, deny, escalate, replay, binding) whose results an external party has reproduced; the battery version is cited in the claim."
- **Suggested test:** the assessor reruns the published battery.

### SD-17 · 10.3.2 · Totals don't prove coverage (existing third-party: #173, PR #182) · **High**
- **Text:** "demonstrated by reconciling gateway action counts against evidence-record counts … with zero unexplained difference".
- **Ambiguity:** a count match can hide one action with no records and another with duplicates. Both counts come from the gateway.
- **Proposed wording:** adopt #182's reconciliation by operation, attempt and phase, with the action population taken from a source the gateway does not produce.

### SD-18 · 7.1.2 versus `schema/poc-evidence.schema.json` · No "during" interception point · **Medium**
- **Text:** 7.1.2 requires records "request received (before), effect performed (during), and result returned (after)".
- **Observed:** the `interception_point` enum is `TASK_INITIALIZATION, CONTEXT_ASSEMBLY, PLAN_GENERATION, PRE_CALL_TOOL_INVOCATION, POST_CALL_TOOL_RESULT, MEMORY_WRITE, SUBAGENT_DELEGATION, TASK_COMPLETION`: no value for "effect performed". Also noted in #173's addendum.
- **Blocks the implementer:** we can't emit a conformant "during" record.
- **Proposed fix:** add `EFFECT_PERFORMED` (or define which existing value carries it).

### SD-19 · 6.3.5 · Undefined projection · **Medium**
- **Text:** "where the declared evidence retention period … extends beyond the period for which the signature scheme is projected to remain unforgeable".
- **Ambiguity:** whose projection, and what source? Without one, the condition can't be evaluated, so nobody can show it does not apply.
- **Proposed wording:** "…as projected by a named public guidance document cited in the claim (e.g., the current NIST or national guidance on quantum-vulnerable algorithms)."

### SD-20 · 7.2.1 · Observer-style evidence · **Medium**
- **Text:** "each evidence record is written within the executing transaction of the action it describes — not batch-reconstructed later".
- **Ambiguity:** host observers (file tailers, drift scanners) record events they didn't mediate, some seconds after the fact. It's unclear whether such evidence can ever meet Level 1, or whether 7.2.1 applies only to mediated actions.
- **Blocks the implementer:** Witness's tailer-ingested evidence is PARTIAL by construction.
- **Proposed wording:** "…for mediated actions; evidence from an observer outside the action path carries both the source capture timestamp and the ingestion timestamp, and the claim states the maximum ingestion delay."

### SD-21 · 7.6.6 · "Anchored externally" undefined · **Medium**
- **Text:** "the chain root is anchored externally within a declared maximum interval".
- **Ambiguity:** whether a mirror on third-party infrastructure that the operator's account controls (an object-store bucket) counts as "external".
- **Proposed wording:** "…to a party or system whose write access the operator does not control (independent witness, public transparency log, or ledger)."

### SD-22 · `impl/attacks/run_attacks.py` docstring · Lists 8 of 11 attacks · **Low**
- **Observed:** the docstring lists A1–A8; the harness runs and records A1–A11 (results identical to `impl/results/attacks.json`).
- **Proposed fix:** list A9–A11.

---

**Matrix cross-reference:**
- Rows marked UNCLEAR in `conformance-matrix.json`: 7.2.3 and 7.2.4 (SD-03).
- SD-01, SD-09, SD-11 and SD-13 change how many rows apply, so they affect every count in the matrix. The matrix states its assumptions for each.
