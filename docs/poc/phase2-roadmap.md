# Phase 2 roadmap (proposed; dependency-ordered)

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · 2026-11-24

All estimates are **engineer-weeks (ew), ranges, unvalidated**. They assume familiarity with the codebase and include tests, but not review latency or calendar time spent waiting on outside parties.

## Capacity assumptions (state these before reading any date)

- **SGAIL engineering capacity:** about **1 engineer-equivalent**. One founder-engineer works with AI coding assistants; the founder reviews, merges and runs every privileged operation.
  - The founder is remote until about 2026-12-02.
  - A new machine where the founder can run privileged commands is expected. Nothing in this plan depends on it before Phase 2 starts.
- **Calendar:** 2026-11-24 to 2027-02-01 is **69 days, about 9.9 weeks**, including the December and January holidays. At 1 ew per week that is **at most about 8–10 ew** before the v1.0 target date.
- **Outside dependencies are excluded from the estimates:** recruiting an independent co-signer, an outside verification run, legal review, the working group's answers to SD-03/SD-09/SD-11/SD-13.
- **The target can move:** v1.0 text may change the rows assessed here (the schedule is in `RELEASE.md` only).

## Work packages

Rows and acceptance criteria refer to the pinned spec. The tests listed are regression tests to add.

### WP-0 Claim scope and Tier 2 documents (T2-1, T2-2)
- **Objective:** a Self-Declared Tier 2 conformance statement for C4 Authorization plus C7–C10, honest about every PARTIAL and FAIL.
- **Requirements:** 7.4.1, 7.5.2, 7.6.5, 8.1.1–8.1.4, 8.1.6, 8.2.1, 8.2.2, 9.1.1–9.1.3, 10.1.1–10.1.6, 10.2.1.
- **Depends on:** none (leadership decides the scope).
- **Effort:** 1–2 ew (+ external claims review).
- **Security impact:** prevents over-claiming; fixes the published `CONFORMANCE_C07.md` `replay` error.
- **Acceptance:** every in-scope Level ≤ 2 row has evidence or an explicit gap; mathematical assumptions listed; retention stated.
- **Regression tests:** a CI check that the statement's machine-readable form validates (later 10.1.7).
- **Evidence and done:** statement and register published in-repo; claims review recorded; 7.5.2 PASS.

### WP-1 Evidence format: identifiers, schema, canonical form
- **Objective:** make Witness heads and records self-describing and unambiguous; **decide BLAKE3 versus a SHA-256 profile** (SD-13).
- **Requirements:** 6.3.4, 7.7.1, 7.7.2, 7.7.3, 7.7.5 (+ 7.7.4 vectors).
- **Depends on:** WP-0 (scope).
- **Effort:** 2–4 ew. A hash change implies a new log format and epoch.
- **Security impact:** closes silent algorithm assumptions and the duplicate-key ambiguity.
- **Acceptance:** published JSON Schema; algorithm-tagged digests; heads sign over a format with an algorithm identifier; duplicate keys rejected; published positive and negative vectors, each rejected for its stated reason.
- **Regression tests:** the C07 probes `HeadNamesItsAlgorithms` and `DuplicateKeysAreRejected` pass; vector tests.
- **Done:** probes moved from the tag to main and passing.

### WP-2 Merkle consistency proofs and a standalone checkpoint verifier
- **Objective:** RFC 6962 §2.1.2 consistency proofs; a verifier that needs only two checkpoints and a proof.
- **Requirements:** 7.3.5 (also 7.3.4 completeness).
- **Depends on:** WP-1 (hash decision), but can be built hash-agnostic first.
- **Effort:** 1–2 ew.
- **Security impact:** new verifiers can detect rewritten history without holding all leaves (upstream A9, scenario 14).
- **Acceptance:** fuzzed proof generation and verification; wrong-length and wrong-size proofs rejected.
- **Regression tests:** C07 `LocalVerifierRejectsReSignedRewrite` and `…Rollback` pass; property tests against a reference RFC 6962 implementation (Go `transparency-dev/merkle`, used as a test oracle only).
- **Done:** 7.3.5 PARTIAL → PASS for proof mechanics.

### WP-3 Independent checkpoint co-signing and outside time
- **Objective:** co-signer protocol (log id, size, root, co-signer timestamp); two independent co-signers; declared anchoring interval with a missed-deadline alert.
- **Requirements:** 7.3.3, 7.2.2, 7.6.6, 8.1.2/8.1.3 (moves the trust analysis).
- **Depends on:** WP-1, WP-2.
- **Effort:** 3–5 ew, plus calendar time to recruit an independent operator.
- **Security impact:** split-view and equivocation detection (A5); outside time.
- **Acceptance:** each co-signer refuses non-extensions; the verifier requires a quorum; equivocation produces a non-repudiable proof (two signed roots).
- **Regression tests:** fork-to-two-cosigners test; stale-co-signer test; re-signed rewrite test.
- **Done:** 7.3.3 PASS in test; operating co-signers recorded in the disclosure.

### WP-4 Public verification without privileged access
- **Objective:** leaf feed and checkpoints over S3/R2 (today file-only); inclusion proofs fetchable by third parties; versioned standalone verifier release; **one recorded outside verification run**.
- **Requirements:** 7.3.4, 8.1.5, 8.1.8.
- **Depends on:** WP-2, WP-3.
- **Effort:** 1–2 ew, plus an outside party.
- **Security impact:** removes the operator-export step (scenario 7.3.4 PARTIAL).
- **Acceptance:** a person without operator credentials verifies inclusion and consistency from public materials only; the run log is published.
- **Done:** 8.1.5 PASS with recorded run.

### WP-5 Per-source sequencing, origin sequencing and epoch links
- **Objective:** per-source sequence numbers checked by the verifier (L2). Optional: origin-assigned sequence for SGAIL-owned sources (gate, gateway, SBH). Signed epoch-link records across re-init.
- **Requirements:** 7.6.2, 3.2.2; #148/SD-07 (optional hardening).
- **Depends on:** WP-1.
- **Effort:** 1 ew (per-source + verifier); +1–2 ew (origin and epoch links).
- **Security impact:** detects gaps per source; closes Hauge's restart case for our own sources.
- **Regression tests:** C07 `Probe_PublishedVerifierFlagsSequenceGaps`, `Probe_SequenceIsPerSource`; restart-with-reset test (Hauge, #148; credit in the commit).

### WP-6 Action Interception Gateway (T3-5)
- **Objective:** default-deny egress for the agent; HTTP/MCP gateway (building on Pipelock routing); tool credentials held by the gateway; before / during / after records; release only after the before-record is durable (reuse gate commit-wait); out-of-scope blocking.
- **Requirements:** 7.1.1–7.1.4, 4.1.3, 7.2.1 (mediated actions), 10.3.6 prerequisites.
- **Depends on:** WP-5 (sequence), WP-7 (gate deployment). Can start in parallel with WP-2/WP-3.
- **Effort:** **6–10 ew**, the largest item.
- **Security impact:** closes the dominant gap (scenarios 1, 16, 17).
- **Acceptance:** a bypass attempt is blocked and recorded; each mediated action has three linked records; the effect is released only after the before-record.
- **Regression tests:** bypass test; kill-the-evidence-store test (fail closed); A1/A10/A11 analogues.
- **Done:** 7.1.1–7.1.4 PASS in the demo environment.

### WP-7 Decision-gate deployment and adversarial gate testing
- **Objective:**
  - a real relying-party service using `gateenforce`;
  - a PoC-capability mode (`snapshot_hash`, `resource`, `nonce`, `measurement`, `alg`);
  - recorded human declines (4.1.6);
  - an **adversarial gate battery**: our 18 acceptance cases + upstream A1/A6/A7/A8/A10/A11 analogues + Hauge's cases + Lucid-generated candidates (offline, human-reviewed).
- **Requirements:** 4.1.x, 4.2.1, 7.1.4(b), 7.6.3, 8.3.3–8.3.5; SD-16.
- **Depends on:** WP-1.
- **Effort:** 2–4 ew.
- **Security impact:** tests verdict correctness, not just logging.
- **Acceptance:** an outside party can rerun the battery from the repo.
- **Done:** battery published; one outside reproduction.

### WP-8 Key custody
- **Objective:** PIV/HSM signer in release builds (witness and gate); replace the machine-id MAC/encryption key with `internal/keymaterial`; signed rotation records; compromise procedure exercised.
- **Requirements:** 6.3.1–6.3.3, 7.3.2.
- **Depends on:** WP-1.
- **Effort:** 2–4 ew. Hardware is needed for testing (the new machine helps).
- **Security impact:** an operator account alone can't forge heads.
- **Acceptance:** key non-exportable; rotation record verifies the old→new link.
- **Regression tests:** C07 `Probe_MACKeyInputIsNotSecret` passes.

### WP-9 Level 2 hygiene
- **Objective:** a secondary durable failure log; evidence-read access records; scheduled verification results recorded as evidence (installed by default); proof-coverage metric.
- **Requirements:** 7.6.1, 7.6.4, 7.3.1, 10.3.6.
- **Depends on:** WP-6 (coverage needs the action population).
- **Effort:** 2–3 ew.
- **Regression tests:** C07 `Probe_WriteFailureIsRecordedElsewhere` passes; a stalled-verification test (#154).

### WP-10 Interoperability adapters
- **(b) Clean-room PoC verifier:**
  - strict parser, RFC 8785, Ed25519, SHA-256 RFC 6962 with a leaf-to-root binding check;
  - passes 17/17 vectors for the stated reasons and flags `modify-bound` (#170) as an expected disagreement.
  - **1–2 ew, no dependencies.**
- **(a) Native PoC-token emitter** from the gateway and gate: 2–4 ew. Depends on WP-1 and WP-6.
- **Acceptance:** upstream `validate.py` accepts our emitted tokens; our verifier accepts upstream vectors.

### WP-11 Encrypted-evidence verification (optional unless C2 is claimed)
- **Objective:** salted or hiding leaf commitments plus a disclosure procedure (SD-05).
- **Requirements:** 2.3.1, 1.4.2.
- **Depends on:** WP-1.
- **Effort:** 2–3 ew.

### WP-12 Distributed edge reference implementation
- **Objective:** the demo in `cloudflare-edge-feasibility.md` §2: three nodes, Workers + Durable Objects co-signer, a non-Cloudflare co-signer, the verifier, scripted scenarios and benchmarks.
- **Depends on:** WP-2, WP-3, WP-4, WP-6 (minimum gateway), WP-7.
- **Effort:** 3–4 ew.
- **Acceptance:** every success criterion in that file passes; benchmark report published.

### WP-13 Commercial prerequisites (non-engineering)
- Legal review (commercial-readiness §5); witness operations runbook; leadership decisions on outreach.

## Grouping

| Group | Work packages | Range |
|---|---|---|
| **Minimum viable Tier 2** (statement) | WP-0 | 1–2 ew |
| **Minimum viable Tier 3** (C4 + cross-cutting) | WP-0, WP-1, WP-2, WP-3, WP-4, WP-5 (per-source part), WP-6, WP-7, WP-8, WP-9 | **21–37 ew** (+ outside parties) |
| **Additional for Tier 4** | Fail-closed for all in-scope actions (extends WP-6), interaction inventory (8.3.1/8.3.2), record-level reconciliation (10.3.2), validator and alert SLAs (10.3.3/10.3.4), third-party re-assessment (10.3.5) | +6–10 ew + external assessor |
| **Optional hardening** | WP-5 origin sequencing and epoch links, WP-11, hardware attestation (only if SD-03 is resolved as mandatory) | +4–8 ew |
| **Cloudflare demonstration** | WP-12 (needs WP-2/3/4 + minimal WP-6/7) | 3–4 ew on top |
| **Commercial service** | WP-13 plus a public witness operating record (months, not weeks) | external |

## Feasibility against 2027-02-01 [INFERENCE]

- **Full Tier 3 by February 1 is not feasible at the stated capacity.** It needs 21–37 ew against about 8–10 available, and depends on an independent co-signer and an outside verification run.
- **It would need about 3 engineer-equivalents** starting in early December, and the gateway (WP-6) would still be the schedule risk.
- **Achievable by February 1 at about 1 ew/week (recommended Phase 2 scope):**
  1. WP-0 (Tier 2 statement; correct the published C07 document);
  2. WP-10(b) (clean-room PoC verifier, 17/17 vectors): **the clearest "independent implementation" evidence**;
  3. WP-2 (consistency proofs);
  4. WP-1 (identifiers, schema, hash decision);
  5. WP-3 prototype with one Cloudflare-hosted and one LAB co-signer (demo-grade, not yet independent operators).

  This yields a credible **"independent verifier + Tier 2 statement + Tier-3-ready anchoring prototype"** position at v1.0 publication, with the gateway (WP-6) as the stated next milestone.
- **No completion date is promised.** Revisit after WP-0 and WP-10(b), with measured velocity.
