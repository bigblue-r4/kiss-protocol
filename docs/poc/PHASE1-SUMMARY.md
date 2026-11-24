# Proof-of-Control Phase 1: summary (open this first)

| | |
|---|---|
| **Specification** | `LFDT-ProofOfControl/ov-poc-standard` @ `54a7bc67140b39c9107216cd390dd47c1d42946d` (Working Draft v0.1; v1.0 targeted for 2027-02-01 per `RELEASE.md`) |
| **Assessed** | `bigblue-r4/kiss-protocol` @ `a78b609685b9e002efad666c66e6ff3ad1122b8f` (v3.4.0): Witness + `gate` + `pkg/gateenforce` + the Pipelock bridge |
| **Method** | Clean-room (spec text and Appendix E; no upstream `impl/` source read); upstream vectors and attacks run as black boxes; nothing posted upstream; no source changes (this branch adds `docs/poc/` only) |
| **Date** | 2026-11-24 |

## Confirmed findings

**Requirement status: all 127 assessed, each exactly once.**

| PASS | PARTIAL | FAIL | N/A | UNCLEAR |
|---:|---:|---:|---:|---:|
| 2 | 49 | 64 | 10 | 2 |

- PASS: 4.1.8 (advisory signals cannot raise authorization) and 7.5.1 (execution-fact schema).
- UNCLEAR: 7.2.3 and 7.2.4 (SD-03).
- Detail: [`conformance-matrix.md`](conformance-matrix.md) / [`.json`](conformance-matrix.json).

**Current demonstrated tier: none complete, not even Tier 1.**
- Tier 1 fails on missing documents: no conformance statement, claim register, retention period or claims review.
- The integrity mechanism is Level-2 grade and capped at Tier 2: operator-held key, operator-run mirror, "a centralized Merkle tree … sits at Tier 2" (C8:71; 8.1.3).
- See [`tier-assessment.md`](tier-assessment.md).

**Baseline runs:**
- `go test -race ./...` green;
- upstream `validate.py --vectors`: 17 passed (the docs say 16; reproduced);
- 11/11 upstream attacks reproduce;
- `modify-bound` vector defect (#170) reproduced;
- our C07 probe suite: 18 pass / 13 fail.

**Correction owed:** our published `CONFORMANCE_C07.md` wrongly lists the `replay` tamper case as passing. Since v3.3.3 a replayed tail record is quarantined as a crash tail, with a WARN, rather than rejected. See [`assessment-baseline.md`](assessment-baseline.md).

**Strongest existing PoC mechanism:**
- The gate's **commit-wait**: no token is signed until the request record is witnessed.
- **Action-bound single-use tokens** checked at the relying party: C7.1.3 and C7.1.4(b).
- Both TESTED in simulation, not deployed.

### Top 5 engineering blockers

1. **No Action Interception Gateway** (7.1.1–7.1.4). Without it, 7.1.5 caps claims about executed actions at Tier 1–2.
2. **No independent anchoring or equivocation resistance** (7.3.3, 7.6.6, 7.2.2): single operator key, operator-run mirror, local clock.
3. **No consistency proofs and no verification without operator help** (7.3.5, 7.3.4, 8.1.5): records are encrypted, and the leaf feed only goes to the operator's mirror.
4. **Evidence format is neither self-describing nor PoC-interoperable** (7.7.1–7.7.3, 7.7.5): no algorithm identifiers, no published schema, and BLAKE3 is not in the spec's hash set.
5. **Key custody** (7.3.2, 6.3.1–6.3.4): a software key readable by root; the MAC key comes from `/etc/machine-id`; no rotation records.

### Top 5 residual security risks

See [`trust-boundary-assessment.md`](trust-boundary-assessment.md).

1. Agent effects outside any enforcement point are **undetectable**, unless they leave drift traces.
2. A root operator controlling both the host and the mirror can rewrite and re-sign history undetected by **new** verifiers.
3. Split-view equivocation is **undetectable** (upstream A5 has no Witness counterpart).
4. A single event dropped before ingestion, or a forged source line, is **undetectable**.
5. Timestamps are local and the head time is unsigned, so evidence can be backdated. A replayed tail record looks like a benign crash (WARN).

## Proposed strategy (not confirmed)

- **Estimated effort to Tier 3** (C4 Authorization + cross-cutting): **21–37 engineer-weeks** plus outside parties (an independent co-signer and an outside verification run). The gateway alone is 6–10. See [`phase2-roadmap.md`](phase2-roadmap.md).
- **2027-02-01 feasibility:** full Tier 3 is **not feasible** at about 1 engineer-equivalent: about 8–10 engineer-weeks are available. It would take about 3 engineers, with the gateway still the schedule risk.
- **Achievable by Feb 1 (recommended Phase 2 scope)**, at the low end of the estimates (about 7–13 ew; trim WP-3 to one co-signer pair if behind):
  1. Tier 2 Self-Declared statement and the C07 correction (WP-0);
  2. a **clean-room PoC verifier** passing 17/17 vectors (WP-10b), the clearest evidence of an independent implementation;
  3. consistency proofs (WP-2);
  4. identifiers, schema and the hash decision (WP-1);
  5. a co-signing prototype (WP-3).
- **Cloudflare integration:** technically **feasible** with Workers + Durable Objects + R2 as one independent co-signer and the public checkpoint host. See [`cloudflare-edge-feasibility.md`](cloudflare-edge-feasibility.md).
  - To verify first: Ed25519 in the Workers runtime; BLAKE3 via WASM (or a SHA-256 profile); our S3 backend against R2.
  - Under the draft's trust rules, Cloudflare can be **one** independent operator, never the whole quorum. A second, non-Cloudflare co-signer is required.
  - No corporate interest is assumed.
- **Strongest potential differentiator (hypothesis):**
  - host-level evidence (drift, process identity) **plus** a fail-closed decision gate with witnessed commit-wait, in one small, signed, open-source stack;
  - a public record of finding, fixing and disclosing defects in our own verifier.

  See [`commercial-readiness.md`](commercial-readiness.md).

## Decisions needed from SGAIL leadership

1. **Claim scope:** C4 Authorization plus cross-cutting first; C6 deferred, since it needs TEE and HSM.
2. **Hash decision:** keep BLAKE3 with a mapping, or adopt a SHA-256 profile. A new log format means a new epoch.
3. **Publish the correction** to `CONFORMANCE_C07.md`, a public document.
4. **Upstream:** whether and when to file follow-ups from [`spec-defects.md`](spec-defects.md) (22 drafts, not filed) and from [`issues-and-provenance.md`](issues-and-provenance.md). Our 8 issues remain open with no maintainer response.
5. **Outreach:** to independent implementers (SHACKLE, VERITON, the #170 second-verifier author) and to platform partners. External communication; none made.
6. **Legal review:** copyright holder versus SGAIL LLC, AI-assisted contributions, names, liability (commercial-readiness §5).
7. **Staffing:** decide on staffing before committing to any date. Also recruit an independent co-signer operator.
8. **Gate in releases:** whether to ship `gate` in release binaries.

## Files

1. `PHASE1-SUMMARY.md`: this page
2. `conformance-matrix.md`, `conformance-matrix.json`
3. `tier-assessment.md`
4. `interop-feasibility.md`
5. `issues-and-provenance.md`
6. `spec-defects.md`
7. `trust-boundary-assessment.md`
8. `sgail-ecosystem-architecture.md`
9. `cloudflare-edge-feasibility.md`
10. `commercial-readiness.md`
11. `phase2-roadmap.md`
12. `assessment-baseline.md`
