# SGAIL standards issues, outside input, and credit record

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · states read 2026-11-24 via the GitHub API.

**Rules for this document:**
- Affiliations are as each person stated them on the thread or on their public GitHub profile.
- Participation in a standards thread is **not** a contribution to SGAIL code, and **no** corporate interest or endorsement is inferred from anyone's affiliation.
- Nothing here has been or will be posted upstream from Phase 1.

## 1. SGAIL issues #148–#155 (filed 2026-10-21 by `@bigblue-r4`, "SGAIL LLC — contact Chris Howard")

Repository: `LFDT-ProofOfControl/ov-poc-standard`.

**State common to all eight:**
- **OPEN**, no labels.
- **No maintainer response.** None of the comments is from a maintainer (`@jim-schwoebel` logs dispositions on other issues).
- The public-comment register (`docs/reviews/public-comment-register-2026-10.md`) was last changed 2026-10-08, before these were filed.
- The last commit to the standard is 2026-10-31 (README process change).

The "Phase 1 effect" column says whether this assessment strengthens, weakens or supersedes the original concern.

| # | Concern (short) | Outside responses | Proposed resolution (ours) | Phase 1 effect | Related SGAIL changes | Open uncertainty |
|---|---|---|---|---|---|---|
| [#148](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/148) F1 | 7.6.2 catches gaps only after the writer numbers a record; one event dropped upstream leaves no trace | **Bjørn Vidar Hauge** (`@buge4`, VERITON AS, commercial interest disclosed), 10-29: supports it and proposes two assessor cases: (1) source restart with counter reset; (2) unreadable observation surface. Cross-referenced by **#171** (Michal Niemiec), **#173** and **#182** (Mikhail Sergeev, PAI-Kernel). | New 7.6.7 (L3): origin sequencing, or a disclosed limitation | **Strengthened.** Probe `Probe_SingleSuppressedEventIsDetectable` still fails on a78b609; Witness sequence numbers are global, not per source (7.6.2 PARTIAL). Hauge's restart case also exposes our own gap: a new epoch has no signed link to the old chain (3.2.2 FAIL). | none yet | Whether the WG adopts origin sequencing or disclosure |
| [#149](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/149) F2 | Are 7.2.3/7.2.4 (hardware attestation) mandatory at L3 or conditional? | None directly. Cross-referenced by **#174** (Sergeev: assessor procedure for vendor-rooted attestation; Hauge adds a reporting point) and **#180** (Tim Bansemer, inblock.io: name the outcome, not the mechanism). | Condition them on a claim that relies on attestation, or state that they are mandatory | **Strengthened.** Both rows are UNCLEAR in our matrix (SD-03). The answer decides whether a software-only Witness can ever reach Tier 3. | none | Pivotal for our Tier 3 path |
| [#150](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/150) F3 | A verifier that is behind treats a size difference as lag; a rewritten history plus one record passes | **Dante Bullock** (`@Fame510`, Sovereign Logic / SHACKLE), 10-26: cites our reproduction as confirming **#139**; groups it with #139 and #146 ("what the evidence must survive"); promotes his **#145** (decision-gating). Cross-referenced by our #154. | Require a consistency proof whenever sizes differ | **Partly superseded for Witness, strengthened for the spec.** Our audit fix (v3.3.3) plus the leaf feed and `verify-leaves` (v3.4.0) close it for holders of earlier leaves. We still have **no consistency proofs** (7.3.5 PARTIAL), and the local-verifier probes fail. Upstream attack A9 shows the reference implementation needed the same fix. | `830e21f` (#30, audit prefix check), `07a4e23` (#61, leaf feed) | None on the spec side |
| [#151](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/151) F4 | A torn write can make a store unopenable; 7.6.1 doesn't cover interrupted writes | **Hauge**, 10-29: supports it and credits the original contributor; proposes a **paired** test (interrupted write vs an altered earlier record), where recovery must not hide a mismatch | Append an interruption-safety clause to 7.6.1 | **Strengthened, with one nuance.** Our crash-tail rule meets Hauge's paired case (one uncommitted record quarantined; anything else is tampering; `TestTwoExtraRecordsAreStillTampering`). Phase 1 found that the C07 `replay` sub-case is classified as a crash tail (quarantined, WARN) rather than tampering. That fits Hauge's wording ("report", don't hide) but should be stated in our claim. | `830e21f` (#30), `c10eb40` (#60, fsync before head) | Whether quarantine plus WARN counts as "reported as a failure event" |
| [#152](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/152) F5 | Level 3 says anyone can verify; can evidence contents stay confidential? | **Hauge**, 10-29: a predicate-to-record binding test (swap B's predicate evidence onto A's inclusion proof). Cross-referenced by **#180**. | A note: roots, proofs and leaf hashes are enough, plus a stated disclosure policy | **Strengthened, plus a new self-finding:** Witness leaves hash plaintext record JSON, so publishing the leaf feed lets anyone **confirm a guessed record** (2.3.1 FAIL, SD-05). Our own proposed wording would need a salted or committed leaf to be safe. | `07a4e23` (#61) documents the guess-confirmation limit | Disclosure-policy wording versus leaf privacy |
| [#153](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/153) F6 | The control objective lists four properties; C7.7 defines a fifth; "binary" has no row | None directly. Cross-referenced by **#177** (Bansemer: conformance should not depend on one format; Mayur Agnihotri, StraightArc, replied 11-13). | Add "interoperable"; give "binary" a row | **Unchanged** (editorial). SD-02. | n/a | — |
| [#154](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/154) F7 | 7.3.1 "defined schedule" has no bound and no required response | **Hauge**, 10-29: maximum verification lag, completed-horizon reporting, stalled-check and old-checkpoint cases | Bound the schedule by the anchoring interval; record results; alert on failure | **Strengthened.** Our own 5-minute pinned audit timer exists but isn't installed by default and doesn't record results as evidence (7.3.1 PARTIAL). | `0c505bc` (#56, `witness-audit.timer`) | — |
| [#155](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/155) F8 | No RFC 2119 keyword in any row; Appendix A says claims are assessed against MUST | None | One sentence making each row MUST at its Level | **Unchanged.** Still true at 54a7bc6 (SD-01). | n/a | — |

### Related threads: cross-references to our filings, and how Phase 1 bears on them

| # | Author (self-stated) | Topic | State | Relation to Phase 1 |
|---|---|---|---|---|
| [#139](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/139) | Zorie Barber (`@Z0rlord`, The Membrane) | The tree must commit to leaf count and order; three self-found defects | OPEN, 1 comment (Bullock) | Witness passes the construction points: RFC 6962 split, 0x00/0x01 tags, append order, exact split and proof depth (`internal/merkle`, C18 fix `68b5c89`). We have not published the three negative vectors he proposes. |
| [#145](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/145) | Dante Bullock (SHACKLE) | Decision-gating is the missing conformance layer; 82/82 reproduced battery | OPEN, 2 comments | Our `gate` is a decision gate with 18 acceptance tests, **not independently reproduced**. Relevant to SD-16 (decision-gate assurance). |
| [#146](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/146) | Dr. Christian Rustenbach (Univ. Tübingen) | Verified control adherence ≠ effective human intervention | OPEN, 10 comments | Gate approvals bind identity, content and time, but a human *decline* is not recorded (4.1.6 PARTIAL); no intervention-path evidence. |
| [#170](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/170) | Sankalp Gilda (`@astrogilda`) | Second verifier; the `modify-bound` root commits to ALLOW | OPEN | **Reproduced independently in Phase 1.** |
| [#173](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/173) | Mikhail Sergeev (PAI-Kernel) | Equal totals don't prove coverage (10.3.2) | OPEN, 4 comments | Applies to our future 10.3.2 work: reconcile by operation × attempt × phase. Its addendum notes the `interception_point` enum lacks "during" (confirmed: SD-18). |
| [#174](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/174) | Mikhail Sergeev | Assessor procedure for composed / vendor-rooted claims | OPEN, 2 comments | Relevant only if we add TEE attestation. |
| [#177](https://github.com/LFDT-ProofOfControl/ov-poc-standard/issues/177) | Tim Bansemer (inblock.io, Aqua SDK) | Conformance should not depend on one evidence format | OPEN, 1 comment (Mayur Agnihotri, 11-13) | Decides whether a BLAKE3 Witness format could conform without a SHA-256 emitter (SD-13). |

## 2. Outside contributions to kiss-protocol: credit record

Searched:
- all kiss-protocol issues (2: #10 and #14) and every PR not authored by `bigblue-r4` (1: Dependabot #34);
- commit messages for references to outside reports;
- the PoC threads for any suggestion implemented in kiss.

Excluded: internal tools (Codex and Claude, both working for SGAIL) and unrelated automation.

| Suggestion | Contributor | Public source | Date | Implementing commit(s) | Component | Related PoC req. | Verification |
|---|---|---|---|---|---|---|---|
| The generated Pipelock config used keys Pipelock rejects, so the proxy silently didn't start; fail loud on startup. A corrected config was supplied. | Josh (`@luckyPipewrench`, Pipelock maintainer) | [kiss-protocol#10](https://github.com/bigblue-r4/kiss-protocol/issues/10) | 2026-07-10 | `d706784` "fix(pipelock): generate valid v3 config and fail loud on startup"; released v3.2.1 (`f856912`) | PIPE bridge | 7.6.1 (pipeline failure must alert); 6.1.2 | VERIFIED: the commit message and the issue reply say so |
| Test receipt ingestion against a real Pipelock v3.0.0 build, not a dev banner (prompted the flight-recorder work) | Josh | #10 comments | 2026-07-10 | `121ac04` "fold flight_recorder receipts into the witness log" (designed and written by SGAIL; prompted by the discussion) | PIPE bridge | 6.1.2; 1.2.1 | VERIFIED as prompted-by, not authored-by |
| Live interop test: four findings (receipt classification, clean-shutdown drain, genesis hash ordering, …) | Josh | #10 comment | 2026-07-10 | `60b2336`, `5d1ed8f`; released v3.2.3 (`c8f562a`) | PIPE bridge; genesis | 7.2.1; 7.6.1; 7.3.1 | VERIFIED (release note "pipelock interop fixes from issue #10 live test") |
| v2 `evidence_receipt` verdict path (`detail.payload.verdict`) and the `session_control` version note; a signed live capture supplied as a fixture | Josh | [kiss-protocol#14](https://github.com/bigblue-r4/kiss-protocol/issues/14) | 2026-07 | `249470d` (#15) | PIPE bridge | 6.1.2; 7.5.1 | VERIFIED |
| Keep ingesting fetch receipts **and** the audit log (receipts don't carry warn verdicts) | Josh | [pipelab-org/pipelock#1675](https://github.com/pipelab-org/pipelock/issues/1675) | 2026-09-26 | Design guidance confirming the existing dual ingestion; **no specific commit** | PIPE bridge | 6.1.2 | VERIFIED as guidance only |
| SSRF allowlist for LAN monitor targets | Josh (fix in **Pipelock**, not kiss) | [pipelab-org/pipelock#1053](https://github.com/pipelab-org/pipelock/issues/1053) | 2026-07 | Upstream Pipelock v2.3.0; **no kiss-protocol commit** | Pipelock (third party) | n/a | VERIFIED: an upstream contribution to Pipelock, listed so it isn't miscredited to kiss |
| Bump `golang.org/x/crypto` | Dependabot (automation) | [kiss-protocol#34](https://github.com/bigblue-r4/kiss-protocol/pull/34) | 2026 | Superseded by `fc3dd46` (#54, x/crypto 0.59.0, which also clears advisories 0.52 still carried); #34 closed 2026-11-18 | deps | 6.3.x hygiene | VERIFIED |
| The attack class "rewritten, re-signed history + append" (the standard's own C7.3.5 note on attack A9) | The PoC working group (spec authors; no individual named) | Spec C7.3.5 note at `93d0e28` | 2026-09/10 | Our C07 test reproduced it in Witness; fixed in `830e21f` (#30, v3.3.3). CHANGELOG 3.3.3 says "attack class described in C7.3.5". | WIT audit | 7.3.5 | VERIFIED |

**Not contributions to kiss-protocol** (standards participation only; nothing implemented from them yet):
- Dante Bullock (#145, #150)
- Bjørn Vidar Hauge (#148, #151, #152, #154)
- Zorie Barber (#139)
- Sankalp Gilda (#170)
- Mikhail Sergeev (#173, #174, #182)
- Tim Bansemer (#177, #180)
- Michal Niemiec (#171)
- Mayur Agnihotri (#177)
- Christian Rustenbach (#146)

Several of their proposed assessor cases are recommended as Phase 2 regression tests (phase2-roadmap.md). If implemented, the implementing commit should cite the thread and author, and this table should be updated.

**Not found:**
- No external PR to kiss-protocol has ever been merged.
- No commit cites a PoC participant.
- No outside suggestion relates to the gate.
