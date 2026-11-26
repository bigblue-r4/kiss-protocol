# Certification-readiness roadmap (Stage 2 view)

**This is not a certification claim.** The pilot makes no Proof-of-Control (PoC) Tier 3 or Tier 4 claim. Certification and Tier 4 are deferred, as the Stage 2 mission says.

This note re-cuts the Phase 1 roadmap (branch `poc/phase1-gap-matrix`, spec `54a7bc6`) to show what the pilot moved, and what still stands between us and any formal claim.

## What the pilot moved (evidence in this branch)

Statuses in the "Phase 1" column are copied from `docs/poc/conformance-matrix.md` on that branch. "After the pilot" applies to the **pilot log only**; the existing Witness log keeps its Phase 1 status. Nothing here has been re-assessed by anyone independent.

| PoC requirement (Phase 1 ID) | Phase 1 | After the pilot (pilot log only) | Evidence |
|---|---|---|---|
| 7.3.3: resists equivocation (gossip, witness quorum, or anchoring) | FAIL | **Witness-quorum mechanism present; independence not yet shown** | tlog-witness client; interop with unmodified omniwitness (422 on a re-signed rewrite); A08–A10. Real independence needs a third-party witness, which is an external contact and needs approval |
| 7.3.5: append-only consistency against earlier roots | PARTIAL | **Consistency proofs between checkpoints; the witness checks them; evaluators keep state** | `pkg/tlog` (cross-checked against `x/mod/sumdb/tlog`); `--state`; A09, A11. PR #77 covers the BLAKE3 Witness log |
| 7.2.2: timestamps anchored outside the operator's control | FAIL | **Partly:** checkpoint existence time is bounded by the witness's signed timestamp; event times are still the host clock | `cosignature/v1` timestamps; `--max-age` |
| 7.6.6: root anchored externally within a declared interval; a missed deadline raises | PARTIAL | **Partly:** checkpoints are witnessed every interval; a cosignature older than `--max-age` is `UNVERIFIABLE` | A12, A13 |
| 8.1.5: an external party verifies with published materials only | PARTIAL | **Met for the pilot log:** plaintext records (D3) and public keys only | `harborlight-verify`; `docs/stage2/example-evaluation/` |
| 7.3.4: single-record inclusion without the rest of the log | PARTIAL | **Unchanged in practice:** `pkg/tlog` has inclusion proofs, but no command serves them yet; the verifier downloads everything | — |
| Evidence-token verification | — | **Built** (PR #78), not yet wired into the pilot report | `pkg/pocverify` |
| Hash alignment with PoC evidence (SHA-256) | open decision | **SHA-256 for new pilot logs** (D2) | `pkg/tlog` |

## What still stands in the way of any formal claim

1. **Conformance statement (WP-0).**
   - The draft is local, on branch `docs/poc-wp0-statement-draft`.
   - It needs decisions on deployment and environment, retention, date and claims reviewer, and on whether to publish.
   - The C07 errata are published separately: `docs/CONFORMANCE_C07-ERRATA.md`.
2. **The C4 gate in force.** Documents alone place no domain; C4 stays unclaimable until the gate is deployed. Leadership expects this to be the largest hurdle.
3. **Key custody.** HSM or PIV custody is needed for anything beyond pilot grade (DEFER).
4. **An independent witness in production**, with a quorum above 1.
5. **Per-source origin signatures and an action interception gateway** (PoC 7.1). Out of the pilot (DEFER).
6. **External assessment.** Only an accredited or independent assessor can turn evidence into a certification. That is an OUTSOURCE item, with no timeline yet.

## Suggested order after the pilot

1. Merge the pilot. Run the Compose path on a Docker host, and sign the pilot binaries in the release workflow.
2. With approval, enrol one independent witness and run a pilot with an outside evaluator.
3. WP-0 statement decisions. (The C07 errata are published: `docs/CONFORMANCE_C07-ERRATA.md`.)
4. WP-3: a co-signer for the BLAKE3 Witness log, or migrating it to the SHA-256 path.
5. Then reassess Tier 3 against the Phase 1 gap matrix. The Phase 1 estimate of 21–37 engineer-weeks for full Tier 3 is reduced by about the work above, but has not been re-estimated.
