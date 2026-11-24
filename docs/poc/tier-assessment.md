# Tier assessment: Harborlight Witness against Proof-of-Control

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` (v3.4.0) · 2026-11-24

Labels used below:
- **[VERIFIED]:** checked in code, tests or spec text.
- **[INFERENCE]:** architectural reasoning from verified facts.
- **[PROPOSAL]:** a design not yet built.

## 1. Current demonstrated tier

**No complete tier is demonstrated today, not even Tier 1. [VERIFIED]**

The gating rule, `0.1/en/0x03-Using-Proof-of-Control.md` (Requirement Levels):

> "Levels are cumulative — a claim at Tier N must satisfy every requirement at Level N and below."

> "Meeting all Level 1–3 requirements in the claimed domains is the minimum for a Proof-of-Control claim."

Two separate facts set the ceiling:

1. **Tier 1 fails on documents, not mechanisms.** Several Level 1 rows that apply to any claim are FAIL because the artifacts they inspect don't exist:
   - 8.1.1 (claim register);
   - 10.1.1–10.1.6 (conformance statement);
   - 7.6.5 (retention period);
   - 7.5.2 (claims review);
   - 9.1.1–9.1.3 (MAESTRO layer fields).

   These are small (S effort) and owned by SGAIL, not by code.
2. **The evidence mechanism is Tier-2-grade, and the spec caps it there.**
   - The Witness log is signed, Merkle-structured and tamper-evident to an assessor holding the key. That is Level 2 ("Attested") evidence.
   - `0x10-C08-Verifiability-Tiers.md:71`: "A centralized Merkle tree is cryptographic and sits at Tier 2, because you still trust whoever controls the root."
   - 8.1.3 (Level 1): claims naming a single trusted party, explicitly "operator-signed logs … centralized Merkle trees", "are registered at Tier 2 or below".
   - Today the operator controls the signing key, the root and the only mirror. [VERIFIED: 7.3.2, 7.3.3, 7.6.6 rows]

**Highest demonstrable position:** Level-2-quality integrity evidence inside a claim that fails Tier 1 on paperwork. Once the C8/C9/C10 and 7.x Level 1 documents exist, a **Tier 2 claim** for a narrow scope becomes available without code changes. [INFERENCE]

### Proposed claim scope [PROPOSAL]

The domain chapters gate only "in the claimed domains". The candidate system (Witness + gate + gateenforce + Pipelock bridge) maps best to:
- **C4 Authorization** (the gate);
- the cross-cutting chapters C7–C10.

**C6 Security is a poor first domain.** Its Level 2 and 3 rows require hardware attestation and HSM keys:
- 6.1.3 (L2) TEE/remote attestation;
- 6.1.4 (L3) hardware-rooted attestation;
- 6.3.1 (L2) non-exportable HSM keys.

C1, C2, C3 and C5 are not claimable with current components (matrix: mostly FAIL, scored on capability).

## 2. Specific assessments

### A. Chain-head anchoring

| Question | Answer | Evidence |
|---|---|---|
| Can a third party verify without privileged access? | **Partly.** `witness verify-export --pubkey` needs only a pinned public key. But the export is **produced by the operator** with the machine key, because records are encrypted. `verify-leaves` needs the leaf feed, which only the operator's mirror publishes. The C07 probe `T3_Probe_ThirdPartyRecomputesRootWithoutMachineKey` **fails**. | 8.1.5 PARTIAL; `internal/store/export.go:137`; `cmd/witness/verify_leaves.go:21` |
| Can the operator present conflicting histories to different verifiers? | **Yes, undetected,** unless two verifiers compare roots out of band. No root gossip, no witness quorum, no ledger (7.3.3 FAIL); gossip carries heartbeats only. Upstream attack **A5 (split view)** has no Witness counterpart. | `internal/gossip/heartbeat.go:198` |
| Can an independent verifier establish continuity between checkpoints? | **Only a verifier holding earlier leaves** (`verify-leaves`). There are no RFC 6962 consistency proofs, so a new verifier must fetch all leaves. A re-initialised log (new epoch) has no signed link to the old chain (3.2.2 FAIL). | 7.3.5 PARTIAL; `internal/merkle/` has `Prove`/`Verify` (inclusion only) |
| Are signing keys pinned and independently distributed? | **Pinned: yes** (`--pubkey`, `--pubkey-file`, `--require-pins`; scheduled pinned audit). **Distributed independently: by hand.** Nothing publishes the key through a channel the operator doesn't control. | `cmd/witness/verifier_flags.go:56`; `packaging/systemd/witness-audit.service:16` |
| Can key rotation be verified? | **No.** Rotation is tolerated (old heads open with the old key), but no signed record links old and new keys (6.3.2 FAIL), and records carry no algorithm or key-version identifier (6.3.4, 7.7.3 FAIL). | `internal/store/store.go:67` |

### B. Action Interception Gateway (C7.1.1)

7.1.1 (L3): "all agent tool and effect invocations are routed through an Action Interception Gateway that runs as a separate process or service from the agent — the agent has no network or credential path to its tools that bypasses the gateway."

- **Does a separate enforcement process exist?** Two exist, and neither is a complete gateway. [VERIFIED]
  - `gate`: a separate daemon and a separate uid. It is an **authorizer**, not a proxy: it issues action-bound tokens that a relying party checks (C7.1.4 option (b)). It only sees what callers send it.
  - **Pipelock:** a third-party forward proxy and MCP scanner, run by the witness. It mediates HTTP/MCP traffic **only if the agent's traffic is routed to it**. Nothing in kiss-protocol forces that.
- **Are all relevant actions mediated?** No. Local file writes, shell commands, local tools, direct sockets and any network path not set to use the proxy are unmediated. [VERIFIED by absence]
- **Bypass paths:** direct egress, local effects, and any credential the agent holds for a downstream service. The gate only binds services that link `gateenforce` and refuse tokenless requests. [INFERENCE]
- **Is enforcement independent of the agent?** The gate and relying party are, provided they run under a different uid or host than the agent; the gate authenticates callers by kernel peer credentials. Pipelock runs as a child of the witness, not the agent. [VERIFIED]
- **Where a gateway would go [PROPOSAL]:**
  1. Put the agent in a network namespace or container whose only egress route is the gateway: the Pipelock forward proxy plus an MCP gateway. Use firewall default-deny (nftables), not a proxy setting the agent can ignore.
  2. Give the gateway, not the agent, the tool credentials (7.1.4(a)), or have downstream services require gate tokens (7.1.4(b), already built).
  3. Have the gateway emit before / during / after records into a witness event feed with a per-source sequence, and hold release until the before-record is durably written, reusing gate commit-wait (7.1.3).
  4. Route local tools through the gateway as RPCs, or run them inside the sandbox with effects observed by Witness drift (detection only).
- **Can a compromised agent invoke tools outside the gateway?** Today, yes. The trust-boundary assessment classifies this as UNDETECTABLE for local effects with no drift trace and as PARTIALLY DETECTED for new binaries and processes.

### C. Fail-closed behaviour (Tier 4)

Applies to gate-mediated action classes only. Everything else is not gated at all. [VERIFIED by tests unless noted]

| Condition | What happens | Evidence |
|---|---|---|
| Evidence missing (the gate cannot write its feed) | No token is issued; the request is refused with `FEED_WRITE_FAILED` and the reservation refunded | `TestAcceptance15UnwritableFeed`; `internal/gate/daemon/daemon.go:479` |
| Witness evidence stale or forged | Refused (stale head, forged head, `CHAIN_UNVERIFIED`; the refusal sticks) | `TestAcceptance08StaleHead`, `TestAcceptance16CommitProofAndForgedHead` |
| Commit-wait not satisfied in time | Refused (`COMMIT_WAIT_TIMEOUT`) | `daemon.go:493-500`; `TestEndToEndCommitWait` |
| Verifier unavailable | `gateenforce` runs in-process at the relying party with pinned keys: no network dependency, so no "unavailable" state | `pkg/gateenforce/gateenforce.go:101` |
| Witness unreachable | Evidence ages; the head is measured on the gate's own clock, so it goes stale and decisions are refused | `TestAcceptance08StaleHead`; `docs/gate-arch.md` |
| Authorization expired | `TOKEN_EXPIRED` | `gateenforce.go:172` |
| Network partition between gate and relying party | High-tier classes need an epoch fresher than 10 s, otherwise `EPOCH_STALE`. Low tier keeps accepting until the token expires. | `gateenforce.go:213-233` |
| Storage failure at the witness | The witness daemon cannot fail anything closed; it records and alerts. The gate sees stale evidence and refuses (above). | 7.6.1 PARTIAL |
| Can an action execute without its required proof? | **Yes** for any action not routed through a relying party that enforces tokens. **No** for gate-mediated classes in simulation. **No real relying party has been deployed**, so this is TESTED, not OBSERVED. | 8.3.3, 8.3.5 PARTIAL |

## 3. Minimum changes, in dependency order

**Mandatory** means: needed to satisfy a Level ≤ N row in the proposed claim scope (C4 plus C7–C10). Effort is engineer-weeks [PROPOSAL; estimates].

### To Tier 2 (narrow scope)

All documents; no code.

1. **T2-1:** Write the conformance statement and claim register:
   - stage Self-Declared;
   - domains, boundary and exclusions;
   - Tier per claim and trust analysis;
   - MAESTRO layer per entry;
   - retention period;
   - trust-assumption disclosure, including the mathematical assumptions (BLAKE3, AES-256-GCM, HKDF, Ed25519, `/etc/machine-id`).

   Rows: 8.1.1–8.1.4, 8.1.6, 8.2.x, 9.1.x, 10.1.1–10.1.6, 10.2.1, 7.4.1, 7.6.5. **1–2 wk**
2. **T2-2:** Documented claims review. Rows 7.5.2, 8.1.4. Needs a legal/compliance sign-off; the README's "Incorruptible" wording needs review. **0.5 wk plus external review**
3. **T2-3 (Level 2 code hygiene that the C4 claim inherits):**
   - record scheduled verification results as evidence (7.3.1);
   - secondary failure log (7.6.1);
   - per-source sequence numbers plus a verifier gap check (7.6.2);
   - evidence-read access records (7.6.4);
   - algorithm identifiers, a published schema, a specified canonical form and duplicate-key rejection for witness records and heads (7.7.1–7.7.3, 7.7.5);
   - machine-readable statement (10.1.7), disclosure tags (10.2.2), inventory reconciliation (10.1.8).

   **3–5 wk**

### To Tier 3 (C4 Authorization + cross-cutting)

Depends on Tier 2 above.

1. **T3-1 Evidence format decision:** adopt the PoC evidence token natively (SHA-256 tree, tagged digests) or keep BLAKE3 and map it (see interop-feasibility.md). This blocks T3-2 and T3-5. **1 wk decision, 2–4 wk implementation**
2. **T3-2 Consistency proofs** (RFC 6962 §2.1.2) in `internal/merkle`, plus a standalone verifier that needs no held leaves (7.3.5). **1–2 wk**
3. **T3-3 Independent witness co-signing:**
   - at least 2 independent operators co-sign checkpoints (7.3.3);
   - the co-signer timestamp or RFC 3161 gives outside time (7.2.2);
   - declared anchoring interval with a missed-deadline alert (7.6.6).

   Depends on T3-1 and T3-2. **3–5 wk, plus calendar time to recruit an independent operator**
4. **T3-4 Public verification without privileged access:**
   - a public checkpoint and leaf feed;
   - inclusion proofs a third party can fetch (7.3.4);
   - a published, versioned verifier (8.1.8);
   - **a recorded verification run by someone with no operator credentials** (8.1.5).

   Depends on T3-2 and T3-3. **1–2 wk plus an external party**
5. **T3-5 Action Interception Gateway:**
   - default-deny egress plus MCP/HTTP gateway (7.1.1);
   - before/during/after records (7.1.2);
   - release precondition (7.1.3, reusing gate commit-wait);
   - bound capability (7.1.4(b), reusing `gateenforce`);
   - out-of-scope blocking at the gateway (4.1.3).

   Without 7.1.4, 7.1.5 limits any claim about executed actions to Tier 1–2. **This is the largest item. 6–10 wk**
6. **T3-6 Key custody:**
   - signing keys the operator and agent cannot read (7.3.2): PIV/HSM build in releases (also 6.3.1 at L2);
   - replace the machine-id-derived MAC key (`internal/keymaterial` already exists);
   - signed rotation records (6.3.2);
   - compromise procedure (6.3.3).

   **2–4 wk**
7. **T3-7 Coverage metric** published per schedule (10.3.6). Depends on T3-5. **1 wk**

**Optional hardening at Tier 3** (not required by a C4 claim):
- origin-side sequencing at sources (#148);
- encrypted-evidence selective disclosure (2.3.1, only if C2 is claimed);
- hardware attestation (only if C6 is claimed, or if #149 is resolved as mandatory).

### To Tier 4

Depends on all of Tier 3.

1. **T4-1:** Fail-closed for every in-scope action, not just gate classes (7.6.3), via T3-5 plus a gate in the release path.
2. **T4-2:** Interaction inventory, with every listed interaction carrying Tier 4 evidence (8.3.1, 8.3.2).
3. **T4-3:** Proof-gated halt demonstrated across the whole scope (8.3.3); halt enforced at the relying party (8.3.5: the design exists in `gateenforce`); availability impact and an exercised recovery (8.3.4).
4. **T4-4:** Continuous monitoring:
   - record-level reconciliation, not totals (10.3.2; see #173);
   - automated validator with logged results (10.3.3);
   - alert SLAs with acknowledgment tracking (10.3.4);
   - third-party re-assessment of the monitoring pipeline (10.3.5).

## 4. What the dependency order implies [INFERENCE]

- The critical path to Tier 3 is **T3-1 → T3-2 → T3-3 → T3-4**, the anchoring chain, running **in parallel with T3-5**, the gateway.
- T3-5 is the longest item, and the only one with no existing partial implementation outside the gate.
- The anchoring chain reuses existing pieces: inclusion proofs, the leaf feed, pinned verifiers.
- The gateway reuses the gate's commit-wait and `gateenforce`, the two strongest PoC mechanisms in the repository today (7.1.3 and 7.1.4 PARTIAL, both TESTED).
