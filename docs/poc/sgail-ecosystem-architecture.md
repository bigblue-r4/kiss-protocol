# SGAIL ecosystem: existing components and a proposed Proof-of-Control architecture

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · related repositories inspected read-only on 2026-11-24 · nothing implemented in Phase 1.

Labels: [VERIFIED] code or tests read; [INFERENCE]; [PROPOSAL].

## 1. Components

| Component | Existing capability [VERIFIED] | Verified integration status | Potential PoC coverage | Missing interfaces | Deployment boundary | Dependencies | Security limits | Integration effort [PROPOSAL] |
|---|---|---|---|---|---|---|---|---|
| **Harborlight Witness** (`kiss-protocol`, Go, v3.4.0) | Encrypted append-only RFC 6962-shaped log (BLAKE3); signed heads; pinned verifiers; export and leaf feed; drift (files, processes, executable identity); signed drift approvals; event feeds; death records; mirror | Deployed on the OptiPlex test host (observed 2026-11-23); ingests Pipelock, SBH and ann-house feeds | 7.2.1, 7.3.1–7.3.5, 7.5.1, 7.6.x, 8.1.5, 9.2.1, 10.1.8 (see matrix) | Consistency proofs; co-signature intake; algorithm identifiers; published schema; PoC-token emitter | Per host, as uid `witness` | Go stdlib, x/crypto, blake3, toml | Single operator-controlled key and mirror; machine-id MAC key; plaintext leaf preimages | Core of the roadmap |
| **gate + circuit breaker** (`internal/gate`, `pkg/gateenforce`, source-only `0.1.0-dev`) | Signed policy; decision core (budgets, in-flight caps, approvals); breaker with quorum reset; evidence view over the witness log; commit-wait inclusion proofs; single-use action-bound tokens; relying-party library (stdlib-only) | 18 acceptance tests in simulation; **not deployed**; no production relying party | 4.1.1–4.1.8, 4.2.1, 7.1.3, 7.1.4(b), 7.6.3, 8.3.3–8.3.5 (PARTIAL; 4.1.8 PASS) | PoC capability fields (`snapshot_hash`, `measurement`); during/after records; a gateway in front of it; decline records | Separate daemon and uid; unix socket with peer credentials | Witness log (read-only), pinned witness key | Software gate key (PIV deferred); scope limited to callers who ask | 2–4 wk to deploy behind a demo relying party |
| **Pipelock** (third party, `pipelab-org/pipelock`) | Forward proxy and MCP scanning, DLP, receipts | Launched and tailed by the Witness bridge; pinned to the v3.8.0 commit in installers | 6.1.2, 1.2.1 (PARTIAL) | Default-deny routing (the agent must not bypass it) | Child process of the witness | External project | Mediates only traffic sent to it | Part of the T3-5 gateway |
| **Split-Brain Harness** (`split-brain-harness`, Rust, v1.6.0) | Multi-pass analysis with local models; arbitrator (accept / refine / escalate → `stop_and_ask`); forge; verdict logs | Witness ingests SBH decision and session logs (`internal/sbh/bridge.go:50-58`); the gate reads SBH verdicts as **advisory** signals that can only deny or demand approval (`TestAcceptance10SBHStopAndAsk`) | 4.1.8 (advisory cannot raise authorization: PASS); input to decision evaluation | A stable verdict schema with algorithm and model digests (1.1.1-style provenance for its own model) | Separate process or host; local model server | Ollama models | **Probabilistic**: verdicts are model outputs; no determinism guarantee | 1–2 wk for a verdict schema and provenance |
| **deobfuscate** (crate v1.18.2, MIT) | 7-pass encoding-evasion normalizer | **Not linked** into Witness, gate or SBH `master` (no dependency found) | Input normalization ahead of policy or DLP (C4/C6 support, not evidence) | A gateway hook (normalize before policy evaluation) | Library | — | Detection aid; false negatives possible | 1 wk to wire into a gateway pre-filter |
| **unicode-interference** (crate 1.0.0) | Homoglyph and interference detection | **Not linked** anywhere in the PoC stack | As above | As above | Library | — | Heuristic | As above |
| **Independent verifier** | `witness verify`, `verify-export`, `verify-leaves` (Go; same codebase as the writer); `gateenforce` (stdlib-only) | Exist; **not independent** of the writer's codebase | 8.1.5, 8.1.8 | A clean-room PoC-token verifier; a standalone checkpoint verifier with no Witness internals | CLI | — | Same authors and codebase as the producer | 1–2 wk (interop plan (b)) |
| **Lucid** (research mode of SBH's Dream Engine, `src/dream_engine.rs`: "Isolated, in-memory Dream/Lucid research controller") | Hypothesis generation and diagnostic experiments with model calls | Research only; examples `lucid_pilot.rs`, `lucid_diagnostic.rs` | **None directly.** At most a test-generation aid (below) | Exporting candidate fixtures for human review | Research harness only | Local models | Model output is untrusted data | 1–2 wk for an offline fixture pipeline |

## 2. Can SBH support independent decision evaluation without making model agreement the authorization? [INFERENCE]

Yes, under the typing the gate already enforces:
- SBH output is a **constraint**, never a **state gate**. It can deny, demand approval or trip a scope. It can never allow.
- That rule is implemented today (`internal/gate/core/core.go:50` ADVISORY_DENY; `TestAdvisorySignals`) and matches Gravit's "no aggregation laundering" proposal (#123).

Conditions:
1. Authorization stays deterministic: signed policy, budgets, operator approvals.
2. SBH verdicts are recorded as **observed outputs** with the model digest and SBH version (7.5.1: execution facts, not correctness claims).
3. Disagreement between SBH passes is evidence for escalation, never a reason to allow.
4. The claim's trust disclosure says SBH is advisory, so it doesn't enter the authorization trust set.

Under these conditions SBH adds independent *evaluation* without weakening the authorization *proof*.

## 3. Can Lucid generate adversarial decision-gate regression tests? [INFERENCE / PROPOSAL]

Plausibly, as an **offline fixture generator**:
1. Lucid proposes candidate adversarial `ActionRequest`s, policy edits and signal sequences (replay, split-amount, cross-asset bursts, epoch races, approval swaps).
2. A deterministic oracle, the gate core plus `gateenforce`, evaluates each one.
3. Any case where the outcome differs from the policy's specification, or the breaker fails to trip, is written out as a candidate fixture with a structured failure analysis: input, expected, observed, the reason code that differs.
4. A human reviews each candidate before it is committed as a regression test.

**Hard isolation rules:**
- Lucid never runs in the gate's or witness's process or host.
- Its output is never parsed into trust decisions.
- Committed fixtures are plain data with no model in the loop at test time.
- The research harness has no access to production keys or evidence.

The value is breadth of adversarial cases. The evidence for PoC remains the deterministic test battery, which an outside party can reproduce, as SHACKLE's 82-case battery was (#145).

## 4. Proposed separated architecture [PROPOSAL; not built]

```
 ┌───────────────────────── Research & adversarial testing (offline, isolated) ───────────────┐
 │  Lucid / SBH Dream Engine ─► candidate fixtures ─► human review ─► committed test battery   │
 └──────────────────────────────────────────────────────────────────────────────────────────────┘
        (no runtime path)

 1 Agent execution        2 Deterministic policy        3 Decision evaluation (advisory)
 ┌──────────────┐  req    ┌────────────────────┐  sig  ┌──────────────────────────┐
 │ agent (no    ├────────►│ Gateway (T3-5):    │◄──────┤ SBH, Pipelock DLP,       │
 │ direct egress│         │ default-deny egress│       │ deobfuscate/unicode      │
 │ no tool creds│◄────────┤ + gate (policy,    │       │ pre-filters: can only    │
 └──────────────┘ result  │ budgets, approvals)│       │ deny / escalate          │
                          └─────────┬──────────┘       └──────────────────────────┘
                     before/during/after records + action-bound token
                                    │
 4 Evidence collection              ▼                    5 Cryptographic commitment
 ┌────────────────────────────────────────────┐        ┌──────────────────────────────┐
 │ Witness: per-source sequenced feeds, drift,├───────►│ Witness log (host) + PoC token│
 │ gateway records, failure log               │        │ stream (SHA-256 RFC 6962),    │
 └────────────────────────────────────────────┘        │ signed checkpoints            │
                                                       └──────────────┬───────────────┘
                                                                      │ checkpoints + leaves
 6 Independent verification                                           ▼
 ┌────────────────────────────────────────────────────────────────────────────────────┐
 │ ≥2 independent co-signing witnesses (different operators) · public checkpoint feed  │
 │ clean-room verifier(s) · relying party enforces tokens (fail closed) · auditors     │
 └────────────────────────────────────────────────────────────────────────────────────┘
```

**Separation rules:**
- **Agent:** holds no tool credentials, and its only egress is the gateway (7.1.1, 7.1.4(a)).
- **Policy enforcement is deterministic:** a signed policy and the gate. Advisory evaluators feed in but cannot allow.
- **Evidence collection** is a different process and uid from both the agent and the gateway. Witness keeps its "sole writer" design.
- **Commitment:** signing keys live in hardware (PIV/HSM) on the evidence host, not readable by the operator account (7.3.2).
- **Verification:** at least one co-signer and one verifier are run by parties other than the operator. The relying party enforces tokens at the far end (8.3.5).
- **Research:** no runtime path; fixtures only.
