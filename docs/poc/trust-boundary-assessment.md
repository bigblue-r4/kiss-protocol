# Trust boundaries and adversarial behaviour

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` (v3.4.0) · 2026-11-24

**Classification:**
- **PREVENTED:** the action or attack cannot complete.
- **DETECTED:** it completes, and evidence available to a verifier shows it.
- **PARTIALLY DETECTED:** only some verifiers, or some variants, catch it.
- **UNDETECTABLE:** no current mechanism can show it.
- **UNTESTED:** no test exercises it, and it can't be classified from code alone with confidence.

The "gate scope" is action classes routed to `gate` and enforced by a relying party using `pkg/gateenforce`. No production relying party exists, so gate rows are TESTED in simulation, not OBSERVED.

## 1. Trust boundaries

```
 ┌──────────── agent host (operator root) ────────────────────────────┐
 │  AI agent ──(optional HTTP proxy)──► Pipelock ──► network           │
 │     │  local tools / files / sockets: UNMEDIATED                    │
 │     │                                                               │
 │     └─(unix socket, kernel peer creds)─► gate ──token──┐            │
 │                                         │ reads (RO)   │            │
 │  feeds (NDJSON: pipelock, sbh, gate, …) ─┼─► witness ◄─┘ gate feed  │
 │                                         │  (sole writer, uid witness│
 │                                         │   key 0400, MAC=machine-id)│
 └─────────────────────────────────────────┼───────────────────────────┘
                                           ▼ heads (+ leaves.bin, file backend)
                              operator-controlled mirror ──► pinned audit / verify-leaves
 relying party (separate service) ◄── token ── checks with pinned gate + witness keys
```

| Boundary | Separates | Enforced by | Weakness |
|---|---|---|---|
| B1 agent ↔ witness | agent identity vs the log writer | separate uid `witness`, hardened systemd unit, seccomp, single capability | root on the host crosses it |
| B2 agent ↔ gate | requester vs decider | separate process; kernel peer-credential check on the socket | the same root crosses it |
| B3 host ↔ mirror | local log vs off-host copy | mirror push and the leaf feed | the mirror is operator-controlled |
| B4 gate ↔ relying party | decision vs effect | Ed25519 tokens bound to the action hash, single use, epoch freshness | only for services that link `gateenforce` |
| B5 agent ↔ outside world | agent effects | **none mandatory**; Pipelock only if traffic is routed to it | the main gap (7.1.1) |

## 2. Scenarios

| # | Scenario | Current behaviour | Class | Evidence | Assumptions | Residual risk | Mitigation (proposed) |
|---|---|---|---|---|---|---|---|
| 1 | Compromised AI agent | Gate scope: it can only request; tokens are bound and single-use, so substitution and replay are refused. Outside gate scope: it can act freely. New binaries and processes appear as drift. | PREVENTED (gate scope) / PARTIALLY DETECTED (host drift) / UNDETECTABLE (local effects with no drift trace) | `TestAcceptance05ReplayAndDifferentAmount`; drift tests | the agent is not root | Unmediated effects | Gateway with default-deny egress (T3-5) |
| 2 | Compromised action gateway | No full gateway exists. A compromised **gate** can sign tokens for any request that passes local checks. With commit-wait, every issued token's request is witnessed first, so issuance is recorded. Breaker and budget state live in the gate. | PARTIALLY DETECTED | commit-wait (`daemon.go:479-505`); `TestAcceptance16CommitProofAndForgedHead` | the witness host is not also compromised | Gate signs "true" tokens for filtered requests (the #78 pattern) | PIV gate key; an independent relying-party feed reconciled against gate records |
| 3 | Compromised event source | A source can write false or missing NDJSON lines. Witness records what it reads: the source field comes from config, not the line. | UNDETECTABLE (false content) / PARTIALLY DETECTED (silence: downtime and liveness) | `docs/event-feeds.md`; C07 `SilencedPeriodicSourceIsFlagged` PASS | file permissions decide who can write as which source | Single dropped or forged events | Origin sequencing plus source signatures (SD-07) |
| 4 | Compromised logging operator (root on the witness host) | Can stop the daemon (recorded on restart as CRITICAL `witness_downtime`), re-sign a rewritten history with the host key, or withhold heads. A rewrite is caught by the pinned audit against the mirror (if the mirror isn't also controlled) and by any `verify-leaves` holder. | PARTIALLY DETECTED | `AuditCatchesRewriteThenAppend`; leaf-feed tests | at least one off-host holder of earlier leaves or heads | The operator also controls the mirror, so a full rewrite of both is undetected by new verifiers | Independent co-signers (T3-3); PIV key |
| 5 | Compromised signing key | Anyone with the key can sign heads. Detection is the same as #4. No revocation or rotation record exists. | PARTIALLY DETECTED | 6.3.2, 6.3.3 FAIL | as #4 | Undetected forgery for new verifiers | Rotation records, compromise procedure, hardware key |
| 6 | Compromised verifier | A verifier reports what it computes; there is no cross-check of verifiers. Pinned keys come from a local file; a compromised verifier host can swap them. | UNDETECTABLE (to that verifier's users) | `cmd/witness/verifier_flags.go:56` | — | A single verifier is a single point of trust | Multiple independent verifiers (a second implementation; interop (b)) |
| 7 | Colluding witnesses | No witness quorum exists, so nothing to collude. With the proposed co-signers, collusion of all co-signers plus the operator defeats it. | n/a today | — | — | — | At least 2 independent operators (SD-11) |
| 8 | Stale verifier | The pinned audit tolerates a mirror lag (default 10 leaves; exit 2 beyond `--max-lag`). The gate measures head age on its own clock and refuses stale evidence. | DETECTED (gate, audit) | `TestAcceptance08StaleHead`; `docs/mirror-setup.md` exit codes | clocks roughly sane on the gate host | No completed-horizon report (#154) | Record verification horizons as evidence |
| 9 | Network partition | Witness keeps logging locally; failed mirror pushes escalate to CRITICAL `mirror_unreachable`. Gate high-tier classes refuse without an epoch fresher than 10 s; low tier continues until token expiry. | DETECTED; fail-closed for high tier | `internal/lifecycle/lifecycle.go:101`; `gateenforce.go:213-233` | — | Low-tier actions during a partition | Classify value-moving actions as high tier |
| 10 | Clock manipulation | Record and head timestamps come from the local clock; the head `ts` is unsigned. The gate uses its own monotonic view of head growth. | UNDETECTABLE (backdating records) / DETECTED for gate staleness | `internal/store/store.go:391`; 7.2.2 FAIL | — | Backdated or forward-dated evidence | Outside time anchor (RFC 3161 or co-signer timestamp) |
| 11 | Source restart and counter reset | Witness's own sequence is global and continuous across restarts (the store keeps the last sequence). Source-side counters don't exist. A witness re-init starts a new epoch with no signed link. | UNDETECTABLE (source-side gaps) / PARTIALLY DETECTED (witness re-init recorded as `mirror_leaf_feed_reset`) | `internal/store/store.go:140`; 3.2.2 FAIL | — | Hauge's #148 restart case | Signed epoch-link records; per-source epochs |
| 12 | Partial write or power failure | One write per record; fsync before the head. On open, a true crash tail (a partial frame and/or exactly one uncommitted record) is moved to a quarantine file, never signed, WARN `log_crash_tail_recovered`. Anything more is tampering. | DETECTED (and recovered) | `TestTornWriteIsRecoveredAndLaterRecordsSurvive`, `TestTwoExtraRecordsAreStillTampering`, `TestUncommittedRecordIsQuarantinedNotSigned`; `c10eb40` | — | A log already left behind its head by a pre-v3.4.0 power cut still won't open (no recovery path) | Owner-approved recovery tool |
| 13 | Replay and duplicate records | **Log:** a record replayed after the head is quarantined as a crash tail (WARN) and never committed. This is the C07 `replay` sub-case, which fails as "opened cleanly" because it is quarantined, not rejected. A duplicate inside the committed range breaks the root. **Tokens:** replay refused. | DETECTED (log, as crash-tail WARN) / PREVENTED (tokens) | C07 `ModifyInsertReorderDelete…/replay`; `TokenReplayed` | the WARN is monitored | The WARN looks like a benign crash | Raise to CRITICAL when the quarantined record duplicates a committed one |
| 14 | Rewritten and re-signed history | Detected by the pinned `audit` (mirror prefix root), by `verify-leaves` holders, and by the gate's evidence view (each head must extend the last). Not detected by a fresh local `verify` with the host key. | PARTIALLY DETECTED | `AuditCatchesRewriteThenAppend` PASS; `LocalVerifierRejectsReSignedRewrite` FAIL | an earlier root is held somewhere off-host | New verifiers with no history | Consistency proofs plus independent anchors |
| 15 | Conflicting signed checkpoints | Two validly signed heads at the same size with different roots are proof of equivocation, but nothing collects heads from different viewers. Within one puller, the audit rejects a same-size different root. | PARTIALLY DETECTED (single viewer) / UNDETECTABLE (split view) | `MirrorCatchesSameSizeRewrite` PASS; 7.3.3 FAIL | — | Upstream attack A5 | Gossip or witness quorum |
| 16 | Events omitted before ingestion | No origin sequence. Liveness catches a silenced source, not a single dropped event. | UNDETECTABLE | `Probe_SingleSuppressedEventIsDetectable` FAIL | — | Selective omission | Origin sequencing (SD-07); gateway emits its own sequence |
| 17 | Unauthorized action outside the enforcement boundary | Executes. May leave host traces (new process, changed file) that drift records. Network actions via Pipelock are recorded; direct egress is not. | UNDETECTABLE / PARTIALLY DETECTED | 7.1.1 FAIL | — | Primary gap for any Tier 3 claim about actions | Gateway (T3-5) plus coverage metric (10.3.6) |

## 3. The seven properties, kept apart

Each property is a separate claim; none implies another.

| # | Property | Witness today | What establishes it | What it does NOT establish |
|---|---|---|---|---|
| 1 | A record exists | Yes, for a verifier with an inclusion proof and a trusted root | `internal/merkle/proof.go:26`; `witness prove` | that the record is true, complete, or that anything else exists |
| 2 | A record has not changed | Yes, against a signed head with a pinned key | head signature plus root recompute; C07 integrity tests | that the head is the only head (see 3, 7) |
| 3 | Append-only history | Only for holders of earlier leaves or heads (`verify-leaves`, pinned audit); no consistency proofs | leaf feed (`07a4e23`), audit prefix check (`830e21f`) | anything for a verifier that holds nothing earlier |
| 4 | Source completeness within an observable boundary | No. Liveness only; global sequence; no origin sequence | `SilencedPeriodicSourceIsFlagged` | that no single event was dropped (#148) |
| 5 | An action was authorized | Only for gate-mediated classes: a signed decision record plus a signed token bound to the action, with approvals | `gate_decision`, `gate_request`, `proto.Token` | that the authorization policy was right (#146), or that un-gated actions were authorized |
| 6 | A required control was enforced | Only where the relying party enforces tokens (simulation) | `gateenforce.Check`; acceptance tests | enforcement for any path not through a relying party (7.1.1) |
| 7 | Independent parties can verify | Partly. Public key plus operator-produced export or leaf feed; no independent anchors or co-signers; no recorded external run | `verify-export`, `verify-leaves`; 8.1.5 PARTIAL | freedom from operator cooperation (records are encrypted; the mirror is operator-run) |

**Key point for external material:** today Witness can support claims of type 1 and 2, type 3 conditionally, and types 5 and 6 only within gate scope. It must not be described as establishing 4, or 7 without qualification.
