# THREAT_MODEL.md

> Phase 0 deliverable. Fill in before writing any V2 code. Every guarantee claimed elsewhere in the project should map back to a row in this document.

## Scope

Witness is a tamper-evident machine-state daemon that runs continuously on an AI-agent host. It takes a cryptographic snapshot of the machine before any agent is installed (genesis), then continuously logs drift, pipelock audit events, and anomalies to an append-only, hash-chained encrypted log. If the daemon is killed unexpectedly it broadcasts its log to redundant locations and — optionally — to a remote server, so that any post-incident investigation has a tamper-evident record of what happened, to whom, and when.

Witness is not a firewall, not a runtime sandbox, not an IDS/IPS, and not a confidentiality tool. It does not prevent agents from acting; it creates a verifiable record of what happened. It does not protect payload contents — operators who need secrecy must encrypt payloads before submission. It does not guarantee availability; it witnesses, it does not defend.

## Assets being protected

In rough priority order:

1. **Log integrity.** The append-only Merkle log is the system of record for events. Past entries must not be silently rewritable.
2. **Death-broadcast authenticity.** A signed assertion that the daemon is alive, or has cleanly stopped, must not be forgeable by an attacker who has displaced the daemon.
3. **Policy integrity (the Soul).** The daemon must not run under a policy the operator did not sign.
4. **Operator key material.** Hardware-held signing keys must not leave the token.

## Attacker capabilities (what we assume the attacker CAN do)

| ID | Capability | In scope? |
|---|---|---|
| A1 | Local root on the host | Yes |
| A2 | Read any file on disk, including the running binary | Yes |
| A3 | Kill any user-space process, including the daemon | Yes |
| A4 | Network MITM between this node and peers / mirror | Yes |
| A5 | Supply-chain insertion at install time (malicious package) | Yes — addressed by reproducible builds + signed releases |
| A6 | Kernel rootkit / ring-0 code execution | Partial — see non-goals |
| A7 | Physical access to extract a hardware token's key material | **Out of scope** |
| A8 | Compromise of the operator's signing token | **Out of scope** — recoverable only via the documented rotation flow |
| A9 | Hostile co-tenant on the same host (no root) | Yes |
| A10 | Compromise of every peer in the gossip mesh simultaneously | **Out of scope** — peering raises the bar, it does not provide unconditional safety |

## Guarantees

For each attacker capability above, state what Witness guarantees and by what mechanism.

| Attacker can... | Witness guarantees... | Mechanism |
|---|---|---|
| A1, A2 (local root, read any file) | Past log entries cannot be silently altered | Merkle log + signed tree heads + external mirror (Phase 5) |
| A3 (kill the daemon) | Peers detect absence within N intervals; no forged "alive" signature is possible | Hardware-bound heartbeat signature + gossip (Phases 2, 4) |
| A4 (network MITM) | Gossip and mirror messages cannot be forged or replayed undetected | Signed messages with monotonic counters |
| A5 (supply chain) | A modified release artifact can be detected by any user | Reproducible builds + signed release tags (Phase 7) |
| A6 (kernel rootkit) | **Best-effort only.** A full ring-0 attacker can forge in-memory state; only the cryptographic record on durable storage + external mirror remains tamper-evident | Documented honestly; not claimed otherwise |
| A9 (hostile co-tenant, no root) | Cannot read log, signer key material, or soul file | Filesystem permissions + dedicated user + capability drops (Phase 3) |

## Non-goals (explicitly NOT defended against)

- Physical extraction of hardware-token key material.
- Attacker who has stolen or coerced use of the operator's signing token.
- CPU side-channel attacks (Spectre, Meltdown, etc.).
- Quorum compromise of the gossip mesh.
- Denial of service against the host (Witness is a witness, not an availability guarantee).
- Confidentiality of log payload contents. Witness proves integrity, not secrecy. Operators who need secrecy must encrypt payloads before submission.

## Trust roots

- **Signer pubkey allowlist** — `~/.witness/trust/signers.txt` (one ed25519 pubkey per line, with operator-assigned label). Created by the installer; placed by a human before `witness init`. Never network-fetched, never auto-updated. Owned by the `witness` system user, mode 0400. A compromised allowlist means a compromised daemon — this is the bootstrap trust root, and its integrity cannot be verified from within the system it protects. Operators must verify it out-of-band (e.g., compare checksum against a trusted copy at setup time).
- **Reproducible-build attestation** — operators verify the binary they run matches a published artifact hash signed by the release key. Verification command (Phase 7): `cosign verify-blob --key witness-release.pub --signature witness_linux_amd64.sig witness_linux_amd64`

## Operational assumptions

- Operator can replace a lost or compromised hardware token via the documented rotation flow.
- Operator runs at least one peer or one transparency mirror they control or trust independently. (Standalone is supported, but with a documented reduction in tamper-evidence.)
- Host clock is monotonic forward. Witness does not depend on wall-clock accuracy but does depend on counters not regressing.

## Open questions

> Things this document cannot yet answer. Resolve before Phase 1 sign-off.

1. **Gossip trust bootstrap (Phase 4 pre-req):** How does a node verify a peer's identity on first contact? Options: (a) pre-shared pubkey exchange out-of-band, added to allowlist before `witness peer add`; (b) TOFU with a "first-contact" log entry and manual confirmation; (c) require allowlist entry before any peering is accepted. Must be decided before Phase 4 to avoid locking in a weaker model.
2. **seccomp profile completeness (Phase 3 pre-req):** The generated seccomp profile is derived from observed syscalls during integration tests. The death-broadcast path (parallel file writes, SGAIL HTTP under short deadline) and the watchdog subprocess spawn exercise syscalls that may not appear in happy-path tests. The profile must cover error and shutdown paths before defaulting on — otherwise a kill signal during death-broadcast will cause the daemon to crash instead of completing the broadcast.
3. **v1 import fidelity (Phase 1 decision):** The existing `internal/store` log is a SHA-256 linear hash chain, not a Merkle tree. v1 entries can be imported as Merkle leaves, but the resulting Merkle root will not match any hash stored in the v1 log — there is no cryptographic continuity, only documentary continuity. The import boundary marker leaf must explicitly state this. Decide whether to document the v1 chain as a separate audit trail or treat the import as a clean-break migration.

## Gate (kiss-gate): prevention for high-consequence actions

The witness above is unchanged: it records and does not prevent. `gate` is a separate binary, user and key that
issues signed tokens for a short list of high-consequence actions, which a protected service checks with
`pkg/gateenforce` before acting. See `docs/gate-arch.md`. The rows below are the gate's own claims.

| Attacker can... | Gate guarantees... | Mechanism |
|---|---|---|
| A1 on a developer endpoint or an internal service (not the gate host) | No high-tier action executes without a root that host cannot produce | Token required at the enforcement point; roots are operator signatures over `action_hash` or the signed policy envelope, never feed data |
| A1 on the gate/signer host | **Not prevented.** Root there can forge feeds and use a software gate key. Detection only: witness log + mirror; a PIV gate key keeps the key off disk | Documented honestly; the gate belongs on a host developers cannot reach |
| Forge or flood feed events (any host whose feed files it can write) | Can only tighten (deny, escalate, trip), never allow or reset | Feed-derived signals are tightening-only by construction |
| Abuse a compromised service inside an automated envelope | Released value ≤ the policy's window budgets; the class then freezes until a quorum reset | Atomic budget reservation + breaker, no auto-reset |
| Replay a token, or reuse it for another amount or destination | Refused | `token_id` replay cache; `action_hash` binds the exact request |
| Rewrite the witness log (re-signed with any key) | Detected before the next token; Global trip | Pinned witness keys + append-only check against every head the gate has seen |
| Freeze or kill the witness to blind the gate | High-tier requests denied | Head age on the gate's own clock (`head_max_age`); DEATH/downtime triggers |
| Serve a stale Epoch to an enforcement point | High tier refused | Signed Epoch with `max_age` |
| A8 for **one** operator token | Cannot reset a breaker; can approve a manual-class action unless the class requires more approvals | M-of-N reset quorum; per-class `approvals_required` (open question, `docs/gate-arch.md` section 8) |
| Trip the breaker on purpose (DoS) | **Not prevented.** A trip is an availability lever; scopes are kept as narrow as the trigger | Documented in `docs/gate-ops.md`; Global trips only on chain-integrity or self-check failures |
| Bypass the enforcement point (a service path that never calls `gateenforce`) | **Out of scope.** The gate protects only what checks its tokens | Deployment requirement |

## Published verifier signer identity

`witness verify`, `prove`, and `audit` accept repeatable `--pubkey HEX` and
`--pubkey-file PATH` flags. The file uses the soul allowlist's `<label> <hex-key>`
format. Non-empty pins require a signed local tree head from an accepted
Ed25519 key. Obtain and protect pins out of band: a key taken from an
attacker-writable head is not a trust root. Without pins the commands retain
legacy consistency checks and warn that signer identity is not pinned.
Pins alone do not establish freshness or prevent replay of an older valid log;
an independent mirror/checkpoint is still needed. `audit` compares the mirror
with the pinned local log; these flags do not authenticate the remote head.
