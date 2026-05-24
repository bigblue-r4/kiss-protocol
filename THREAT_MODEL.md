# THREAT_MODEL.md

> Phase 0 deliverable. Fill in before writing any V2 code. Every guarantee claimed elsewhere in the project should map back to a row in this document.

## Scope

What Witness is, in one paragraph. What it is not.

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

- **Signer pubkey allowlist** — a small file shipped alongside the binary, listing the public keys whose signatures the daemon will accept on the soul file and on peer messages. The integrity of this file is the bootstrap trust root. Document where it lives, who may modify it, and how.
- **Reproducible-build attestation** — operators verify the binary they run matches a published artifact hash signed by the release key. Document the verification command.

## Operational assumptions

- Operator can replace a lost or compromised hardware token via the documented rotation flow.
- Operator runs at least one peer or one transparency mirror they control or trust independently. (Standalone is supported, but with a documented reduction in tamper-evidence.)
- Host clock is monotonic forward. Witness does not depend on wall-clock accuracy but does depend on counters not regressing.

## Open questions

> Things this document cannot yet answer. Resolve before Phase 1 sign-off.

1. 
2. 
3. 
