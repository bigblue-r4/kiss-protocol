# Threat Model

> This document is the canonical threat model for SGAIL Labs Harborlight Firewall (Witness).
> The authoritative source is `THREAT_MODEL.md` in the repo root; this copy is placed here
> for doc-site navigation.

## Scope

Witness is a tamper-evident machine-state daemon that runs continuously on an AI-agent host.
It takes a cryptographic snapshot of the machine before any agent is installed (genesis), then
continuously logs drift, pipelock audit events, and anomalies to an append-only Merkle log. If
the daemon is killed unexpectedly it broadcasts its log to redundant locations and — optionally —
to a remote server, so that any post-incident investigation has a tamper-evident record of what
happened, to whom, and when.

Witness is **not** a firewall, not a runtime sandbox, not an IDS/IPS, and not a confidentiality
tool. It does not prevent agents from acting; it creates a verifiable record of what happened. It
does not protect payload contents — operators who need secrecy must encrypt payloads before
submission. It does not guarantee availability; it witnesses, it does not defend.

## Assets Being Protected

In rough priority order:

1. **Log integrity.** The append-only Merkle log is the system of record for events.
   Past entries must not be silently rewritable.
2. **Death-broadcast authenticity.** A signed assertion that the daemon is alive, or has cleanly
   stopped, must not be forgeable by an attacker who has displaced the daemon.
3. **Policy integrity (the Soul).** The daemon must not run under a policy the operator did not sign.
4. **Operator key material.** Hardware-held signing keys must not leave the token.

## Attacker Capabilities

| ID  | Capability | In scope? |
|-----|-----------|-----------|
| A1  | Local root on the host | Yes |
| A2  | Read any file on disk, including the running binary | Yes |
| A3  | Kill any user-space process, including the daemon | Yes |
| A4  | Network MITM between this node and peers / mirror | Yes |
| A5  | Supply-chain insertion at install time | Yes — addressed by reproducible builds + signed releases |
| A6  | Kernel rootkit / ring-0 code execution | Partial — see non-goals |
| A7  | Physical access to extract hardware-token key material | **Out of scope** |
| A8  | Compromise of the operator's signing token | **Out of scope** — recoverable only via the documented rotation flow |
| A9  | Hostile co-tenant on the same host (no root) | Yes |
| A10 | Compromise of every peer in the gossip mesh simultaneously | **Out of scope** — peering raises the bar, it does not provide unconditional safety |

## Guarantees

| Attacker can... | Witness guarantees... | Mechanism |
|---|---|---|
| A1, A2 (local root, read any file) | Past log entries cannot be silently altered | Merkle log + signed tree heads + external mirror (Phase 5) |
| A3 (kill the daemon) | Peers detect absence within N intervals; no forged "alive" signature is possible | Hardware-bound heartbeat signature + gossip (Phases 2, 4) |
| A4 (network MITM) | Gossip and mirror messages cannot be forged or replayed undetected | Signed messages with monotonic counters |
| A5 (supply chain) | A modified release artifact can be detected by any user | Reproducible builds + cosign-signed release tags (Phase 7) |
| A6 (kernel rootkit) | **Best-effort only.** A full ring-0 attacker can forge in-memory state; only the cryptographic record on durable storage + external mirror remains tamper-evident | Documented honestly; not claimed otherwise |
| A9 (hostile co-tenant, no root) | Cannot read log, signer key material, or soul file | Filesystem permissions + dedicated user + capability drops (Phase 3) |

## Non-Goals

- Physical extraction of hardware-token key material.
- Attacker who has stolen or coerced use of the operator's signing token.
- CPU side-channel attacks (Spectre, Meltdown, etc.).
- Quorum compromise of the gossip mesh.
- Denial of service against the host (Witness is a witness, not an availability guarantee).
- Confidentiality of log payload contents. Witness proves integrity, not secrecy.

## Trust Roots

- **Signer pubkey allowlist** — `~/.witness/trust/signers.txt`
  (one ed25519 pubkey per line, with operator-assigned label). Created by the installer; placed
  by a human before `witness init`. Never network-fetched, never auto-updated. Owned by the
  `witness` system user, mode 0400. A compromised allowlist means a compromised daemon — this is
  the bootstrap trust root, and its integrity cannot be verified from within the system it
  protects. Operators must verify it out-of-band.

- **Reproducible-build attestation** — operators verify the binary they run matches a published
  artifact hash signed by the release key:
  ```
  cosign verify-blob \
    --certificate-identity-regexp \
      "https://github.com/bigblue-r4/kiss-protocol/.github/workflows/release.yml" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --signature witness_linux_amd64.sig \
    --certificate witness_linux_amd64.pem \
    witness_linux_amd64
  ```

## Operational Assumptions

- Operator can replace a lost or compromised hardware token via the documented rotation flow
  (see `docs/keys.md`).
- Operator runs at least one peer or one transparency mirror they control or trust independently.
  Standalone is supported but with a documented reduction in tamper-evidence.
- Host clock is monotonic forward. Witness does not depend on wall-clock accuracy but does
  depend on counters not regressing.
