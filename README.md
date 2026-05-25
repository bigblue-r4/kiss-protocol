# SGAIL Labs Harborlight Firewall

Tamper-evident machine-state logging for AI agent environments. Witness takes a cryptographic snapshot of your machine **before** any AI agent is installed, then continuously logs drift, network traffic, and anomalies to an append-only Merkle log. If the process is killed or detects tampering, it fires a signed death broadcast to every peer in the gossip mesh.

## Quick start

```bash
# 1. Clone and install (run BEFORE installing any AI agent)
git clone https://github.com/bigblue-r4/kiss-protocol.git
cd kiss-protocol
sudo bash install.sh

# 2. Install your AI agents (Claude Code, Cursor, etc.)

# 3. Start the witness daemon
witness start
```

That's it. Witness is now monitoring.

## Works with any AI agent

Witness is **LLM-agnostic**. It routes agent traffic through [Pipelock](https://github.com/luckyPipewrench/pipelock) — a transparent auditing proxy — and logs every request into the tamper-evident Merkle log. Any agent that respects standard HTTP proxy environment variables is supported.

When `witness start` runs it prints the proxy address:

```bash
export HTTPS_PROXY=http://127.0.0.1:8889
export HTTP_PROXY=http://127.0.0.1:8889
```

Tested with: Claude Code, Cursor, Aider, and any tool using standard Go/Python/Node HTTP clients.

## Runs standalone — no server required

Witness works completely offline. No account, no cloud endpoint, nothing required. The Merkle log and signed tree heads stay on your machine. Optionally connect peers or a transparency mirror for stronger tamper-evidence.

## Commands

```
witness init              Take genesis snapshot and initialize the Merkle log
witness start             Start the continuous witness daemon (blocks until signaled)
witness status            Print current status
witness verify            Walk the Merkle log and verify integrity
witness prove <index>     Emit an inclusion proof for the leaf at index
witness audit             Compare local log against the configured transparency mirror
witness peer add          Add a gossip peer (label, addr, pubkey)
witness peer remove       Remove a gossip peer
witness peer list         List configured gossip peers
witness soul sign         Sign the soul file with the operator key
witness soul verify       Verify the soul file signature
witness soul trust add    Add a public key to the signer allowlist
witness migrate           Import a v1 log into the v2 Merkle log (one-shot)
witness enable-sync       Enable opt-in SGAIL remote sync (deprecated — use gossip)
witness version           Print version
```

## Status view

```
─────────────────────────────────────────────────
Harborlight Firewall   v2.0.0
Machine ID    : <id>
Genesis       : CLEAN
Log entries   : 142
Merkle root   : a3f9c1…
Tree size     : 142
Drift events  : 0
Pipelock      : running → http://127.0.0.1:8889
Gossip peers  : 2 alive / 0 silent / 0 presumed-compromised
Mirror        : https://mirror.example.com/witness
Last event    : [INFO] pipelock / connect (2026-05-24T07:41:02Z)
─────────────────────────────────────────────────
```

## Gossip mesh

Witness nodes discover peer compromise via a signed UDP heartbeat protocol. Peers that miss `N` consecutive heartbeats are flagged `SILENT`; after `M` misses they are `PRESUMED_COMPROMISED` and the surviving nodes fire death broadcasts. No central coordinator, no libp2p — stdlib UDP with an allowlist trust model.

```bash
# Exchange pubkeys out-of-band, then:
witness peer add --label peer-b --addr 10.0.0.2:9273 --pubkey <hex-pubkey>
```

See [`docs/migrating-from-sgail-sync.md`](docs/migrating-from-sgail-sync.md) if you were using SGAIL sync.

## Transparency mirror

Push a signed copy of the tree-head to an external store after every drift tick:

```json
{ "mirror_url": "https://mirror.example.com/witness" }
```

Supported backends: `file://`, `https://`, `http://`, `s3://` (build with `-tags s3`).

```bash
witness audit    # compare local log against mirror; exits 1 on disagreement
```

See [`docs/mirror-setup.md`](docs/mirror-setup.md) for AWS, Cloudflare R2, MinIO, and HTTP setup.

## Soul file

The soul file (`~/.witness/soul.toml`) is the operator-signed policy for this deployment. Witness refuses to start if the soul file fails signature verification. Sign it with your ed25519 key (or PIV/YubiKey with `-tags piv`):

```bash
witness soul sign    # signs with ~/.witness/dev-signing.key or attached PIV token
witness soul verify  # verifies detached signature against the trust allowlist
```

See [`docs/keys.md`](docs/keys.md) for key rotation and recovery.

## What is here

```
cmd/witness/          Main daemon and CLI
cmd/witness-pd/       Law enforcement evidence chain-of-custody edition
internal/merkle/      RFC 6962 Merkle tree (BLAKE3) + inclusion proofs
internal/store/       Append-only encrypted Merkle log + signed tree heads
internal/gossip/      UDP heartbeat mesh, anti-replay, death broadcasting
internal/mirror/      Transparency mirror backends (file, HTTP, S3)
internal/signer/      ed25519 signer interface, dev signer, PIV stub
internal/soul/        Soul file TOML parse, hash check, signature verification
internal/pipelock_bridge/  Pipelock subprocess seam → Merkle leaf forwarding
internal/genesis/     Pre-agent machine-state snapshot
internal/drift/       Continuous drift detection
internal/anomaly/     Storage and network anomaly detection
packaging/            systemd unit, launchd plist, seccomp OCI profile
docs/                 keys, mirror setup, threat model, audit prep, migration
```

## Build from source

Requirements: Go 1.22 or newer

```bash
go test ./...
go build ./...

# With S3 mirror support:
go build -tags s3 ./cmd/witness/
```

## Verifying a release

All release artifacts (v2.x and later) are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) using GitHub Actions OIDC (keyless — no long-lived signing keys):

```bash
# Replace linux_amd64 with your platform: linux_arm64, darwin_amd64, darwin_arm64

cosign verify-blob \
  --certificate-identity-regexp \
    "https://github.com/bigblue-r4/kiss-protocol/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature witness_linux_amd64.sig \
  --certificate witness_linux_amd64.pem \
  witness_linux_amd64

sha256sum -c witness_linux_amd64.sha256
```

## Reproducible builds

The witness binary is built with `-trimpath -buildvcs=false`. Same source + same toolchain = identical bytes.

```bash
make verify-reproducible   # builds twice, compares SHA-256 hashes
nix build .#witness        # fully hermetic build via Nix flake
```

## SGAIL remote sync (deprecated)

`witness enable-sync` is deprecated in v2.0 and will be removed in v2.1. The gossip mesh replaces it — see [`docs/migrating-from-sgail-sync.md`](docs/migrating-from-sgail-sync.md).

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure policy and release verification instructions.

See [`docs/threat-model.md`](docs/threat-model.md) for attacker capabilities, guarantees by mechanism, and explicit non-goals.

## License

MIT. See `LICENSE`.
