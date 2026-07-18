# SGAIL Labs Harborlight Firewall

Tamper-evident machine-state logging for AI agent environments. Witness takes a cryptographic snapshot of your machine **before** any AI agent is installed, then continuously logs drift, network traffic, and anomalies to an append-only Merkle log that cannot be silently rewritten.

**v3 ships as two binaries with a hard process boundary:**

| Binary | Role |
|---|---|
| `witness` (kiss-core) | Incorruptible local observer — Merkle log, drift detection, soul verification, mirror push. No network listeners. |
| `enforcer` (kiss-enforcer) | Distributed enforcement layer — gossip mesh, cross-node death alerts, loyalty policy evaluation. Reads the core log read-only; cannot write to it. |

A compromised enforcer cannot falsify the core witness record.

[![CI](https://github.com/bigblue-r4/kiss-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/bigblue-r4/kiss-protocol/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bigblue-r4/kiss-protocol)](https://github.com/bigblue-r4/kiss-protocol/releases)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

See [CHANGELOG.md](CHANGELOG.md) for full version history.

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Status view](#status-view)
- [Gossip mesh](#gossip-mesh)
- [Transparency mirror](#transparency-mirror)
- [Soul file](#soul-file)
- [What is here](#what-is-here)
- [Build from source](#build-from-source)
- [Verifying a release](#verifying-a-release)
- [Reproducible builds](#reproducible-builds)
- [Security](#security)
- [License](#license)

---

## Quick start

```bash
# 1. Clone and install — run BEFORE installing any AI agent
git clone https://github.com/bigblue-r4/kiss-protocol.git
cd kiss-protocol
sudo bash install.sh

# 2. Install your AI agents (Claude Code, Cursor, etc.)

# 3. Start the witness daemon (core)
witness start

# 4. Start the enforcer (peer mesh + enforcement) — optional but recommended
enforcer start
```

That's it. Witness is monitoring. The enforcer connects peers and handles cross-node alerts.

---

## How the two binaries relate

```
kiss-core (witness)
  └─ writes: ~/.witness/primary/witness.log   (encrypted, append-only)
             ~/.witness/primary/tree-head.json (signed Merkle head)

kiss-enforcer (enforcer)                       ← reads log, never writes
  └─ enforcer.TailReader polls log every 5 s
  └─ gossip mesh (UDP 9273) — signed heartbeats, liveness tracking
  └─ death broadcast on peer silence / core DEATH event
  └─ loyalty policy evaluator (future: pluggable rules)
```

The machine-derived AES-256 key is derived independently by both binaries from
the machine ID — no IPC required. See [`docs/enforcer-arch.md`](docs/enforcer-arch.md)
for the full isolation contract and recommended OS user separation.

---

## Works with any AI agent

Witness is LLM-agnostic. It routes agent traffic through [Pipelock](https://github.com/luckyPipewrench/pipelock) — a transparent auditing proxy — and logs every request as a signed Merkle leaf. Any agent that honours standard HTTP proxy environment variables works out of the box.

When `witness start` runs it prints the proxy address:

```
[witness] Pipelock proxy running → http://127.0.0.1:8889
[witness] Set HTTPS_PROXY=http://127.0.0.1:8889 HTTP_PROXY=http://127.0.0.1:8889
```

Tested with: Claude Code, Cursor, Aider, and any tool using standard HTTP clients.

### Enforce at the OS level

Setting env vars is opt-in — an evasive agent can ignore them. For kernel-level enforcement that cannot be bypassed, redirect TCP egress by UID using iptables, nftables, eBPF TC, or macOS pf. See [`docs/ebpf-proxy.md`](docs/ebpf-proxy.md) for copy-paste rules.

---

## Runs standalone — no server required

Witness works completely offline. No account, no cloud endpoint, no registration. The Merkle log and signed tree heads stay on your machine. Peers and a transparency mirror are optional add-ons for stronger tamper-evidence.

---

## Commands

### witness (kiss-core)

```
witness init                    Take genesis snapshot, initialize Merkle log
witness start [--dev]           Start the continuous witness daemon
witness status                  Show current status
witness verify                  Walk Merkle log and verify integrity
witness prove <index>           Emit inclusion proof for leaf at index
witness migrate [src-dir]       Import v1 log into the v2 Merkle log (one-shot)
witness soul sign [--dev]       Sign the soul file with the operator key
witness soul verify             Verify the soul file signature
witness audit [--max-lag N]     Compare local log against the transparency mirror
witness version                 Print version
```

### enforcer (kiss-enforcer)

```
enforcer start [--dev]          Start the enforcer daemon (reads core log, runs gossip)
enforcer peer add <l> <a> <k>  Add a gossip peer (label, UDP addr, hex pubkey)
enforcer peer remove <label>   Remove a gossip peer
enforcer peer list             List configured peers
enforcer status                Print peer configuration
enforcer version               Print version
```

---

## Status view

```
─────────────────────────────────────────
Machine ID    : <id>
Genesis       : CLEAN
Log entries   : 142
Drift events  : 0
Tree size     : 142
Tree root     : a3f9c1…
Prev root     : 8d2e7b…
Integrity     : OK
Log dir       : ~/.witness/primary
Last event    : [INFO] pipelock / connect (2026-06-14T07:41:02Z)
─────────────────────────────────────────
```

---

## Gossip mesh

The enforcer runs a signed UDP heartbeat protocol on port 9273. Peers that miss `N` consecutive heartbeats are marked `SILENT`; after `M` misses they are `PRESUMED_COMPROMISED` and surviving peers fire signed death broadcasts. No central coordinator, no libp2p — stdlib UDP with an allowlist trust model (SSH known-hosts semantics).

```bash
# Exchange pubkeys out of band, then:
enforcer peer add peer-b 10.0.0.2:9273 <hex-pubkey>
```

---

## Transparency mirror

Push a signed copy of the Merkle tree head to an external store after every drift tick. Add to `~/.witness/config.json`:

```json
{ "mirror_url": "https://mirror.example.com/witness" }
```

Supported backends: `file://`, `https://`, `http://`, `s3://` (build with `-tags s3`).

```bash
witness audit              # exits 0: agree; 1: tamper; 2: unreachable or lagging
witness audit --max-lag 50 # tolerate up to 50 leaves of S3 propagation lag
```

Mirror writes are atomic (write-to-temp + rename on file; ETag conditional PUT on HTTP; retry with backoff on all backends). The tree head carries a `prev_root` field for chain continuity verification. See [`docs/mirror-setup.md`](docs/mirror-setup.md).

---

## Soul file

The soul file (`~/.witness/soul.toml`) is the operator-signed identity policy for this deployment. Witness refuses to start if the soul file fails signature verification — a tampered soul halts the daemon before it touches the log.

```bash
witness soul sign    # signs with dev key (--dev) or attached YubiKey PIV token
witness soul verify  # verifies detached .sig against the trust allowlist
```

See [`docs/keys.md`](docs/keys.md) for key rotation and recovery.

---

## What is here

```
cmd/witness/               kiss-core daemon and CLI
cmd/enforcer/              kiss-enforcer daemon and CLI
cmd/witness-pd/            Law enforcement evidence edition (chain-of-custody)
internal/enforcer/         TailReader — async log reader interface for enforcer
internal/merkle/           RFC 6962 Merkle tree (BLAKE3) + inclusion proofs
internal/store/            Append-only encrypted Merkle log + signed tree heads
internal/gossip/           UDP heartbeat mesh, anti-replay, death broadcasting
internal/mirror/           Transparency mirror backends (file, HTTP, S3)
internal/signer/           ed25519 signer interface, dev key, PIV (YubiKey)
internal/soul/             Soul file TOML parse, hash check, signature verify
internal/pipelock_bridge/  Pipelock seam → Merkle leaf forwarding
internal/genesis/          Pre-agent machine-state snapshot
internal/drift/            Continuous file + process drift detection
internal/anomaly/          Storage and network anomaly detection
packaging/                 systemd unit, launchd plist, seccomp profile
docs/                      enforcer-arch, ebpf-proxy, keys, mirror-setup,
                           threat-model, audit-prep, pipelock-integration
```

---

## Build from source

Requires Go 1.22 or newer.

```bash
go test ./...
go build ./cmd/witness ./cmd/enforcer

# With S3 mirror support:
go build -tags s3 ./cmd/witness ./cmd/enforcer

# With YubiKey PIV signing support:
go build -tags piv ./cmd/witness ./cmd/enforcer
```

---

## Verifying a release

All release artifacts are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) using GitHub Actions OIDC (keyless — no long-lived signing keys):

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

---

## Reproducible builds

Both binaries are built with `-trimpath -buildvcs=false`. Same source + same toolchain = identical bytes.

```bash
make verify-reproducible   # builds twice, compares SHA-256 hashes
nix build .#witness        # fully hermetic build via Nix flake
```

---

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure policy and release verification instructions.

See [`docs/threat-model.md`](docs/threat-model.md) for attacker capabilities, guarantees by mechanism, and explicit non-goals.

---

## License

MIT. See `LICENSE`.
