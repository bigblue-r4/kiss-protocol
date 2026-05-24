# V2_PLAN.md — Implementation map

> Phase-0 deliverable. Inventory pre-filled from the v1.0.0 repo state; verify each row by viewing the file before treating it as gospel.

## Repo inventory

> Verified against v1.0.0 source. Corrections from the original skeleton are marked *.

| Component | Language | Path | Notes |
|---|---|---|---|
| Witness daemon + CLI | Go | `cmd/witness/` | Commands: `init`, `start`, `status`, `enable-sync`, `watchdog`, `version` |
| PD edition binary * | Go | `cmd/witness-pd/` | Separate binary; evidence chain-of-custody for law enforcement; embeds `static/index.html` — **HTML removed in Phase 6** |
| Genesis snapshot | Go | `internal/genesis/` | Pre-agent machine-state snapshot; stays |
| Storage / log writer * | Go | `internal/store/` | SHA-256 linear hash chain (NOT Merkle); encrypted NDJSON — **rewritten as Merkle log in Phase 1** |
| Drift detection | Go | `internal/drift/` | Stays; emits leaves into new log |
| Backup (3-tier) * | Go | `internal/backup/` | secondary (`/var/lib/.watcher_state`) + HMAC-derived tertiary — **mostly deleted in Phase 1** |
| Anomaly detection | Go | `internal/anomaly/` | Stays |
| Death broadcaster * | Go | `internal/death/` | Parallel broadcast to all tiers + SGAIL on SIGKILL/SIGTERM; updated in Phase 1 for Merkle log |
| Encryption * | Go | `internal/encrypt/` | AES-256-GCM with machine-derived key; stays |
| Machine ID * | Go | `internal/machid/` | Stable host identifier; stays |
| Config * | Go | `internal/config/` | `~/.witness/config.json`; stays |
| Soul loader | Go | `internal/soul/` | TOML parse + SHA-256 self-hash check; **crypto signature check added in Phase 2** |
| Pipelock runner + tailer * | Go | `internal/pipelock/` | Spawns `pipelock` subprocess, tails NDJSON audit log — **replaced by library call in Phase 6** |
| SGAIL sync client * | Go | `internal/sgail/` | Opt-in remote push (`enable-sync`); **deprecated in Phase 4, removed after one release** |
| PD evidence store * | Go | `internal/pd/evidence/` | Chain-of-custody log for PD edition; stays |
| PD export * | Go | `internal/pd/export/` | NDJSON bundle + Ed25519 signing; stays |
| PD roles * | Go | `internal/pd/roles/` | Role permission table; stays |
| HTML dashboard * | HTML | `cmd/witness-pd/static/index.html` | Single file, embedded via `//go:embed` in `cmd/witness-pd/main.go` only — **removed in Phase 6** |
| systemd / launchd units | Shell / plist | `install.sh`, `harborlight-install.sh`, `harborlight-install.command` | **Hardened in Phase 3** |
| CI | YAML | `.github/workflows/ci.yml` | **Extended in Phase 7, not replaced** |
| Existing SECURITY.md | Markdown | `SECURITY.md` | **Updated in Phase 7, not created** |
| Pipelock (external) | Go | `github.com/luckyPipewrench/pipelock` | **Vendored as library in Phase 6** |

## Cross-language boundaries

Confirmed all-Go. Current `go.mod` dependencies: `github.com/BurntSushi/toml v1.3.2`, `golang.org/x/crypto v0.19.0`. The only repo-crossing dependency is Pipelock — also Go — which is currently invoked as a subprocess by `internal/pipelock/runner.go`. Phase 6 collapses that seam by vendoring.

## Current encryption model (v1 — for migration context)

Key derivation: AES-256-GCM key derived from machine ID via `internal/encrypt` (machine-local; not hardware-bound).
Log format: encrypted NDJSON records prefixed with a 4-byte big-endian length; each entry carries a `prev_hash` (SHA-256 of previous plaintext entry) for linear chain integrity.
This is a hash chain, not a Merkle tree — there are no inclusion proofs, no signed tree heads, and no external verifiability.

## Phase → file map

### Phase 1 — Merkle log
- Files to add:
  - `internal/merkle/tree.go` — RFC 6962-style tree
  - `internal/merkle/proof.go` — inclusion proof gen + verify
  - `internal/store/log.go` — new append-only Merkle log writer (replaces current hash-chain logic in `internal/store/store.go`)
  - `cmd/witness/verify.go`
  - `cmd/witness/prove.go`
  - `internal/migrate/v1_import.go` — one-shot v1-tier importer (see open question #3 on import fidelity)
- Files to modify:
  - `internal/store/store.go` — replace SHA-256 linear chain with Merkle log; keep encrypted wire format
  - `internal/death/death.go` — broadcast signed tree head alongside log data
  - `cmd/witness/main.go` — `cmdStatus()`: drop "Secondary / Tertiary" lines; `cmdInit()`: drop 3-tier write calls
- Files to remove:
  - `internal/backup/secondary.go`, `internal/backup/tertiary.go` (entire `internal/backup/` package)
- New dependencies:
  - `lukechampine.com/blake3` (BLAKE3 hashing)
  - `github.com/transparency-dev/merkle` *or* a thin in-tree ~200-LOC implementation — see open question #2
- Test files:
  - `internal/merkle/tree_test.go`
  - `internal/merkle/proof_test.go`
  - `internal/store/log_test.go` (tamper, truncate, reorder, inclusion proof, tampered tree head)

### Phase 2 — Hardware signer + soul signing
- Files to add:
  - `internal/signer/signer.go` — interface
  - `internal/signer/dev.go` — software ed25519, `--dev` only
  - `internal/signer/fido.go` — FIDO2 / PIV backend
  - `internal/soul/verify.go` — soul-file signature check on startup
  - `cmd/witness/soul.go` — `sign` / `verify` subcommands
  - `docs/keys.md` — rotation & recovery
  - `~/.witness/trust/signers.txt` — runtime trust allowlist (created by installer)
- Files to modify:
  - `cmd/witness/start.go` — refuse to start on bad soul signature
  - `internal/storage/log.go` — tree heads signed by `signer`
- New dependencies:
  - `github.com/keys-pub/go-libfido2` and/or `github.com/go-piv/piv-go` — pick one as primary
- Test files:
  - `internal/signer/dev_test.go`
  - `internal/signer/fido_test.go` (skip on hardware-less CI)
  - `internal/soul/verify_test.go`

### Phase 3 — Loyalty (capabilities, seccomp, systemd, launchd)
- Files to add:
  - `packaging/systemd/witness.service`
  - `packaging/launchd/ai.sentinelproject.witness.plist`
  - `packaging/seccomp/witness.json` — generated, committed
  - `scripts/regen-seccomp.sh` — observed-syscall regeneration
- Files to modify:
  - `install.sh`, `harborlight-install.sh`, `harborlight-install.command` — create dedicated user, install hardened units
- Test files:
  - `internal/sandbox/sandbox_test.go` — caps dropped as expected

### Phase 4 — Gossip + death detection
- Files to add:
  - `internal/gossip/peer.go`
  - `internal/gossip/heartbeat.go`
  - `internal/gossip/death.go`
  - `cmd/witness/peer.go` — `add` / `remove` / `list`
  - `docs/migrating-from-sgail-sync.md`
- Files to modify:
  - `internal/sgail/sgail.go` — add deprecation notice comment; keep functional for one release
  - `cmd/witness/main.go` `cmdEnableSync()` — print deprecation banner before existing logic
- Files to remove (next release after Phase 4):
  - `internal/sgail/` (entire package)
- New dependencies:
  - `github.com/libp2p/go-libp2p`
  - `github.com/libp2p/go-libp2p-pubsub`
- Test files:
  - `internal/gossip/heartbeat_test.go` — silence → presumed-compromised state machine
- Note: Gossip trust bootstrap model (open question #1 in THREAT_MODEL.md) must be resolved before this phase.

### Phase 5 — Transparency mirror
- Files to add:
  - `internal/mirror/mirror.go` — interface
  - `internal/mirror/static.go` — file / HTTP backend
  - `internal/mirror/s3.go` — S3-compatible backend (optional build tag)
  - `cmd/witness/audit.go` — verify local against mirror
- Test files:
  - `internal/mirror/static_test.go`

### Phase 6 — Surface reduction
- **Pipelock vendor:**
  - Coordinate with Pipelock maintainer to expose stable Go API + tag release
  - Add to `go.mod`: `github.com/luckyPipewrench/pipelock vX.Y.Z`
  - Replace `internal/pipelock/runner.go` (subprocess spawn) and `internal/pipelock/tailer.go` (NDJSON tail) with direct library calls
  - Remove pipelock subprocess setup from `install.sh`
  - New: `internal/pipelock_bridge/bridge.go` — adapter that pipes pipelock events into Merkle log leaves
  - New: `docs/pipelock-integration.md`
- **HTML removal:**
  - Scope is narrower than originally stated: there is exactly **one** HTML file (`cmd/witness-pd/static/index.html`) embedded via a single `//go:embed` directive in `cmd/witness-pd/main.go`. No templates, no JS files, no spread across the repo.
  - Remove: `cmd/witness-pd/static/index.html`
  - Modify: `cmd/witness-pd/main.go` — remove `//go:embed`, `dashboardHTML` var, `runServe()`, all HTTP handler methods, and the `http` import; keep CLI commands only
  - `witness-pd status --json` is the documented replacement for dashboard consumers

### Phase 7 — Credibility & supply chain
- Reproducible builds:
  - `flake.nix` — hermetic build
  - `Makefile` targets `make reproducible-build` and `make verify-reproducible`
  - CI matrix: Linux + macOS, compare artifact hashes
  - Pinned `GOTOOLCHAIN` in `go.mod`
- Signing:
  - `cosign` integration in release workflow
  - Verification command added to `README.md`
- Fuzz:
  - `internal/soul/fuzz_test.go`
  - `internal/storage/fuzz_test.go`
  - `internal/gossip/fuzz_test.go`
  - `internal/mirror/fuzz_test.go`
  - CI: short pass per PR, nightly long pass
- History rewrite:
  - `git filter-repo` script committed to `scripts/rewrite-history.sh`
  - Force-push only after sign-off
- Docs to update / add:
  - Update existing `SECURITY.md`
  - New `docs/audit-prep.md`
  - New `docs/threat-model.md` (copy of `THREAT_MODEL.md`)
  - Update `README.md` with cosign verification + reproducible-build instructions

## Open questions

> Items marked **[OPEN]** need operator input before the phase that depends on them. Items marked **[PROPOSED]** have a suggested answer — confirm or override.

1. **[OPEN] Pipelock maintenance:** is `github.com/luckyPipewrench/pipelock` under the same operator? If yes, Phase 6 coordination is trivial (tag a release, expose a stable Go API, vendor). If not, a formal upstream API contract and stability guarantee is needed before vendoring.
2. **[PROPOSED] Merkle library:** Recommend an in-tree ~200-LOC implementation over `transparency-dev/merkle`. Rationale: minimal third-party surface is a stated project principle; RFC 6962 is a narrow spec; in-tree code is fully auditable without chasing transitive deps. `transparency-dev/merkle` remains an option if the in-tree impl shows correctness issues during fuzzing.
3. **[PROPOSED] FIDO vs PIV as primary:** Recommend **PIV** as primary, FIDO2 as opt-in. PIV gives PKCS#11 semantics, works with `piv-go`, and is the standard interface for code-signing workflows. FIDO2 via `go-libfido2` is simpler API but less ecosystem-compatible for signing tree heads. YubiKey 5 supports both; the primary backend can switch without changing the `internal/signer` interface.
4. **[OPEN] Mirror policy:** Does v2.0 ship with a default mirror endpoint (e.g. a static file on sentinelproject.ai)? Or pure BYO? Affects Phase 5 scope and whether the installer sets `mirror_url` by default.
5. **[PROPOSED] macOS hardening parity:** Accept Linux as the more-hardened tier. macOS has no `seccomp` and no Linux capabilities — the equivalent (Seatbelt sandbox profiles + entitlements) has a different attack surface model and is not worth shipping in Phase 3. macOS Phase 3 deliverable is: hardened `launchd` plist (`KeepAlive`, `ProcessType=Background`, `HardResourceLimits`) + dedicated user + `harborlight-install.command` update. Document the Linux/macOS gap explicitly.
6. **[PROPOSED] v1 import boundary:** Recommend lossy import (timestamps + payloads only) with an explicit boundary marker leaf that states: "v1 chain imported — Merkle continuity begins here." The v1 SHA-256 linear chain cannot be reconstructed as a Merkle tree without changing all hashes. Claiming cryptographic continuity would be misleading. Documentary continuity (all events present, in order, with a clear seam) is sufficient and honest.

## Risk log

| Phase | Risk | Detection | Mitigation |
|---|---|---|---|
| 1 | Tree-head storage corrupted independently of leaves | Startup self-check loads head, walks first 100 leaves | Atomic rename on head update; checksum head against tail leaf hash |
| 1 | v1 import importer drops data silently | Diff leaf count vs. v1 backup tiers; emit count to status | Importer prints per-tier counts and exits non-zero on mismatch |
| 2 | Hardware-token loss bricks deployment | N/A — operator concern | Rotation flow in `docs/keys.md`; allowlist supports multiple operator pubkeys |
| 3 | seccomp profile too tight, daemon crashes on rare codepath | Integration tests + canary-style staged rollout | Profile generated from observed syscalls including error paths; opt-in via flag for one release before defaulting on |
| 4 | Gossip false positive → spurious "compromise" alert | Logged with peer-pubkey attribution | Configurable `N` intervals; require quorum > 1 by default |
| 4 | libp2p adds large dependency surface | `govulncheck` + `go mod why` audit | Pin to a known-good version; revisit annually |
| 5 | Mirror outage misread as tampering | `witness audit` distinguishes "mirror unreachable" from "mirror disagrees" | Two distinct exit codes |
| 6 | Pipelock vendor introduces parsing regressions | Existing pipelock test fixtures replayed against vendored library | Fuzz harness on the pipelock-event boundary |
| 6 | Removing HTML breaks scripts users built against `:8080/status.html` | Deprecation banner one release earlier — but this is V2.0, so consider whether to flag now | Release notes one-liner; `witness status --json` documented as replacement |
| 7 | History rewrite breaks downstream forks | Zero forks today, low risk | Notify in release notes; tag pre-rewrite commit as `pre-v2-history` for anyone who needs it |
