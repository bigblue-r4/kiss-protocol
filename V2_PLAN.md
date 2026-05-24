# V2_PLAN.md — Implementation map

> Phase-0 deliverable. Inventory pre-filled from the v1.0.0 repo state; verify each row by viewing the file before treating it as gospel.

## Repo inventory

| Component | Language | Path | Notes |
|---|---|---|---|
| Daemon + CLI entrypoint | Go | `cmd/witness/` | Single binary, both modes |
| Genesis snapshot | Go | `internal/genesis/` | Pre-AI-install machine state |
| Storage / log writer | Go | `internal/storage/` | **Rewritten in Phase 1 → Merkle log** |
| Drift detection | Go | `internal/drift/` | Stays; emits leaves into the new log |
| Backups (3-tier) | Go | `internal/backups/` | **Mostly deleted in Phase 1** |
| Anomaly detection | Go | `internal/anomaly/` | Stays |
| Sync (centralized, `enable-sync`) | Go | `internal/sync/` | **Deprecated in Phase 4, removed after one release** |
| Soul file (default policy) | TOML | `payload/witness/default-soul.toml` | **Becomes signed in Phase 2** |
| HTML dashboard | HTML / JS | spread across repo, ~17.7% of codebase | **Removed in Phase 6 — locate via `//go:embed` and template handlers** |
| systemd / launchd units | Shell / plist | `install.sh`, `harborlight-install.sh`, `harborlight-install.command` | **Hardened in Phase 3** |
| CI | YAML | `.github/workflows/` | **Extended in Phase 7, not replaced** |
| Existing SECURITY.md | Markdown | `SECURITY.md` | **Updated in Phase 7, not created** |
| Pipelock (external) | Go | `github.com/luckyPipewrench/pipelock` | **Vendored as library in Phase 6** |

## Cross-language boundaries

Confirmed all-Go. The only repo-crossing dependency is Pipelock — also Go — which is currently invoked as a subprocess. Phase 6 collapses that seam by vendoring.

## Phase → file map

### Phase 1 — Merkle log
- Files to add:
  - `internal/merkle/tree.go` — RFC 6962-style tree
  - `internal/merkle/proof.go` — inclusion proof gen + verify
  - `internal/storage/log.go` — append-only writer
  - `cmd/witness/verify.go`
  - `cmd/witness/prove.go`
  - `internal/migrate/v1_import.go` — one-shot v1-tier importer
- Files to modify:
  - `internal/storage/*` — replace 3-tier write path
  - `cmd/witness/status.go` — drop the "Primary / Secondary / Tertiary" lines
- Files to remove:
  - Most of `internal/backups/`
- New dependencies:
  - `lukechampine.com/blake3` (BLAKE3 hashing)
  - `github.com/transparency-dev/merkle` *or* a thin in-tree implementation — decide based on dependency surface
- Test files:
  - `internal/merkle/tree_test.go`
  - `internal/merkle/proof_test.go`
  - `internal/storage/log_test.go` (tamper, truncate, reorder)

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
  - `internal/sync/*` — deprecation warnings; flagged for removal next release
  - `cmd/witness/enable-sync.go` — print deprecation banner
- New dependencies:
  - `github.com/libp2p/go-libp2p`
  - `github.com/libp2p/go-libp2p-pubsub`
- Test files:
  - `internal/gossip/heartbeat_test.go` — silence → presumed-compromised state machine

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
  - Replace subprocess + log-tail with direct library calls
  - Remove install.sh's pipelock subprocess setup
  - New: `internal/pipelock_bridge/bridge.go` — adapter that pipes pipelock events into Merkle log leaves
  - New: `docs/pipelock-integration.md`
- **HTML removal:**
  - Find via: `grep -r "//go:embed" --include="*.go"`, `find . -name "*.html"`, `grep -r "html/template" --include="*.go"`
  - Remove every template, every route handler, every embed directive, every static asset
  - Remove any HTTP listener that existed only for the dashboard

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

> Resolve before Phase 1 sign-off.

1. **Pipelock maintenance:** is the Pipelock repo under the same operator? If yes, the Phase 6 coordination is trivial. If not, an upstream API contract is needed first.
2. **Merkle library:** vendor `transparency-dev/merkle` (battle-tested, larger dep surface) or write an in-tree ~200-LOC implementation (smaller surface, more review burden)?
3. **FIDO vs PIV as primary:** YubiKey 5 supports both. PIV gives smartcard semantics (PKCS#11 ecosystem); FIDO2 is simpler API but less standard for code-signing flows. Pick one as default, support the other as opt-in.
4. **Mirror policy:** is the v2.0 release going to ship with a default mirror endpoint (e.g., a static file on sentinelproject.ai), or pure BYO?
5. **macOS launchd vs systemd parity:** how much of the Phase 3 hardening (seccomp, capability drops) has a macOS equivalent worth shipping, vs. accepting Linux as the more-hardened tier?
6. **v1 import boundary:** should the v1-tier importer be lossy (timestamps + payloads only) or attempt to reconstruct the v1 hash chain inside the v2 Merkle log for full continuity?

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
