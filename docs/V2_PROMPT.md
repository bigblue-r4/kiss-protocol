# Claude Code Prompt — Harborlight V2: Hardening & Tamper-Evidence Upgrade

## Project context

Repo: `github.com/bigblue-r4/kiss-protocol` — public name **SGAIL Labs Harborlight Firewall**, internal name Witness / Sentinel. Tamper-evident machine-state witness for AI agent environments. v1.0.0 was cut on 2026-05-13.

Stack: Go 1.22+. Module path `github.com/bigblue-r4/kiss-protocol`. Main binary: `witness` (CLI + daemon). License: MIT.

Existing layout:

- `cmd/witness` — CLI entry
- `internal/` — `genesis`, `storage`, `drift`, `backups`, `anomaly`, `sync`
- `payload/witness/default-soul.toml` — soul file
- `.github/workflows/` — existing CI (extend, do not replace)
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` — exist (update, do not recreate)
- `install.sh`, `harborlight-install.sh`, `harborlight-install.command` (macOS), `usb-setup.sh`
- HTML dashboard assets (~17.7% of the repo) — slated for removal in Phase 6

Pipelock dependency: separate repo `github.com/luckyPipewrench/pipelock`, Go, currently started by Witness as a subprocess with audit-log tailing. Phase 6 vendors it as a library and removes the subprocess seam.

## Mission

Replace security-through-obscurity with cryptographically verifiable integrity and hardware-rooted trust, while shrinking attack surface. Land a V2 that an external security reviewer would take seriously on first read. Standalone mode stays a first-class deployment at every phase.

## Design choices (already made — flag before changing)

- Hash: **BLAKE3** via `lukechampine.com/blake3`.
- Log structure: **Merkle log** (RFC 6962-style), backed by `github.com/transparency-dev/merkle` or a thin equivalent.
- V2 hardware signer: **FIDO2 / PIV** via `github.com/keys-pub/go-libfido2` and/or `github.com/go-piv/piv-go`. TPM2 deferred.
- Software-key signer is `--dev` only with a startup warning banner. Never default in release.
- Gossip: **`go-libp2p` gossipsub.** No central server. Replaces `witness enable-sync --endpoint`.
- Release signing: **`sigstore/cosign`** (Go-native).
- Fuzzing: **native Go 1.18+ fuzz** (`go test -fuzz`). No external framework.
- No eBPF in V2. Death-broadcast is the cryptographic absence of a signed heartbeat from a hardware key.

## Phase 0 — Threat model (write before code)

Fill in `THREAT_MODEL.md` (skeleton already in repo root). Spell out:

- Attacker capabilities (local root, network MITM, kernel rootkit, supply-chain at install, hostile co-tenant).
- Guarantees Witness provides against each, mapped to mechanisms.
- Non-goals (hardware-token physical extraction, CPU side-channels, full-mesh compromise, payload confidentiality).

Stop and wait for sign-off before Phase 1.

## Phase 1 — Verifiable Merkle log (eliminates the three-tier backup model)

- **Remove** the existing three-tier backup model: `~/.witness/primary`, `/var/lib/.watcher_state`, and the derived "tertiary [not displayed]" tier. That whole structure goes.
- **Replace** with one canonical append-only Merkle log at `~/.witness/log/` (per-user) and `/var/lib/witness/log/` (system-wide install).
- Each leaf: monotonic counter, timestamp, payload. Internal nodes hashed with BLAKE3 per RFC 6962 conventions.
- Signed tree head stored separately from leaves; rotated on each append.
- New CLI:
  - `witness verify` — walks the tree, reports first inconsistency by leaf index.
  - `witness prove <index>` — emits an inclusion proof a third party can verify with only the tree head and the leaf.
- Migration: one-shot importer from v1 backup tiers into the v2 log, emitting a "v1 import boundary" marker leaf.
- Tests: known-good passes; flipped byte → fails with exact index; truncation detected; reordering detected; inclusion proof verifies; tampered tree head fails signature check.
- Touches: `internal/storage`, `internal/backups` (largely deleted), `cmd/witness/verify.go` (new), `cmd/witness/prove.go` (new).

## Phase 2 — Hardware-bound signer (covers tree heads AND soul file)

- Single `internal/signer` package with two backends:
  - `dev` — software ed25519. Requires `--dev` flag; logs a 5-line warning banner at startup.
  - `fido` — FIDO2 / PIV via `go-libfido2` and/or `piv-go`. Pick one as primary, document why.
- Signed tree heads from Phase 1 use this signer.
- `payload/witness/default-soul.toml` requires a detached ed25519 signature from a key in the trust allowlist. Witness refuses to start on missing / mismatched / unknown-key signature.
- New CLI:
  - `witness soul sign <path>` — sign a soul file with the configured signer.
  - `witness soul verify <path>` — verify against allowlist.
- Trust allowlist at `~/.witness/trust/signers.txt` (one pubkey per line, with operator-assigned label). Documented as the bootstrap trust root.
- Key rotation flow in `docs/keys.md`.

## Phase 3 — Reinforce loyalty (resist being killed)

- Dedicated `witness` system user; daemon runs as that user, not root.
- `PR_SET_NO_NEW_PRIVS`; seccomp profile generated from an observed-syscall pass during integration tests.
- Hardened systemd unit (replace whatever `install.sh` ships today): `Restart=always`, `RestartSec=1s`, `MemoryMax`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `CapabilityBoundingSet` pruned, `PrivateTmp`, `ProtectHome`, `ProtectKernelModules`, `ProtectKernelTunables`, `SystemCallArchitectures=native`.
- macOS: equivalent `launchd` plist with `ProcessType=Background`, `KeepAlive`, and `HardResourceLimits`. The existing `harborlight-install.command` is the install seam to update.
- Document what these protect against and what they do not.

## Phase 4 — Peer-to-peer gossip + death detection (replaces `enable-sync`)

- New `internal/gossip` package using `go-libp2p` gossipsub.
- Nodes exchange signed integrity summaries (current tree head + heartbeat counter) on a configurable interval.
- "Presumed compromised" = no signed heartbeat for N intervals AND no signed shutdown message received. N and the response action are user-configurable.
- A signed shutdown message is the clean exit path; absence of one is the death broadcast.
- Quorum threshold configurable.
- **Deprecate** `witness enable-sync --endpoint` and `WITNESS_SGAIL_TOKEN`. Keep them working for one release with a deprecation warning, then remove. Document the migration to gossip in `docs/migrating-from-sgail-sync.md`.
- Standalone mode unchanged — peering is opt-in via `witness peer add <multiaddr>`.

## Phase 5 — External transparency mirror

- New `internal/mirror` package.
- Witness periodically publishes the signed tree head to an external location: static file on a neutral host, S3-compatible bucket, or an existing public transparency log. Pluggable backend.
- Mirror endpoint and publish interval in `~/.witness/config.json` (or env vars).
- New CLI: `witness audit --mirror <url>` — fetches the mirror's current head and verifies the local log against it.
- Attacker now needs to compromise the mirror in addition to the host to silently rewrite history.

## Phase 6 — Reduce attack surface

**Pipelock integration:**

- Vendor `github.com/luckyPipewrench/pipelock` as a Go module dependency.
- Replace the subprocess + audit-log-tail pattern with an in-process library call. Pipelock's audit events flow directly into the Merkle log as leaves.
- Coordinate with the Pipelock maintainer (likely the same operator) to expose a stable Go API and tag a release before vendoring.
- Document the API surface vendored in `docs/pipelock-integration.md`.

**HTML dashboard removal:**

- HTML is ~17.7% of the codebase. Find every template, every route serving them, every JS asset, every embedded `//go:embed` directive — remove all of it.
- `witness status` (CLI, with `--json` for machine consumption) is the only supported interface going forward.
- Document the removal in `CHANGELOG.md` with a one-line migration note for anyone scripting against the dashboard.

## Phase 7 — Credibility & supply chain

- **Reproducible builds:**
  - Build flags: `-trimpath -buildvcs=false`.
  - Pinned `GOTOOLCHAIN` in `go.mod`.
  - Nix flake at `flake.nix` for hermetic builds.
  - CI verifies bit-identical output across two runners (Linux + macOS).
  - Publish artifact hashes alongside releases.
- **Signed releases:** tags signed with `cosign`. Verification command added to `README.md`.
- **Fuzz targets in CI** using native Go fuzzing, for every parser:
  - `internal/soul` — TOML parser.
  - `internal/storage` — log leaf decoder.
  - `internal/gossip` — frame decoder.
  - `internal/mirror` — response decoder.
  - Short pass on every PR; nightly long pass.
- **Git history rewrite:** remove `Co-Authored-By: Claude` and AI authorship trailers via `git filter-repo`. Force-push **only after explicit sign-off.** Notify the (currently zero) forks via release notes.
- **Docs:**
  - Update existing `SECURITY.md` with disclosure policy and contact public key.
  - New `docs/audit-prep.md` — reviewer entry point, build reproduction, test coverage map.
  - New `docs/threat-model.md` (copy of `THREAT_MODEL.md` from Phase 0).
- CI clean on: `go vet`, `staticcheck`, `gosec`, `govulncheck`.

## Constraints

- No new runtime dependency without justification in PR description.
- Every phase ships behind a feature flag where feasible.
- Standalone single-node mode must keep working at every commit on `main`.
- No telemetry, no phone-home, no auto-update.
- Public CLI flags and config keys are stable within a phase; breaking changes get their own labeled commit and a `CHANGELOG.md` entry.
- Cross-platform: Linux and macOS both supported at every phase. Existing `harborlight-install.command` (macOS) and `install.sh` (Linux) paths kept in sync.

## Working protocol

1. Read the repo. Read `go.mod` to confirm current dependencies. Fill in `V2_PLAN.md` (skeleton already in repo) — map each phase to specific files / packages / new dependencies. Flag anything ambiguous.
2. Wait for sign-off on `V2_PLAN.md` and `THREAT_MODEL.md`.
3. Implement one phase per branch (`v2/phase-1-merkle-log`, `v2/phase-2-signer`, etc.). Each branch ships: code + tests + docs + `CHANGELOG.md` entry.
4. Open each branch as a PR-style summary at the end of the phase. Do not start the next phase until reviewed.

**First action:** read the repo (including `go.mod`, `cmd/witness/`, and `internal/`), then fill in `V2_PLAN.md` and `THREAT_MODEL.md`. No other code yet.
