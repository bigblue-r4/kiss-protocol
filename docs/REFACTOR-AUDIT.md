# Refactor audit (2026-11-16)

Baseline: `origin/main` 68b5c89. Tools: `deadcode` (x/tools), `staticcheck`,
`govulncheck` v1.9.0. This file tracks the cleanup pass. Each item is **act**
(done or scheduled) or **keep** (with the reason).

## Fixture note

Reproducible-binary hashes **cannot** prove a source refactor changed nothing.
Line numbers are compiled into the binary's line tables, so deleting any line
changes the bytes, even with `-buildid=` stripped. Behaviour is pinned by the
test suite instead (`go test -race ./...`, the gate sim acceptance tests, and
the fuzz corpora). `make verify-reproducible` still proves that a *given*
source tree builds deterministically.

## Dead code (`deadcode -test ./...`: unreachable even from tests)

| Symbol | Verdict |
|---|---|
| `breaker.Breaker.SpendNonce` | **act: removed.** `Rebuild` spends nonces directly (`b.nonces[...] = true`), so this was a redundant second path. |
| `gossip.Node.PeerStatuses` | **act: removed.** No caller. |
| `pipelock.Runner.AuditLogPath` | **act: removed.** `Config.AuditLogPath` is the one in use. |
| `soul.InstallDefault` | **act: removed.** Its comment said `witness init` calls it; nothing does. |
| `store.Store.Snapshot` | **act: removed.** No caller. |
| `pd/evidence.PDStore.RecordAccess`, `RecordDestroyed`, `GetItem` | **keep: unwired feature, not ghost code.** `docs/pd/chain-of-custody.md` documents the legal-hold refusal in `RecordDestroyed`, but `witness-pd` has no command that reaches it. Needs a decision: wire it up or drop the feature and its docs. |
| `pd/roles.Can`, `Valid`, `All` | **keep: unwired, and security-relevant.** Roles are defined but never enforced; `cmd/witness-pd/main.go` holds them with `_ = roles.Can // future expansion`. Same decision as above. |
| `pd/export.Verify` | **keep: unwired.** Export bundles can be signed, but no CLI path verifies one. |

Symbols that are unreachable only without `-test` are kept: `internal/gate/sim`
is test support, `pkg/gateenforce/**` is public library API, and
`gate/proto` Verify/Decode are used by enforcement points.

Commented-out code: **none.** The regex hits were all prose comments.

## Duplicate helpers

- Temp-file-then-rename atomic write is hand-rolled 7 times: store,
  death, accept/spool, gossip/peer, mirror/static, gate/daemon/state, and
  pipelock/tailer. **act: PR 2**, unify as `internal/fsutil.WriteFileAtomic`.
- Ed25519 key loading appears in 4 places (accept/request, pd/export,
  pipelock/signingkey, signer/dev), and sha256→hex in 7. **act: PR 3**, only
  where the on-disk format really is the same.

## Dependencies

The direct deps are `BurntSushi/toml`, `golang.org/x/crypto`, and
`lukechampine.com/blake3`. **keep all three:** the stdlib has no TOML or BLAKE3,
and x/crypto supplies primitives. Dependabot #34 (x/crypto 0.19 → 0.52) is
open.

**Finding: the Go toolchain pin.** `go.mod` pins `toolchain go1.25.0`, and both
`ci.yml` and `release.yml` build with it via `go-version-file`. `govulncheck`
reports **37 stdlib vulnerabilities that the code actually reaches**, for
example GO-2026-6859 (net/http server crash, reached via the gate daemon's
`Serve`). Fixes land up to go1.26.11. Bumping the pin changes release builds,
so it needs an explicit go.

## Loose types (`map[string]any` / `interface{}`: 37 sites in 16 files)

- **act: PR 6.** `lifecycle.Event.Data`, `accept.RejectedData`, and the gate
  daemon's response maps become typed structs with the same JSON keys.
- **keep.** `gate/core` and `gate/evidence/signals` decode into
  `map[string]any` to probe untrusted JSON paths. `gate/feed` deliberately
  avoids map decoding for numbers above 2^53.
