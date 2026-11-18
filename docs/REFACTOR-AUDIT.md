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
  pipelock/tailer. **act: done (#51, landed with #47).** Six sites now use
  `internal/fsutil.WriteFileAtomic`. Every one gained file and directory
  fsync, and none got weaker. **keep: `death.go`.** Its destination name is
  derived from the random temp name, and it already does a full fsync.
- sha256→hex is hand-written in 8 places. **act: done (#52).** Seven witness-side
  sites use `internal/hashutil.SHA256Hex`, which makes the same stdlib calls, so
  every output is byte-identical. **keep: `gate/policy.Hash`.** The gate is a
  separate process boundary (`tests/importboundary_test.go`). **keep: the
  streaming hashes** (death, pd/export, genesis `HashOneFile`): different shape.
- Ed25519 key loading appears in 4 places. **keep all four.** They read three
  different on-disk formats: a raw 32-byte seed file (accept/request,
  signer/dev), a 64-byte hex string (pd/export), and pipelock's
  header+base64 (pipelock/signingkey). The two raw-seed readers differed in
  what they did with a bad file, which exposed a real bug: see below.

**Finding (fixed, #53): the signer replaced a damaged key file.**
`signer.loadOrGenerateSeed` treated a key file of the wrong length as missing
and wrote a new key over it, with no error and no log line. The witness runs as
root, so mode 0400 did not stop this. A truncated `signing.key` therefore
silently changed the witness's and the gate's signing identity and destroyed
the old key. Now only a missing file is generated; a damaged one is an error.

## Dependencies

The direct deps are `BurntSushi/toml`, `golang.org/x/crypto`, and
`lukechampine.com/blake3`. **keep all three:** the stdlib has no TOML or BLAKE3,
and x/crypto supplies primitives. **act: done (#54).** x/crypto
0.19 → 0.59 rather than Dependabot's 0.52, which still carried four x/crypto
advisories. That cleared all 17 Dependabot alerts. The `go` directive moved to
1.26.0, which x/crypto 0.59 requires. `go mod tidy` is not run, because it would
add `go-piv/piv-go` for the optional `piv` build tag.

**Finding: the Go toolchain pin.** `go.mod` pins `toolchain go1.25.0`, and both
`ci.yml` and `release.yml` build with it via `go-version-file`. `govulncheck`
reports **37 stdlib vulnerabilities that the code actually reaches**, for
example GO-2026-6859 (net/http server crash, reached via the gate daemon's
`Serve`). Fixes land up to go1.26.11. **act: done
(#48, landed with #54).** `toolchain go1.26.11`; govulncheck now reports 0.

## Loose types (`map[string]any` / `interface{}`: 37 sites in 16 files)

- **act: PR 6.** `lifecycle.Event.Data`, `accept.RejectedData`, and the gate
  daemon's response maps become typed structs with the same JSON keys.
- **keep.** `gate/core` and `gate/evidence/signals` decode into
  `map[string]any` to probe untrusted JSON paths. `gate/feed` deliberately
  avoids map decoding for numbers above 2^53.

## Other findings during the pass

- **Witness drift scan CPU (fixed, #46).** Each 30 s drift check re-read and
  hashed every watched file in memory, once per symlinked alias. Now each real
  file is hashed once per check, streamed: 1.98 s / 1300 MB → 0.58 s / 58 MB.
- **`EvidenceTailer.Stop` race (fix: #49).** `Stop` could return before `Run`
  had registered, which skipped the final drain, so pipelock's last receipt could
  be lost. Under `-race` it failed about 1 run in 30 on Go 1.25 and 1.26.
- **witness-pd docs overclaimed (fix: #50).** They described a dashboard that
  was removed in b2a82ea, and roles as enforced. The docs now say what is
  wired and what is not.
- **Open: `TestAcceptance18ConcurrentBudget` flakes on Ubuntu.** It reports
  "issued 0 against budget 100". Under CPU load the number issued falls as low
  as 9 of 200, so 0 is reachable on a busy runner. It needs a test-side fix.
