# Phase 1 assessment baseline

Every Phase 1 document cites these two pins.

| | Value |
|---|---|
| Specification | `LFDT-ProofOfControl/ov-poc-standard`, branch `master`, commit **`54a7bc67140b39c9107216cd390dd47c1d42946d`** (2026-10-31, "Update comment submission process in READM…"). Text is Working Draft v0.1; requirement rows unchanged since `93d0e28`, the commit our October issues cite. |
| Requirement export | `checklist/poc-checklist.json` and `checklist/poc-checklist.csv` (Appendix E is generated from the chapters by `tools/generate_checklist.py`). **127 requirements**: L1 35, L2 45, L3 35, L4 12. Matches the baseline of 127; no additions or removals to identify. |
| Conformance-stage text | `0.1/en/0x10-C10-Conformance-and-Disclosure.md` (C10.1 stages: Self-Declared, Third-Party Assessed, Continuously Monitored). Tier gating: `0.1/en/0x03-Using-Proof-of-Control.md` (Requirement Levels) and `0.1/en/0x10-C08-Verifiability-Tiers.md`. |
| Publication schedule | `RELEASE.md:28-29`: working-group ratification December 2026 to January 2027; **Stable Version 1.0 published February 1, 2027**. `README.md:263` repeats the date. Not confirmed with the working group; the repository is the only source. |
| Witness | `bigblue-r4/kiss-protocol` `main` at **`a78b609685b9e002efad666c66e6ff3ad1122b8f`** (tag `v3.4.0`, released 2026-11-24). Clean working tree. |
| Assessment date | 2026-11-24 |
| Assessor | SGAIL Labs internal assessment (Claude, for SGAIL), clean-room per the mission rules. Not a third-party assessment. |

## Clean-room record

- The understanding of the standard comes from `0.1/en/` chapters, Appendix E, `schema/README.md`, `schema/canonicalization.md`, `schema/poc-evidence.cddl` and `schema/poc-evidence.schema.json`. These are spec documents, not implementation.
- **`impl/` source was not read.** From `impl/` only the following were used:
  - `impl/attacks/run_attacks.py`: executed as a black box. Its first 30 lines (docstring and imports) were read, for execution safety only.
  - `impl/results/attacks.json`: read as output data.
- `schema/validate.py` was run as a black box. Its import lines were read for safety: no network, no subprocess; it imports `jsonschema`, `cryptography` and `hashlib`.
- Nothing was posted upstream. No issue, PR, comment or reaction was made on any repository.

## Environment

| Item | Value |
|---|---|
| Host | LAB workstation, Ubuntu (glibc 2.39), x86_64 |
| Go | `go1.26.11 linux/amd64`, the module toolchain pin (`go.mod`: `go 1.26.0`, `toolchain go1.26.11`) |
| Python for upstream tools | 3.12.3, in an isolated venv with `jsonschema 4.26.0` and `cryptography 50.0.2`. Run with `python -I`; no SGAIL credentials or keys in the environment. |
| Isolation | Upstream tools ran in a scratch clone, with no signing keys or production evidence present. Network was not blocked at the OS level: user-namespace sandboxing is restricted on this host. The safety review found no network use in the executed scripts. |

## Commands and results

| # | Command | Result |
|---|---|---|
| 1 | `go vet ./... && go test -race -count=1 ./...` (kiss-protocol @ a78b609) | **exit 0**. 35 packages `ok`; 395 test, fuzz and benchmark functions listed by `go test -list`. No failures. |
| 2 | `go test -tags poc_c07 -count=1 -v ./tests/poc_c07/`, with the suite from tag `c07-assessment-2026-10` copied into a scratch worktree of a78b609. **No file on any branch was changed.** | **18 pass / 13 fail** (exit 1, expected: the 13 failures are gap probes). Identical outcome on the same suite at `f15bc45`. |
| 3 | `python -I schema/validate.py --vectors` (spec @ 54a7bc6) | **exit 0, "17 passed, 0 failed"**: 4 positive, 11 negative, 2 canonical. |
| 4 | `python -I impl/attacks/run_attacks.py` (black box) | **exit 0, 11 scenarios, all PASS.** The regenerated `impl/results/attacks.json` is byte-identical to the published one. |
| 5 | `gh release download v3.4.0` + `cosign verify-blob` (v2.5.2) + `gh attestation verify` | Binary and SBOM signatures **Verified OK**. The provenance attestation binds `refs/tags/v3.4.0` @ a78b609 to `release.yml`. |

### Findings from the baseline runs

- **Correction to our October assessment (`CONFORMANCE_C07.md`).** It lists `TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected` (including the `replay` case) as passing. Since v3.3.3 the `replay` sub-case fails: one copy of record 0 appended after the signed head is treated as a crash tail. It is moved to `witness.log.crash-tail-*` with a WARN and is never committed, so `store.Open` succeeds instead of failing. The overall count (18/13) is unchanged because the earlier document's count was also taken after v3.3.3. Behaviour: the replayed record never enters the committed history (DETECTED and quarantined, not REJECTED as tampering). See trust-boundary-assessment.md, scenario 12.
- **Documentation mismatch reproduced.** The upstream docs give two different vector counts:
  - `README.md:143` says "16 signed test vectors — four positive, ten negative, two";
  - `schema/README.md` says "16 passed, 0 failed (4 positive, 10 negative, 2 canonical-form)".

  The validator reports **17** (11 negative). The extra negative vector is `digest-alg-width-mismatch.json`, which the schema README's own table does not list.
- **Upstream reference vector defect (#170) reproduced.** In `schema/vectors/positive/modify-bound.json` (verdict MODIFY, tree_size 1), `merkle_root` equals `SHA-256(0x00 || {"snapshot":…,"verdict":"ALLOW"})`, not the MODIFY leaf. The validator accepts it. The fix (PR #169) is still open.

## Inventory: kiss-protocol @ a78b609

- **Language:** Go only: 179 `.go` files (82 of them tests), 30,989 lines. Release binaries are static (`CGO_ENABLED=0`) for linux/darwin × amd64/arm64.
- **Binaries:**
  - `witness`: daemon and CLI; the evidence log.
  - `enforcer`: reads the log and prints alerts.
  - `gate`: decision gate. **Source only**, `0.1.0-dev`, not in releases.
  - `witness-pd`: chain-of-custody variant.
- **Process boundaries:**
  1. **`witness` daemon:** the only writer of the log. It runs as the unprivileged `witness` user with one capability (`CAP_DAC_READ_SEARCH`) under a hardened systemd unit and seccomp.
  2. **`gate` daemon:** separate process. It reads the witness log read-only, serves a unix socket authenticated by kernel peer credentials, and writes its own NDJSON feed that the witness ingests.
  3. **Relying party:** a protected service that links `pkg/gateenforce` (standard library only) to check tokens. No such service exists yet; only the simulation in `internal/gate/sim`.
  4. **Pipelock:** a third-party upstream proxy, launched and tailed by the witness bridge.
  5. **Event-feed producers:** SBH, ann-house and others write NDJSON files that the witness tails.
- **No NATS subscriber exists.** Ingestion is file tailing (`internal/pipelock`, `internal/sbh`, `internal/feeds`, `event_feeds` config). A NATS subscriber was planned before the 2026-10 rebuild and never built.
- **Hash chain / Merkle:**
  - `internal/merkle`: RFC 6962 structure, **BLAKE3** leaf and node hashing with 0x00/0x01 domain tags, exact split point, proof-depth check (fix C18). Inclusion proofs only; **no consistency proofs**.
  - The v1 `PrevHash` chain field is decode-only.
- **Store** (`internal/store`):
  - AES-256-GCM-encrypted frames, key = HKDF of `/etc/machine-id` (`internal/encrypt/encrypt.go:23`), plus a BLAKE3 MAC.
  - Signed tree head `tree-head.json` (Ed25519 over `size_be8‖root`).
  - One write per record; fsync before the head is written; crash-tail quarantine; read-only pinned open for verifiers.
- **Signing keys:**
  - Witness: software Ed25519 key `~/.witness/signing.key`, mode 0400; damaged files are refused.
  - YubiKey PIV signer behind build tag `piv`, not in releases.
  - Operator approval keys: `witness accept keygen`, listed in `trust/operators.txt`.
  - Gate: software key; PIV deferred.
- **Mirror** (`internal/mirror`): file, HTTPS, and S3 (S3 behind build tag `s3`) heads; file-only leaf-hash feed `leaves.bin` (`witness verify-leaves`).
- **Gossip** (`internal/gossip`): signed heartbeats between witness peers. **Roots are not exchanged.**
- **Gate / circuit breaker (in this repo):**
  - `internal/gate/{proto,policy,core,breaker,evidence,daemon,feed,sim}`;
  - `pkg/gateenforce`, `pkg/gateenforce/witnessproof`;
  - hardened `packaging/systemd/gate.service`; `docs/gate-arch.md` and `docs/gate-ops.md`.
- **Functionality that lives elsewhere:**
  - Split-Brain Harness (`bigblue-r4/split-brain-harness`, Rust, v1.6.0): analysis verdicts, consumed as an advisory feed.
  - Pipelock (third party): egress proxy and receipts.
  - `deobfuscate` and `unicode-interference` (Rust crates): not linked into Witness or gate.
  - Dream Engine / Lucid (SBH `src/dream_engine.rs`): research only.
- **Existing tests relevant to PoC:**
  - store crash-tail, pinned-open, export and leaf tests;
  - merkle unit and fuzz tests;
  - gate proto, core, breaker, evidence, daemon tests and 18 acceptance tests (`internal/gate/sim`);
  - the C07 probe suite (on a tag, not on main).
