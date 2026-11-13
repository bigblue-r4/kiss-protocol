# Gate Architecture: kiss-gate, provenance gate and circuit breaker

> Status: **steps 1–2 built** (wire formats in `internal/gate/proto`, enforcement
> point in `pkg/gateenforce` + `pkg/gateenforce/witnessproof`, verified evidence
> view in `internal/gate/evidence`). No gate daemon yet. This document is the contract the build steps follow; section 2 records
> where the code differs from the original brief (C16–C18 found in step 1).

## 1. What the gate is, and what it is not

The witness records and never prevents ("it witnesses, it does not defend",
THREAT_MODEL.md). That stays true. The gate is a **third binary** that adds
prevention for a short list of high-consequence actions (withdrawals, key use,
production deploys, privilege grants, bulk export) without touching the
witness:

```
            evidence (read-only)                 decision                    control
┌──────────────────────────────┐   ┌──────────────────────────────┐   ┌──────────────────────────┐
│ witness (kiss-core)          │   │ gate (kiss-gate)             │   │ protected service        │
│  writes the Merkle log       │──▶│  reads + verifies the log    │   │ (signer / wallet / deploy│
│  records the gate's feed     │◀──│  writes ONLY its own feed    │   │  holds pkg/gateenforce)  │
│  no authority                │   │  signs tokens + epochs       │──▶│  executes only with a    │
└──────────────────────────────┘   │  breaker: trips, never resets│   │  valid token             │
                                   │  on its own                  │   └──────────────────────────┘
                                   └──────────────────────────────┘
```

- **witness = evidence, no authority.** Unchanged. It records the gate's feed
  as it records any other feed.
- **gate = decision.** Read-only on evidence. Deterministic policy, no LLM or ML.
- **enforcement point = the real control.** `pkg/gateenforce` runs inside the
  service that holds the dangerous capability. A service that does not call it
  is not protected, whatever the gate decides.

Motivating incident (Binance, 2026-10-29): a compromised DevOps laptop reached
an internal service container, which submitted unauthorized withdrawals. About
$6.3B moved across 10 chains in about 20 minutes, and every hop looked like
normal engineer activity. The gate's answer: withdrawals need a root that
laptop cannot produce (an operator signature, or a signed automated envelope
with a global value budget), and a breaker that freezes the class when the
budget runs out, until a quorum of operators resets it.

## 2. Brief assumptions checked against the code

Read during Phase 0: README, THREAT_MODEL.md, docs/{threat-model, enforcer-arch,
event-feeds, keys, mirror-setup}.md, CHANGELOG [Unreleased],
internal/store/{store,export}.go, internal/enforcer/reader.go, internal/signer/*,
internal/soul/{soul,verify}.go, internal/config/config.go, internal/feeds/*,
internal/sbh/bridge.go, internal/pipelock_bridge/bridge.go, internal/gossip/*,
cmd/enforcer/main.go, plus internal/lifecycle, internal/merkle,
internal/pipelock/tailer.go, internal/accept and cmd/witness/main.go where the
brief relied on them.

### Confirmed

| Brief says | Code |
|---|---|
| Go 1.22 module, stdlib-first, CGO-free static builds, `-trimpath` reproducible | `go.mod` (go 1.22, toolchain 1.25.0); Makefile `REPRO_FLAGS`; CI `make verify-reproducible`. Deps: BurntSushi/toml, x/crypto, blake3. |
| AES-256-GCM log, machine-derived key | `encrypt.DeriveKey(machid.Get())`; frames are 4-byte BE length + sealed JSON. |
| RFC 6962 Merkle tree with BLAKE3, ed25519-signed heads | `internal/merkle` (0x00 leaf / 0x01 node prefixes); leaf = `HashLeaf(json.Marshal(Entry))`. |
| `ExportDir` / `VerifyExport` are a read-only path with prior-head (append-only) checks | `export.go`. `ExportDir` re-reads the head and log until they agree and never moves a crash tail. `VerifyExport` checks root, size, pinned signature, entries vs leaves, and every prior as a prefix. |
| `Open` / `OpenTrusting` can mutate the log dir | `openStore` quarantines a crash tail (`quarantineTail` truncates `witness.log`). |
| `enforcer.TailReader` never checks the recomputed root against the signed head | Confirmed. `poll()` recomputes leaves and checks nothing against the head or any key, and swallows read errors (`err != nil → return`). Listed as a follow-up (section 12). |
| Feed source = configured name, enforced only by file permissions | `internal/feeds`, `config.ValidateEventFeeds`. |
| Soul escalation = weighted ticks with warn/escalate/halt thresholds | `soul.Escalation{Thresholds, TickSources}`. |
| `<label> <hex>` allowlist format | `soul.LoadAllowlist(path)` takes any path, so `/etc/gate/trust/operators.txt` loads with no change. `witness accept` already uses the same format for `~/.witness/trust/operators.txt`. |
| Log events the gate keys on | All exist, with these exact names: `DEATH signal_received` (source `witness`); `INFO daemon_start` (`witness`); `witness_downtime` (`witness`, **CRITICAL** when `clean_stop:false`); `mirror_unreachable` (CRITICAL, `witness`); `mirror_not_configured` (CRITICAL in production, WARN in `--dev`, `witness`); `WARN tree_head_unsigned`; `DRIFT drift_detected` (source `drift`); `WARN sbh_decision:stop_and_ask` and `WARN sbh_escalation` (source `sbh`); `pipelock_receipt:proxy_decision` (source `pipelock`). |

### Corrected

| # | Brief assumption | What the code actually does | Consequence for the gate |
|---|---|---|---|
| C1 | "Head stale = no new verified head in head_max_age"; token carries `witness_head {size, root, sig_key}` | The head signature covers **only `size_be8 ‖ root`** (`treeHeadSigInput`). `ts` and `prev_root` are **unsigned**, and there is no domain-separation prefix. | Head age cannot come from `head.ts`. The gate measures it on **its own monotonic clock**: the time since it last verified a head with a **larger size**. A replayed old head never moves that clock. The token must also carry the head **signature** (`witness_head.sig`), or the enforcement point cannot verify the head. Gate-signed messages are always domain-prefixed (`kiss-gate/...`), so a gate signature can never pass as a 40-byte head signature, and the reverse cannot happen either. |
| C2 | Never call `OpenPinned`, because it can quarantine a crash tail | Since #41, `OpenPinned` → `readCommitted` is **read-only** (never moves, truncates or creates). Only `Open`/`OpenTrusting` quarantine. | The constraint stands anyway. `OpenPinned` decrypts the whole log on every call and is coupled to store internals. The gate uses `ExportDir` + `VerifyExport` for the first full verify, and a new read-only incremental helper after that (section 5). |
| C3 | Append-only check against *every* prior head, VerifyExport-style | `VerifyExport` recomputes `merkle.Root(leaves[:p.Size])` once per prior, so O(n) per prior and O(n·k) over a run. | The gate keeps the **full verified leaf vector** in memory. A new head is accepted only if `head.Size ≥ last.Size` and `head.Root == Root(cached_leaves ‖ new_leaves)`. By induction every earlier head is then a prefix: the same property, at O(new). Retained heads are persisted, and at startup the gate re-checks them with `VerifyExport` priors. |
| C4 | Evidence verification includes the MAC | `ExportDir` does not check the MAC, and `VerifyExport` cannot (no key). | Fine. The MAC adds nothing against A1, because the key derives from world-readable `/etc/machine-id`. The gate relies on the **pinned signature only**. It still needs the machine key to *decrypt*, derived the same way the enforcer does. |
| C5 | enforcer-arch.md: "Core never imports enforcer: enforced by Go module boundaries" | Nothing enforces it. Go module boundaries do not stop one `cmd` from importing an `internal` package of the same module. | `tests/importboundary_test.go` (Phase 0) makes it true and covers gate ↛ enforcer and witness ↛ gate. The doc line is fixed. |
| C6 | "laptop host feed shows connect → container exec"; "connect edges" | The witness writes no `connect` or exec events. The only network-ish built-ins are pipelock receipts (`pipelock_receipt:*`, target in the payload). | Edges (`origin_host\|principal → target`) come from **custom feeds** (e.g. a `netflow` or `exec-audit` feed) and from `ActionRequest` itself. The sim builds such a feed. The edge rule is tightening-only. |
| C7 | "drift_detected on the gate or signer host"; drift "by host" | **One witness log = one host.** `drift_detected` describes the machine its witness runs on and carries no host field. | The gate reads **one** witness (its own host's). "Drift on the signer host" works when the gate runs on the signer host (the recommended topology, section 9). Other hosts (the laptop) reach the gate only through feeds written on the gate's host. Those are forgeable by whoever ships them, so they are tightening-only. Reading several witnesses is a follow-up. |
| C8 | Gate feed records can be matched in the log | The witness parses each line into `map[string]interface{}` and stores `json.Marshal` of it: keys re-sorted, **numbers become float64** (precision loss above 2^53). | Every gate-feed field that matters (amounts, ids, epochs, leaf indexes, hashes) is written as a **string**. The gate finds its own records by `request_id`, never by byte-equality with the line it wrote. |
| C9 | Head cadence: "heads update on every append and drift tick" | Confirmed: `Append` writes a signed head every time, and drift ticks append every `drift_interval_sec` (default **30 s**). The feed tailer sleeps **200 ms** at EOF. | `head_max_age` (default 60 s) is valid only while `drift_interval_sec ≤ head_max_age / 2`. Policy load checks this against an operator-declared `witness_drift_interval_sec` and refuses otherwise. Expected commit-wait ≈ tailer (≤ 0.2 s) + append + gate poll (1 s default) ≈ **0.2–1.3 s**, to be measured (section 11). |
| C10 | Feed source "gate" | `config.reservedSources` also reserves `operator` (docs/event-feeds.md omits it). `gate` is **not** reserved. | That is correct: `gate` must be a configurable feed. No change. |
| C11 | `pkg/gateenforce` is stdlib-only **and** verifies commit-wait inclusion proofs | Leaf and node hashes are BLAKE3, which is not in the stdlib. | Split: `pkg/gateenforce` (token, epoch, replay) is **stdlib only**. `pkg/gateenforce/witnessproof` verifies inclusion proofs and imports `lukechampine.com/blake3`, which is already a dependency and pure Go. No new module dependency. A service without commit-wait classes never imports it. |
| C12 | Policy signed with "the same mechanics as soul sign/verify" | `soul.SignSoul` signs the **raw file bytes**, with no domain separation. | A soul signature and a policy signature would be interchangeable messages. The gate keeps the `SoulSig` JSON envelope and `soul.LoadAllowlist`, but signs `"kiss-gate/policy/1\n" ‖ bytes` in `internal/gate/policy`. Soul code is not changed. |
| C13 | Gate key via the signer package, PIV preferred | `signer.NewPIV()` hard-codes slot **9a**, which the witness PIV build also uses. | A gate co-located with a PIV witness needs a separate token or a different slot. Step 4 adds an **additive** `signer.NewPIVSlot(slot)` and keeps `NewPIV` as is. The dev/software signers take a key dir, so `/var/lib/gate` just works. |
| C14 | Restart rebuilds breaker state from the gate's records in the verified log | The gate's own feed lines reach the log with tail latency, so the newest few may not be there yet at a crash. | Rebuild = verified-log records **∪** the local feed file **∪** the local state file, and the most restrictive wins. A trip in the local file but not yet in the log still counts. A reset counts only once it is in the verified log, with its quorum signatures re-checked. |
| C16 | Formats live in `internal/gate/proto`; `pkg/gateenforce` is the public library | A service in another module cannot name a type from an `internal` package, so it could not build an `ActionRequest` or read a `Token`. | `pkg/gateenforce` re-exports the formats as **type aliases** (`gateenforce.Token = proto.Token`). External code uses the aliases; the layout stays as briefed. |
| C17 | Token carries `witness_head` + `witnessed_leaf_index`; the enforcement point checks the inclusion proof | A proof that *some* leaf sits at index i says nothing unless the verifier knows what the leaf is, and the enforcement point never saw the log. | The token carries one optional `witnessed` block: the signed head, the leaf index, the **log entry JSON itself** (the leaf preimage, exactly as the witness hashed it) and the proof. `witnessproof` recomputes the leaf from the entry, checks the proof and head, then checks the entry is source `gate`, event `gate_request`, with this token's `action_hash`. |
| C18 | `internal/merkle` can verify untrusted proofs | Found by tests and fuzzing in step 1: `merkle.Verify` **panics** on a proof shorter than the tree needs (unchecked index), and `splitPoint` **never returns** for sizes above about 2^62 (int overflow). The witness is not exposed (`witness prove` only checks proofs it just built), but a token is attacker-supplied. | `witnessproof` refuses heads above 2^48 records and proofs of the wrong length before calling `merkle`; regression tests and `FuzzVerify` pin both. **`merkle` itself is now hardened:** `Verify` rejects a path of the wrong length before indexing it, and `splitPoint` works on unsigned 64-bit sizes, so any `uint64` size terminates. Both failing fuzz inputs are kept as seeds, and `FuzzVerifyAdversarial` runs in CI. The `witnessproof` prechecks stay as defence in depth. |
| C15 | Witness runs as user `witness` | `packaging/witness-service.sh` does, but older USB installs ran it as **root**. | Feed file mode `0640 gate:witness`. With a root witness, root reads it anyway. Documented in gate-ops.md. |
| C19 | Reason codes cover every deny | A malformed request, or one whose `ts` is far from the gate clock, had no code. | `REQUEST_INVALID` (same name as the gateenforce refusal). `ts` must be within `request_max_skew` (default 5 min) of the gate clock; this bounds C20's memory. Step 3. |
| C20 | One approval, one action | Nothing stopped the gate issuing **several tokens for one `action_hash`**. Each token has its own `token_id`, so the enforcement point's replay cache passes all of them: one pair of approvals could release the same withdrawal many times. | The gate admits an `action_hash` once. While its reservation is pending or after its token is issued, the same request is denied `REQUEST_REPLAYED`; after a refund (deny, timeout) it may be decided again. Entries are forgotten once the request's `ts` falls outside `request_max_skew`, when the request would be refused anyway. Step 3. A matching `action_hash` replay cache in `gateenforce` would be defence in depth; it is a contract change and is listed under follow-ups. |
| C21 | Soul escalation: warn / escalate / halt | The brief says what halt does (trip) but not escalate. | At `escalate_at`, every request in a covering scope needs operator approvals (`BREAKER_ESCALATE`, Escalate outcome), automated classes included. It tightens and never allows. Warn is reported only. Step 3. |
| C22 | Feed-derived events feed "edge learning" | Learning an edge from a feed **loosens** future decisions: a forged feed line (A1) would mark `laptop → wallet-svc` as known before the attack. | Edges are learned only from tokens the gate actually issued (so a new edge needs one approved request) and, in a class's explicit `edge_mode = "learn"`, from the requests themselves, each reported in the decision for the feed. Feeds still tighten. Step 3. |
| C23 | "Token buckets" per class, principal, destination, asset and global | A refilling token bucket gives no exact bound on what can leave inside a window. | Budgets are **sliding-window sums**: inside any window of the configured length, admitted value never exceeds the cap, which is the property acceptance 2 and 18 assert. Values are exact (`big.Rat`), never floats. Assets carry an operator-set `ref_value` (a constant in the signed policy, never a live price) that weights them in the global budget. Step 3. |
| C24 | `gate reset sign --scope ... --epoch N` produces a partial | Each operator signing independently would sign different nonces and timestamps, and partials over different messages never add up to a quorum. | `gate reset new` writes the one Reset everybody signs (scope, epoch, reason, a fresh nonce); `gate reset sign RESET` produces each partial; `gate reset submit RESET PARTIAL...` sends the bundle. Step 4. |
| C25 | Commit-wait: embed the head and the leaf's inclusion proof | `merkle.Prove` rehashes every leaf: about 1.7 s per proof on a million-record log, inside every commit-wait decision. | The evidence view caches the root of every complete aligned subtree (one hash per leaf) and builds RFC 6962 audit paths from it in O(log² n). Checked equal to `merkle.Prove` for every leaf of every tree up to 130 leaves, and accepted by `witnessproof`. Step 4. |

## 3. Trust model

- **Feeds are only as trustworthy as the host's file permissions.** Root on a
  host can write any feed on it (A1). So nothing read from a feed can allow
  anything.
- **ALLOW roots must authenticate themselves**, checkable without any feed:
  - **Approval:** an operator ed25519 signature (PIV preferred) over
    `action_hash`, from `/etc/gate/trust/operators.txt` (`<label> <hex>`), with
    an expiry.
  - **Automated envelope:** class limits declared in the **signed** policy
    (class, max per-action value, destination rules, budgets). The policy
    signature is the root.
- **Feed-derived events** (pipelock, sbh, drift, anomaly, lifecycle, custom
  feeds) drive only **tightening** rules, edge learning and breaker triggers.
- **Witness evidence** counts only after the root is recomputed, the head
  signature checks against **pinned** witness keys, and the append-only check
  against every head the gate has seen passes.
- Production topology: the gate and the witness it reads run on the **signer
  host** or a dedicated host, never on developer endpoints. Callers reach the
  gate over a unix socket with an `SO_PEERCRED` uid allowlist. Remote callers
  use mTLS, only when explicitly configured.

## 4. Formats (`internal/gate/proto`)

Signed structs are Go structs with fixed field order, encoded with
`encoding/json` (`SetEscapeHTML(false)`, no trailing newline). No maps, no
floats: every number that is not a small counter is a decimal **string**.
Decoders reject unknown fields. Every signature input is
`"<domain>\n" ‖ canonical(struct without sig)`.

| Type | Fields | Signature / hash |
|---|---|---|
| ActionRequest | `v, class, target, asset, amount (decimal string), destination, request_nonce (16 B hex), principal, origin_host, ts` | `action_hash = SHA-256("kiss-gate/action/1\n" ‖ canonical)`. SHA-256 so external HSMs and signers can compute it. BLAKE3 stays inside the Merkle log. |
| Approval | `v, action_hash, approver_label, expires_at, sig` | operator key over `"kiss-gate/approval/1\n" ‖ …`. A decide request carries a **list**; the policy's per-class `approvals_required` (default 1) counts distinct operator keys, so two labels for one key count once. |
| Token | `v, token_id (16 B random hex), action_hash, issued_at, expires_at, breaker_epoch, policy_hash, witnessed? {head {size, root, sig, signer_key}, leaf_index, entry, proof[]}, gate_key, sig` | gate key over `"kiss-gate/token/1\n" ‖ …`. Default lifetime 30 s; a lifetime over 120 s is malformed whatever the signature. **Head signature added (C1); entry carried (C17).** |
| Epoch | `v, epoch, open_scopes[{kind, value}], issued_at, gate_key, sig` (`open_scopes` is never null; an unknown scope kind freezes everything) | gate key over `"kiss-gate/epoch/1\n" ‖ …`. Enforcement points cache it for `max_age` (default 10 s). |
| Reset | `v, scope, new_epoch, reason, nonce, ts` + `[]PartialSig{operator_label, sig}` | each operator over `"kiss-gate/reset/1\n" ‖ canonical(Reset)` |
| Policy signature | `SoulSig` envelope (`algorithm, signer_key, signature, signed_at`) | over `"kiss-gate/policy/1\n" ‖ file bytes` (C12) |

Decoders accept only the canonical encoding (no whitespace, reordered or
case-folded keys, duplicates, unknown fields or trailing bytes), so one value
has exactly one accepted spelling. `TestActionHashGolden` pins the
`action_hash` of a fixed request (cross-checked with `sha256sum`); changing it
means a format version bump.

`policy_hash = SHA-256(policy file bytes)`. `amount` is a non-negative decimal
string with no exponent, compared as integers in the asset's smallest unit (the
policy declares `decimals` per asset). It is never parsed as a float.

**Enforcement point checks (`pkg/gateenforce`):** signature by the pinned gate
key; not expired (with allowed skew); `action_hash` equals the hash of the
*exact* request about to run; `token_id` not seen before (cached until expiry);
`breaker_epoch ≥` the newest **fresh** signed Epoch, and the token's scope is
not open in it. For commit-wait classes (`witnessproof`): the inclusion proof of
`witnessed_leaf_index` checks against `witness_head`, and the head signature
checks against the **pinned witness key**. Any failure means refuse, and write
a refusal line to the service's own feed. Refusal codes (stable):
`TOKEN_INVALID, TOKEN_EXPIRED, ACTION_MISMATCH, TOKEN_REPLAYED, EPOCH_STALE,
EPOCH_SUPERSEDED, SCOPE_FROZEN, COMMIT_WAIT_MISSING, COMMIT_WAIT_INVALID,
REQUEST_INVALID`. A token is marked used only after every other check passes,
so a refusal for a reason that later clears (no epoch yet) does not burn it.
`UpdateEpoch` refuses an epoch older than the one held, one from an unpinned
key, and one issued in the future.

## 5. Evidence view (`internal/gate/evidence`)

1. **Bootstrap:** `store.ExportDir(dir, key, Filter{})` followed by
   `store.VerifyExport(x, pins, persistedPriors)`. Any error is
   `CHAIN_UNVERIFIED` and trips the Global scope.
2. **Incremental**, polled every `poll_interval` (default 1 s) through a new
   read-only helper:

   ```go
   // ReadSince returns the stored head and the records after byte offset off
   // that the head covers, plus the offset just past the last one. It opens the
   // log O_RDONLY, never writes, renames, truncates or creates, and is safe
   // beside a running writer (head read first, as readCommitted does).
   func ReadSince(dir string, key []byte, off int64, have uint64) (TreeHead, []Entry, int64, error)
   ```

   Built (step 2) as `store.ReadSince(dir, key, off, have)`, plus two pure
   helpers: `store.LeafHash` and `store.VerifyHeadSignature`, and the sentinels
   `ErrHeadBehind` / `ErrLogShort`. A separate `readLogFrom` leaves the daemon's
   `readLog` untouched. Tests prove the no-mutation property (names, modes,
   sizes, mtimes, inodes and content hashes identical before and after, with an
   uncovered record and a torn frame present; still works on a read-only
   directory) and contiguity beside a live writer.
3. **Accept a head** only if: signed by a pinned key; `Size ≥ lastSize`;
   `Root == Root(cached ‖ new)`; `Size == len(cached) + len(new)`. Anything else
   is `CHAIN_UNVERIFIED` and trips Global. The same size with a different root
   is a rewrite. The root is kept incrementally: a frontier of the perfect
   subtrees on the tree's right edge, O(log n) per record, checked against
   `merkle.Root` for every size up to 300. The failure is sticky: the view
   never clears it itself.
4. **Freshness:** `head_age = now_mono − time the gate first verified a head
   larger than the previous one`. `head.ts` is shown but never trusted (C1).
5. **Periodic full re-verify** (default every 10 min, and at every start): the
   bootstrap path again, checked against the retained priors.
6. **State tracked:** last verified head and its age; per-source last-seen
   (silence); CRITICAL/WARN counts by `(source, event)`; drift events; SBH
   decisions and escalations; pipelock verdicts (parsed from the payload with
   the bridge's precedence, because WARN also covers plain `warn` verdicts);
   edges from custom feeds; the gate's own records by `request_id`.

## 6. Decision flow

Service → gate: `POST /v1/decide {ActionRequest, Approval?}` over the unix
socket returns `Allow{token}`, `Deny{reasons}` or `Escalate{action_hash}`.

1. **Synced?** The evidence view is verified and caught up, and the breaker
   state is rebuilt. Otherwise `GATE_NOT_SYNCED`.
2. **Breaker:** is any scope covering (class, principal, origin_host,
   destination, asset, global) open? `BREAKER_OPEN`.
3. **Root:** a valid Approval (manual classes) or inside the signed envelope
   (automated classes). Otherwise `NO_ROOT` (Escalate), `APPROVAL_INVALID`,
   `APPROVAL_EXPIRED` or `OUTSIDE_ENVELOPE`.
4. **Evidence health:** `head_age ≤ head_max_age`; no unacknowledged CRITICAL
   since the last reset inside the window (`witness_downtime`,
   `mirror_unreachable`, `mirror_not_configured` / `mirror_misconfigured` in
   production); mirror health within policy. Otherwise `EVIDENCE_UNHEALTHY`,
   `ANCHOR_STALE` or `CHAIN_UNVERIFIED`.
5. **Tightening signals** inside the lookback: `drift_detected` (`DRIFT_ON_HOST`),
   `sbh_decision:stop_and_ask` / `sbh_escalation` and pipelock block verdicts
   (`ADVISORY_DENY`), first-seen edge for protected classes (`FIRST_SEEN_EDGE`).
   Each leads to Deny or Escalate per policy, never Allow.
6. **In-flight caps, then an atomic budget reservation.** Over the per-class,
   per-principal or per-origin_host in-flight cap: immediate `INFLIGHT_LIMIT`
   plus a breaker tick. Otherwise, under **one lock**, debit every applicable
   bucket (class, principal, destination, asset, global value-per-window). If any
   one fails, debit none: `VELOCITY_EXCEEDED` plus a breaker trigger. Never
   check now and debit later.
7. **Write the decision** to the gate feed (fsync before any Allow). On error:
   `FEED_WRITE_FAILED`, refund, deny. If `class.commit_wait`: wait (bounded by
   `commit_wait_timeout`, default 10 s) until a pinned, verified head covers the
   `gate_request` record, then `COMMIT_WAIT_TIMEOUT` (refund + breaker tick on
   `witness_unhealthy`) on timeout.
8. **Re-validate** (commit-wait classes; cheap, so run for all): repeat steps 1,
   2, 4 and 5 against the *current* view. Any change means `REVALIDATION_FAILED`,
   refund, record. **The wait doubles as a detection window, on purpose.**
9. **Sign and return** the token (the head plus leaf index and inclusion proof
   when commit-wait applies).

Refunds happen on every deny, timeout or cancel after step 6. Steps 1–6 and 9
run from memory, with a p99 target under 10 ms excluding fsync. The fsync cost
of step 7 and the commit-wait latency are **measured and reported, not hidden**.

**Reason codes (stable enum):** `GATE_NOT_SYNCED, BREAKER_OPEN, NO_ROOT,
APPROVAL_INVALID, APPROVAL_EXPIRED, OUTSIDE_ENVELOPE, EVIDENCE_UNHEALTHY,
CHAIN_UNVERIFIED, ANCHOR_STALE, DRIFT_ON_HOST, ADVISORY_DENY, FIRST_SEEN_EDGE,
VELOCITY_EXCEEDED, COMMIT_WAIT_TIMEOUT, FEED_WRITE_FAILED, POLICY_INVALID,
INFLIGHT_LIMIT, REVALIDATION_FAILED,
REQUEST_INVALID, REQUEST_REPLAYED, BREAKER_ESCALATE` (the last three from C19–C21).

**As built (step 3, `internal/gate/core`).** Steps 1 and 2 short-circuit.
Step 3 denies outright on a forged or expired approval or a request outside the
envelope; a missing approval is only *noted* (`NO_ROOT`), and steps 4 and 5 still
run, so a request that would be denied anyway is denied rather than sent to a
human. Escalations from step 5 (and C21) are satisfied by the class's
`approvals_required` valid approvals, for automated classes too. The in-flight
caps are checked **before** an Escalate answer: a caller already at its cap
keeps getting `INFLIGHT_LIMIT` and keeps ticking toward a trip even once its
tick level makes every other answer an escalation (found by the acceptance-22
test). Denies the caller caused (`APPROVAL_*`, `OUTSIDE_ENVELOPE`,
`ADVISORY_DENY`, `FIRST_SEEN_EDGE`, `DRIFT_ON_HOST`, `REQUEST_REPLAYED`) tick
`deny` on its principal and origin host; denies caused by the gate's own state do
not, so one incident cannot cascade into trips on every caller.

Signals are applied relative to the latest quorum reset covering the request: a
signal at or before it was in front of the operators who signed the reset, so it
no longer counts against health, tightening, or re-ticking the breaker. Advisory
records (SBH, pipelock) apply to the principal named in their data (`principal`
or `agent`, top level or under `detail`); a record that names nobody applies to
every principal on the host.

## 7. Breaker (`internal/gate/breaker`)

- **Scopes:** Global, Class, Principal, OriginHost, Destination, Asset.
  Open → Closed **only** by a quorum Reset. There is no half-open state and no
  timer.
- **Ticks:** weighted per trigger with warn/escalate/halt thresholds, the soul's
  escalation model. Halt trips the narrowest scope that contains the trigger.
  **Global trips only** on `CHAIN_UNVERIFIED`, an append-only failure, or a gate
  self-check failure.
- **Triggers** (configurable, with defaults): VELOCITY_EXCEEDED; N denies per
  principal or host in a window; CHAIN_UNVERIFIED (Global); `DEATH
  signal_received` with no `daemon_start` inside the window; CRITICAL
  `witness_downtime`; `mirror_unreachable`; `tree_head_unsigned` after signing
  was established; `drift_detected` (the classes of the gate's own host);
  `sbh_escalation` (principal); COMMIT_WAIT_TIMEOUT ×N (affected classes);
  INFLIGHT_LIMIT ticks (principal / origin_host); self-check failure.
- **Which scope each trigger ticks** (fixed in code, so a policy cannot point a
  noisy trigger at Global):

  | Trigger | Scope ticked | Default weight |
  |---|---|---|
  | `chain_unverified`, `self_check` | Global (trips at once) | 10 |
  | `velocity_exceeded` | the bucket's own scope; the class for class and global buckets | 10 |
  | `deny`, `inflight_limit` | the caller's principal and origin host | 1, 2 |
  | `commit_wait_timeout` | the class | 4 |
  | `sbh_escalation` | the principal named in the record (no tick if none) | 10 |
  | `drift_detected`, `witness_downtime` (CRITICAL), `witness_death` (no `daemon_start` within `head_max_age`), `mirror_unreachable`, `tree_head_unsigned` | every class (one witness = this host, C7) | 10 |

  `chain_unverified` must weigh at least `halt_at` (policy validation). Signals
  older than the breaker window never tick, so replaying a day of log at restart
  cannot re-trip a scope.
- **On trip:** stop issuing in that scope, bump the epoch, serve the new signed
  Epoch, write `breaker_trip` to the gate feed, then call the `TripAdapter`. The
  adapter is log-only, or an exec hook running an operator-owned script. There
  are no built-in infrastructure killers.
- **Reset:** each operator runs `gate reset sign --scope S --epoch N`, which
  writes a partial. `gate reset submit partials…` verifies M-of-N distinct
  operators from operators.txt, an unused nonce and `new_epoch == current+1`,
  then writes `breaker_reset`. A nonce is spent once it appears in the gate feed
  or the verified log.
- **Restart:** see C14. The gate reports `GATE_NOT_SYNCED` until the rebuild
  finishes. As built: a scope is open if its newest trip epoch is not below its
  newest counted reset epoch (a tie stays open); every reset nonce seen anywhere is
  spent; the epoch is the highest seen; and only a reset that actually closed its
  scope counts as acknowledging earlier signals. Tick totals are not restored:
  they only ever lead to a trip, and trips are.

## 8. Policy (`internal/gate/policy`, `examples/gate-policy.toml`)

TOML (BurntSushi/toml, already a dependency), strict decode (undecoded keys are
an error). A detached `.sig` is verified against `/etc/gate/trust/operators.txt`.
Unsigned, invalid or failing validation: start in **deny-all** and record
`POLICY_INVALID`. Reloads happen only on SIGHUP and only with a valid signature;
a bad reload keeps the old policy and records `POLICY_INVALID`. Per class: tier
(low|high), root kind (approval|automated_envelope), envelope limits, budgets,
in-flight caps, tightening rules and actions, `commit_wait`,
`commit_wait_timeout`, fail mode (high is always closed), lookbacks, edge rules
(learn mode explicit and logged). Global: pinned witness keys, `head_max_age`,
`witness_drift_interval_sec` (C9), mirror tolerance, quorum M/N, tick weights
and thresholds, assets with `decimals`.

**Approvals per class:** the brief had single-signer approvals, so one
compromised operator token (A8) could approve a manual-class withdrawal. The
formats (step 1) carry a list of approvals, and the policy sets a per-class
`approvals_required` (default 1, **recommended 2 for withdrawals**). The number
is a policy choice for the operator; no format change is needed either way. **Decided 2026-11-03: two.** An unset
`approvals_required` defaults to **2**; a single-approver class must say
`approvals_required = 1` explicitly. `examples/gate-policy.toml` sets 2 on both
withdrawal classes. A policy whose `approvals_required` or `reset_quorum`
exceeds the number of distinct operator keys is refused at load, since every
request in that class would otherwise escalate forever.

As built, validation also refuses: an automated envelope without an explicit
destination list (`"*"` is allowed only for approval classes); an automated
value-moving class without `max_value`, a class budget and a global budget;
`fail_mode = "open"` on a high-tier class; a token lifetime over 120 s; an asset
used by a class but not declared; an unknown breaker trigger; and decimal values
in any form other than plain digits (`1e6` is refused).

## 9. Process isolation and deployment

- Own binary `cmd/gate`, own system user `gate`, own signing key (signer
  package: PIV slot from C13 / software / `--dev`), own config dir `/etc/gate`,
  own state dir `/var/lib/gate`.
- Read access: `gate` joins group `witness` for `primary/` (0750), the same
  model as the enforcer.
- Write access: **only** `/var/lib/gate/gate.jsonl` (`0640 gate:witness`), plus
  its own state and key files.
- Witness config (config only, no code change): add
  `{"path": "/var/lib/gate/gate.jsonl", "source": "gate"}` to `event_feeds` and
  create the file empty **before** the witness first starts. Protected services
  get their own feeds (e.g. `wallet-svc`).
- Import boundaries (`tests/importboundary_test.go`): `cmd/witness` ↛
  `internal/gate/*`, `cmd/gate`, `internal/enforcer`; gate packages ↛
  `internal/enforcer`.

## 10. Dependencies

None new. BurntSushi/toml (policy), lukechampine.com/blake3 (witnessproof
only, C11), stdlib for everything else. CGO stays off. The PIV path stays behind
the existing `piv` build tag.

## 11. Measurements

Step 2 (LAB box, i3-class 4 threads, Go 1.25, `go test -bench`, 10 runs):

| Operation | 50,000-record log |
|---|---|
| Evidence poll, one new record (`ReadSince` + frontier + signature) | **0.46 ms** |
| First full verify at gate start (bootstrap) | **455 ms** |

Step 3 (Intel N95, 4 threads, `BenchmarkDecide`, 20,000 decisions with 10,000
signals indexed and 1,000 known edges): decision logic (steps 1–6 plus release,
no fsync, no signing) **p50 9 µs, p99 30 µs**, against the 10 ms target.

Step 4 (same box, `internal/gate/daemon` tests, real witness store and the real
event-feed bridge tailing the gate feed): one commit-wait decision over the unix
socket, from request to signed token with inclusion proof, took **237 ms** with
the gate polling every 50 ms. That is the witness tailer's 200 ms EOF sleep
plus one poll, as C9 predicted; at the 1 s default poll expect up to about
1.2 s. A proper p50/p99 at both settings is step 5.

**Witness-side observation (not changed here):** `store.Append` rewrites the
head with `merkle.Root` over the whole log on every record, so each append costs
O(n). Building a 50,000-record log through it took over 10 minutes in a
benchmark; on a log of a million records each append rehashes all of them. The
frontier used by the gate would make it O(log n). Listed under follow-ups.

## 11a. The daemon as built (step 4)

`internal/gate/daemon` (with `cmd/gate` a thin CLI over it):

- **Socket API** (HTTP over a unix socket, mode 0660, every connection's
  caller uid checked with `SO_PEERCRED` against the gate's own uid plus
  `allowed_uids`; off Linux every caller is refused): `POST /v1/decide`
  (canonical request plus approvals), `GET /v1/epoch` (re-signed on every poll),
  `GET /v1/status`, `POST /v1/reset` (a canonical quorum bundle). Bodies are
  capped at 64 KiB and decoded strictly.
- **Feed records** (all values strings, each fsynced): `gate_start`,
  `policy_load` / `policy_invalid`, `breaker_restored`, `gate_decision` (every
  outcome), `gate_request` (the commit-wait leaf), `gate_issued` (key use, written
  before the token leaves), `gate_edge_learned`, `breaker_trip`,
  `breaker_reset`, `breaker_reset_rejected`, `gate_stop`. Both issuing writes
  guard: if either fails, the reservation is refunded and no token leaves. A
  failed write is sticky; the gate issues nothing until restarted with a
  working feed.
- **Startup never refuses**: a missing or invalid policy, missing operators or an
  unwritable feed leave the gate running in deny-all, saying why in `status`
  and (where it can) in the feed. Until the first verified poll and the breaker
  rebuild, every decision is `GATE_NOT_SYNCED`.
- **Restore** (C14) reads `breaker_trip` / `breaker_reset` records from the
  verified log (the evidence view keeps these for the life of the process,
  outside the 24 h signal lookback, so an old reset still counts) and from the
  local feed file. Tested both ways round: a trip only in the local feed and a
  trip only in the verified log (local feed deleted) each survive a restart.
- **State** (`state.json`, 0600, written atomically): retained witness heads and
  known edges. Neither can loosen the breaker.
- **Self-check**: the gate key must sign and verify a test message at start;
  a token that fails to sign trips Global (`self_check`). A reset whose record
  cannot be written re-trips its scope.
- **Reload**: SIGHUP, only with a valid signature. A reload cannot re-pin the
  witness keys; that needs a restart, and the gate says so.
- **Gate key**: the software signer (`signing.key` in `key_dir`). The PIV slot
  option (C13) is deferred: the PIV build needs a module this tree does not
  carry, so the change could not be compiled or tested here.

## 12. Follow-ups (documented, not built)

- Witness feed tailer: a feed file created between the tailer's failed open
  and its stat is treated as pre-existing and read from its end, dropping its
  first lines. Deployment avoids it (create `gate.jsonl` before the witness
  starts, as event-feeds.md says); fixing the tailer is a witness change.
  Found by a second Claude session reviewing step 4.
- `signer.NewPIVSlot(slot)` for a gate key on a hardware token beside a PIV
  witness (C13), built and tested where the PIV module is available.

- Enforcer writes gossip peer state (`SILENT` / `PRESUMED_COMPROMISED`) to an
  enforcer-owned feed, so the gate can trip on peer death.
- A freeze relay over gossip, signed by the gate key, for multi-host enforcement.
- `TailReader`: compare the recomputed root with the signed head and pins, and
  stop swallowing read errors (C5).
- Gate reading more than one witness (multi-host evidence, C7).
- A Rust or other-language `gateenforce` port from section 4.
- `gateenforce`: also cache used `action_hash` values until token expiry, as
  defence in depth behind C20 (a contract change).
- Witness `store.Append` is O(n) per record (section 11): keep a frontier instead of rehashing every leaf.
- ~~Harden `internal/merkle` against untrusted input (C18).~~ Done: `Verify` checks the exact path length and `splitPoint` is overflow-safe for all `uint64` sizes. The `witnessproof` size and path prechecks stay as defence in depth.
- A domain-separated tree-head signature input in a future log format (C1). This
  is a witness format change, so it is out of scope here.
