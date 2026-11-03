# Death records

New deaths create mode-0600 `death_<UTC time>_<unique>.json` files in the primary
directory, format `witness-death/2`. The reader/checker also accepts
`witness-death/1`. Neither the encrypted log nor genesis is copied. Existing
records and legacy full copies are never rewritten or removed. Operators may
archive old copies according to their evidence policy; there is no automatic
cleanup. Keep linked JSON records together: removing a referenced record breaks
offline chain verification.

Each record preserves the stored `tree-head.json` object, timestamp, trigger,
machine ID, captured `log_bytes`, and genesis SHA-256. Invalid/missing heads are
reported as `tree_head_error`, without inventing a replacement. The byte length
is captured before hashing; appends after that length are excluded. Genesis is
still hashed each time and is never changed or copied.

## Incremental hashes and exact encoding

The writer considers `death_*.json` in lexicographic filename order (not mtime or
JSON timestamp), choosing the newest parseable supported record. Unreadable,
oversized (over 1 MiB), malformed, unsupported or structurally invalid candidates
are listed in `skipped_records` with filename and reason. Skipping newer invalid
records forces a full-hash reset even if an older valid record exists.

`prev_record` contains `name` and `sha256`: the SHA-256 of the exact previous JSON
file bytes, including whitespace and the trailing newline. It is kept on resets
as well as incremental records when a parseable predecessor is available.

Before extending a complete /2 predecessor, the writer hashes the previous
region's tail `[max(0, prev.log_bytes - 1048576), prev.log_bytes)` and compares it
with that record's `tail_sha256`. If it matches, `hash_mode` is `segment` and:

- `segment_start = prev.log_bytes`.
- `segment_sha256 = SHA256(log[segment_start:log_bytes])`.
- `chain_sha256 = SHA256(P || S || N)`.

Here `P` is the previous `chain_sha256` for a segment record, or previous
`log_hash.sha256` for a full-hash anchor. `P` and `S` are decoded raw 32-byte
digests, **not** their 64-byte hexadecimal text. `S` is `segment_sha256`.
`N` is the current nonnegative `log_bytes` encoded as an unsigned 64-bit
big-endian integer. The input is exactly 72 bytes with no delimiter, newline or
domain prefix. JSON digests are lowercase hexadecimal. An empty segment uses
SHA-256 of the empty byte string and still creates a new chain value.

In segment mode `log_hash` carries the operation's `status`/`error` only; it has
no `sha256`, because a chain digest is not the SHA-256 of the whole log. On
success, `segment_sha256` and `chain_sha256` contain complete digests. In full
mode, `log_hash.sha256` hashes `[0, log_bytes)` and starts a fresh anchor;
segment and chain digests are absent. The full anchor is the input `P` for the
next successful segment record.

Every /2 record attempts to save its own last 1 MiB in `tail_sha256`; `tail_hash`
records that operation's status/error and, on success, the same digest. Empty
logs have the empty-string digest. The tail must be available for a future
incremental extension. `genesis_hash` has the same hash-result structure.

## Fallbacks, deadlines and atomicity

`fallback_reason` explains a full-hash reset: no previous record, skipped invalid
records, incomplete/error previous hash, missing previous tail, /1 handover,
changed machine ID, broken predecessor link, failed tail read, or tail mismatch.
A /1 predecessor always causes one full /2 anchor before incremental operation
can resume. A smaller log sets `log_shrank: true`. A successful previous-tail
read with a changed digest sets `prefix_changed: true`. These are evidence of
changed history, not permission to ignore the old records. A current tail read
is attempted on resets too; complete anchors can resume chaining afterward.

Hash results are `complete`, `incomplete` when the shared deadline expires, or
`error`. Incomplete/error results never contain partial digests. Hashing uses
64 KiB buffers and a shared 7.5-second budget inside the 8-second death budget,
with genesis first. A segment that times out has neither `segment_sha256` nor
`chain_sha256`; the next death falls back to full hashing. An already expired
budget may prevent history selection or tail hashing; the record still contains
the head and length, hash statuses, and the fallback reason. Missing log/stat
evidence is recorded as an error (`log_bytes: -1`).

Atomic publication is unchanged: write a hidden temporary file, fsync, close,
rename to the final JSON filename, then fsync the directory. Final filenames
always contain complete JSON. Hash workers never write files, even after a
cancelled read. Ordinary write errors clean up temporary files; forced kill or
power loss may leave a hidden temporary file, never a partial final JSON.
Filesystem syscalls blocked in the kernel cannot have a portable hard deadline;
publication remains synchronous rather than abandoning writes mid-file.

## Offline checker

```bash
witness verify-death /path/to/primary
witness verify-death --log /path/to/retained/witness.log /path/to/primary
```

The checker walks filename order, reports malformed files, checks exact-byte
`prev_record` links against the immediately preceding parseable record, validates
segment bounds and eligibility, and recomputes chain arithmetic. With `--log` it
also reads each recorded full prefix/segment and each /2 tail directly using
read-only file operations. It never opens the log through the daemon's store
code and never writes files. This can be expensive across many full anchors.

Exit 0 means the selected checks succeeded; exit 1 means a malformed/broken link,
hash mismatch, incomplete/error log hash, unavailable tail, or read failure.
Shrink/prefix-change flags are printed as warnings; a full reset can be internally
consistent, while `--log` will fail older records whose captured bytes no longer
match. With no `--log`, only record links and chain arithmetic are checked, not
the encrypted bytes. Genesis bytes and Merkle signatures are not verified by
this command. Retain the original genesis and verify trusted signed heads with
the established Merkle verification tools.

## Limits of the evidence

The tail check only detects changes inside that 1 MiB tail. Older prefix bytes
can change without setting `prefix_changed`. The signed Merkle head, checked
against a trusted pinned signer and the retained log prefix, remains the proof
of the **whole** prefix. A chain digest is not a full-log SHA-256, a new signature,
a standalone backup, or proof against replacement of the whole local history.

No local filename scan can detect a removed newest record when no surviving
record references it. A missing/corrupt referenced predecessor triggers a writer
reset and a checker failure; detecting removal of an unreferenced newest file
requires an externally retained record/reference. Likewise a clock rollback or
concurrent writers can create non-linear filename/link order, which the checker
reports rather than silently treating it as one chain. Head, length and hash
reads are separate; concurrent writes/tampering may create inconsistent evidence.
Keep external trusted heads and records for independent comparison.

## Daemon and watchdog on stop

The daemon records a death for signals/storage anomalies. The watchdog polls
parent liveness every two seconds and records `watchdog_parent_exit` after parent
death, without distinguishing clean exits. `Setsid` separates its session, not
its systemd cgroup. The shipped `witness.service` does not override systemd's
default `KillMode=control-group`, so a normal `systemctl stop` signals the daemon
and watchdog together; the watchdog has no signal handler and terminates. A
second watchdog death record is therefore not expected for that shipped unit.
This is a code/unit review, not a live test on the OptiPlex.

Outside that unit (or with `KillMode=process`), a surviving watchdog can record
a second death after a clean daemon exit. This behavior is unchanged: robust
suppression needs a parent/watchdog shutdown protocol, not a global marker that
could suppress evidence from a later process. Unique filenames keep simultaneous
records from overwriting each other.
