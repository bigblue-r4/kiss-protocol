# Death records

New deaths create a mode-0600 `death_<UTC time>_<unique>.json` in the primary
directory, format `witness-death/1`. Neither the encrypted log nor genesis is
copied. Existing `death_*_witness.log` and `death_*_genesis.enc` files are left
untouched. Operators may archive old copies according to their evidence policy;
there is no automatic cleanup. No current code reads the legacy death files.

The JSON contains the stored `tree-head.json` object (including signature and
signer key), timestamp, trigger, machine ID, log byte length, and SHA-256 results
for the captured log prefix and `genesis.enc`. The length is captured before
hashing; later appends are excluded. A truncated/unreadable file produces an
error, not a digest of whatever bytes happened to be read. Missing or invalid
heads are recorded as errors; no replacement head is invented. Genesis is read
and hashed each time, never re-copied or changed.

Each hash has `status`: `complete` with `sha256`, `incomplete` without a digest
when the hashing deadline expires, or `error` with the read failure. Hashing
uses a 64 KiB buffer, with 7.5 seconds of the 8-second death budget available for
hashing (genesis first). Even an expired hashing deadline still publishes the
head and length. Hash workers never write records. The publisher writes a hidden
temporary file, fsyncs and closes it, renames it to the final JSON filename, then
fsyncs the directory. Readers of final filenames see complete JSON. On ordinary
write failures the temporary file is removed. A forced kill/power loss may leave
a hidden temporary file, never a partially written final record. A filesystem
read or fsync blocked in the kernel cannot be given a portable hard time bound;
publication is synchronous rather than abandoned at the deadline.

The copied head commits to log records up to its Merkle size. Verify its signature
against a trusted pinned signer and recompute that prefix's root from the retained
log to detect rewrites. A complete SHA-256 additionally identifies the captured
encrypted bytes; an incomplete hash makes no such claim. These JSON files are
local evidence, not independently signed manifests, standalone log backups, or
proof that a compromised host could not replace both head and log. Retain the
original log/genesis and external trusted heads for later verification. A head
and length are separate reads; unexpected concurrent writes or tampering can
produce inconsistent evidence, which must be investigated rather than treated
as an authenticated snapshot.

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
