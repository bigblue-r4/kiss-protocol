# Design: `witness accept` — approving known drift

Status: **BUILT** (`internal/accept`, `cmd/witness/accept.go`). Decisions in §6 were taken as recommended (2026-11-01). §7 is how to use it.

## 1. Problem

Drift compares the live machine against the genesis snapshot on every tick
(30 s) and logs every difference, every time. Once an operator knows a change
is legitimate, it keeps being reported forever. On the OptiPlex test box on
2026-10-31, each tick reported 14–16 changes, all known:

| Change | Why |
|---|---|
| `/etc/passwd`, `/etc/shadow`, `/etc/group` | `sbh` user created after genesis |
| `/usr/bin/snap`, `snapctl`, `snapfuse` (+ the same 3 under `/bin`) | snapd auto-refresh, 18:48 |
| new processes `pipelock`, `ollama`, `split-brain-har`, `dbus`, `gdm-wayland-ses` | services/session started after genesis |

A real change would be one more line in that list, once every 30 s, in
thousands of identical drift entries (2,901 of 4,519 entries were DRIFT).

## 2. Non-goals

- **Not a re-baseline.** Genesis stays as-is: it is the signed record of the
  machine at install, and replacing it would erase the evidence of what
  changed since. (`init` refuses to overwrite it, and must keep refusing.)
- **No wildcards or path globs.** "Accept anything under /usr/bin" is the hole
  an attacker would use.
- Not the per-tick delta logging idea (log a change once, not every tick).
  That is separate and could follow.

## 3. Design

### 3.1 What an approval is

An approval pins **exact** observed values:

```json
{"type":"file_changed","path":"/usr/bin/snap","new":"726468b8…"}
{"type":"new_process","process":"ollama","path":"/usr/local/bin/ollama"}
```

A file approval matches only that path **with that hash**. If snap refreshes
again, the new hash is not approved and drift reports it again. That is the
key property: an approval covers one known state, not a file for all time.
(`file_removed` and `file_mode_changed` are approved the same way, by path +
observed value, and so is `file_added`, a file that appeared in a watched
directory after genesis: path + its hash, or `unreadable` if the witness
cannot read it.)

New Linux process drift records the command name and the executable target read
from `/proc/PID/exe` in `path`. An approval with both fields matches only that
name and exact resolved path. Different executables with the same name are
reported separately, so approving `/opt/pipelock` does not hide `/tmp/pipelock`.
The CLI displays the path before signing. The procfs target is used directly,
including any ` (deleted)` suffix; it is not inferred from the command name or
looked up through PATH. If the target cannot be read (permissions or process
exit), drift still reports the name without a path, which cannot match a pinned
approval. Unsupported platforms likewise retain name-only observations.

Existing name-only approvals still load, verify and match that name at any path.
They are intentionally broad for backward compatibility: revoke an old name-only
approval and approve a newly observed name+path item to get path pinning. Existing
signed payloads and request version 1 are unchanged. New genesis snapshots also
record optional process identities as described below; existing snapshots retain
their original name-only baseline. A path pin is not a content hash: replacing a
binary at the same path is covered by file drift, not this process approval.

#### Process identity at genesis

New snapshots record `process_identities`: distinct `(name, path)` observations
from the same collector and pass used for drift, alongside the existing `procs`
name list. Paths are the `/proc/PID/exe` targets where readable. An empty path is
an explicit unavailable observation, not a wildcard. With an identity-aware
baseline, a same-name process at a different path is `new_process` drift; losing
path visibility or gaining visibility after an unavailable baseline is also a
new observation. A name may have several baseline executable paths.

The optional top-level field is omitted when empty. Old snapshots without it
retain their exact serialized bytes, integrity hashes, and name-only comparison.
Installing a newer binary does not add identities to an existing genesis or
change epoch 4. No genesis rewrite or epoch action is part of this code change.

Run `witness init` as the same user as the witness daemon, with the same `/proc`
visibility and service permissions. Root initialization followed by a uid-999
service can baseline executable paths the service cannot read, causing persistent
false process drift. The operator epoch scripts already initialize as the witness
user; installing this change does not run init or change an existing genesis.

When a process exits between `ps` and reading `/proc/PID/exe`, ENOENT or ESRCH
causes that observation to be dropped rather than inventing a name-only identity.
EACCES or EPERM keeps a name-only observation because visibility was refused.
Other failed or invalid executable lookups also retain a name-only observation,
so unexpected errors cannot hide a live process. Only ENOENT/ESRCH drops it;
unsupported platforms retain their name-only collection behavior.

On the OptiPlex, the witness uid 999 has CAP_DAC_READ_SEARCH but not
CAP_SYS_PTRACE. Reading another user's `/proc/PID/exe` may therefore be denied:
its own pipelock process is readable, while llama-server/ollama running as
`ollama` may remain name-only. This implementation does not add capabilities or
change host policy. Legacy broad approvals can still filter new observations;
replacing those approvals is a separate operator step after the witness update.

### 3.2 The log is the source of truth

The approval is written **into the witness Merkle log** as a signed entry:

```
level INFO  event drift_accepted  source operator
data { "by": "<operator key id>", "reason": "snapd auto-refresh 2026-10-31",
       "changes": [ …exact items… ], "request_sig": "…" }
```

At start, the daemon rebuilds its set of approvals by replaying
`drift_accepted` entries from the log. There is no separate state file to
edit or delete: removing an approval would mean rewriting the log, which
verify (and the mirror, once configured) already detects. The approval
history is itself auditable: `witness export --source operator`.

### 3.3 How the CLI reaches the daemon

The store has one writer: the running daemon (it holds the log open; the
CLI must not append concurrently). So `witness accept` does not write the log
itself:

1. `witness accept` reads the latest `drift_detected` entry and lists its
   changes; the operator picks all or some (`--all`, or by index) and must
   give `--reason`.
2. The CLI writes a signed request file to a spool dir,
   `<primary>/accept-spool/<timestamp>.json` (mode 0600, owned by the witness
   user).
3. On the next tick, the daemon checks each request's signature against the
   **operator allowlist**, `~/.witness/trust/operators.txt` (same format as the
   soul allowlist, but a separate file: an operator key approves drift, it does
   not sign tree heads), appends `drift_accepted` (or `drift_accept_rejected` with the
   reason, WARN), adds the items to its in-memory set, and deletes the
   request file.
4. `witness accept` waits up to one tick for the entry to appear and prints
   the seq number.

### 3.4 What drift logs afterwards

`drift.Measure` is unchanged. The daemon filters its result against the
approval set:

- Unapproved changes left → `DRIFT drift_detected` with only those. Its data
  stays a plain list of changes, so existing readers of the log keep working.
- Nothing left → `INFO drift_clean` with `{"approved": N}` (data stays empty
  when nothing is approved).

So the approved drift never disappears from the record, it is just stated as
"N known, approved" instead of re-listed.

### 3.5 Revoking

`witness accept revoke <id>` → `drift_accept_revoked` entry naming the
approval's id; replay drops those items. (Approvals are named by a random id,
not a log seq: other feeds append concurrently, so the seq of an entry is not
known to the writer.) Same spool path, same signature check.

## 4. Threat notes

- Someone who can write the spool dir **and** sign with an allowlisted key
  can hide changes. That is the whole question of §6 Q1.
- Each approval is pinned to a hash, so an attacker cannot reuse an existing
  approval to hide a *different* binary at the same path.
- New-process approvals are by name only (drift tracks names today), so a
  malicious process named `ollama` would be hidden by an `ollama` approval.
  That's a pre-existing limitation of name-based process drift. Approvals
  could be tightened to name + executable hash later.
- An approval of `/etc/shadow` hides later password changes only if the hash
  matches exactly, which it won't: any change re-reports. Good.

## 5. Size

Roughly: `cmd/witness/accept.go` (CLI + spool write), daemon spool pickup +
replay + filter in `main.go`, an `internal/accept` package for the matcher and
request signing/verification, tests for matching, replay, revoke, bad
signatures and the hash-pin property. Similar in size to `export`.

## 6. Decisions (taken as recommended, 2026-11-01)

1. **Who can approve?** (a) Any key in the operator allowlist. On the test box
   that is the witness's own software key, so anyone who can act as the
   `witness` user can approve. (b) Require a **separate operator key**, kept
   off the box (YubiKey/PIV, or a key on the LAB machine), and refuse the
   witness's own key. *Recommendation: (b), and allow (a) only with `--dev`.*
2. **Process approvals by name only for now**, or wait and do name+exe-hash?
   *Recommendation: name only now, noted as a limitation (§4).*
3. **Approval scope across reboots:** keep forever until revoked, or expire
   (e.g. 90 days) so stale approvals resurface? *Recommendation: forever +
   revoke; expiry is easy to add later.*
4. OK to include **revoke** in the first version, or ship accept-only first?

Also built in: the source `operator` is reserved, so an event feed cannot
write an entry that looks like an approval, and replay re-checks each
recorded request (signature, machine id, signer in operators.txt), so an
operator removed from operators.txt loses their approvals at the next start
(recorded as WARN `drift_accept_replay_skipped`).

## 7. Using it

Once, on a machine that is **not** the witnessed one (the LAB box, a stick):

    witness accept keygen --out operator.key     # prints "operator <hex>"

On the witnessed machine, add that line to the witness user's
`~/.witness/trust/operators.txt` (as root; `/var/lib/witness/.witness/trust/`
on a service install).

Then, each time:

    sudo -H -u witness witness accept list                       # numbered drift
    sudo -H -u witness witness accept request --item 1,3 --reason "snap refresh" --out req.json
    witness accept sign --key operator.key req.json              # where the key is
    sudo -H -u witness witness accept submit req.json            # waits for the record

`request ... --key operator.key` signs and submits in one step when the key is
at hand. `revoke ID --reason ...` takes the same `--key`/`--out`.
