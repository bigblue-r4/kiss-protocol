# Design: `witness accept` — approving known drift

Status: **DRAFT, awaiting decisions (§6).** Nothing here is built.

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
{"type":"new_process","process":"ollama"}
```

A file approval matches only that path **with that hash**. If snap refreshes
again, the new hash is not approved and drift reports it again. That is the
key property: an approval covers one known state, not a file for all time.
(`file_removed` and `file_mode_changed` are approved the same way, by path +
observed value.)

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
   **operator allowlist** (the same `soul` allowlist `witness soul sign`
   writes), appends `drift_accepted` (or `drift_accept_rejected` with the
   reason, WARN), adds the items to its in-memory set, and deletes the
   request file.
4. `witness accept` waits up to one tick for the entry to appear and prints
   the seq number.

### 3.4 What drift logs afterwards

`drift.Measure` is unchanged. The daemon filters its result against the
approval set:

- Unapproved changes left → `DRIFT drift_detected` with only those, plus
  `"accepted": N` (count of suppressed items) so the record still shows that
  approved differences exist.
- Nothing left → `INFO drift_clean` with `"accepted": N`.

So the approved drift never disappears from the record, it is just stated as
"N known, approved" instead of re-listed.

### 3.5 Revoking

`witness accept --revoke <seq>` → `drift_accept_revoked` entry naming the
earlier seq; replay drops those items. Same spool path, same signature check.

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

## 6. Decisions needed (Chris)

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
