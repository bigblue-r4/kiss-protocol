# Enforcer Architecture — kiss-core / kiss-enforcer Decoupling

## Problem Statement

In v2, the `witness` binary blended local logging with distributed enforcement.
The gossip mesh, death broadcasts, and SGAIL sync client all ran inside the same
process that owned the Merkle log write path. This meant:

- A compromised enforcer (e.g., network-triggered exploit) could also tamper with the log.
- The core log was exposed to network state (open UDP sockets, HTTP clients) inside the same process.
- The death broadcaster had an SGAIL HTTP dependency that could block or stall the write path.

## v3 Solution: Hard Process Boundary

```
┌────────────────────────────────────────────────────────────────┐
│                        kiss-core (witness)                     │
│                                                                │
│  soul → genesis → store (Merkle log) → drift → mirror push    │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  ~/.witness/primary/witness.log   (encrypted, append-only│  │
│  │  ~/.witness/primary/tree-head.json (signed Merkle head)  │  │
│  └───────────────────────────────┬─────────────────────────┘  │
│  NO network listeners            │ file read only              │
│  NO outbound peers               │                             │
└──────────────────────────────────┼─────────────────────────────┘
                                   │ store.ReadAll() — O_RDONLY
                                   │ no lock, no IPC
┌──────────────────────────────────▼─────────────────────────────┐
│                      kiss-enforcer (enforcer)                  │
│                                                                │
│  enforcer.TailReader → event chan → gossip mesh                │
│                                  → loyalty policy evaluator    │
│                                  → death broadcaster (UDP)     │
│                                                                │
│  ~/.enforcer/peers.json           (peer allowlist)             │
│  ~/.enforcer/dev-signing.key      (or YubiKey PIV slot 9a)     │
└────────────────────────────────────────────────────────────────┘
```

## Isolation Contract

| Property | Guarantee |
|---|---|
| Core never imports enforcer | Enforced by Go module boundaries |
| Enforcer never opens log for writing | TailReader uses store.ReadAll (os.Open, O_RDONLY) |
| Key derivation is independent | Both derive from machid → encrypt.DeriveKey; no IPC |
| Enforcer compromise ≠ log corruption | No write handle; no lock ownership |
| Core death is local-only | death.Broadcaster writes disk only; UDP broadcast is enforcer's job |

## Data Flow

```
1. kiss-core appends a log entry
   └─ store.Append() → encrypt → write frame → writeTreeHead (atomic rename)

2. enforcer.TailReader.poll() fires (every 5 s, default)
   └─ store.ReadAll(dir, key)            — read-only open
   └─ merkle.HashLeaf() for each entry   — verify structure
   └─ deliver new entries to chan Event

3. Event consumer (cmd/enforcer main loop)
   └─ DEATH event  → gossip.BroadcastDeath() to all peers
   └─ DRIFT event  → log to stderr / optional alerting endpoint
   └─ WARN event   → log
```

## Upgrade Path

The enforcer currently uses a polling tail reader. A future inotify-backed
reader can provide sub-second latency on Linux without changing the interface:

```go
// internal/enforcer/reader_inotify.go  (linux only)
func NewInotifyTailReader(dir string, key []byte, events chan<- Event) (*TailReader, error)
```

The `TailReader.Run(ctx)` / `TailReader.Wait()` interface is unchanged.

## Process Isolation on Linux (Recommended)

For production deployments, run each binary under its own system user:

```
witness  → runs as user:  witness   (group: witness)
enforcer → runs as user:  enforcer  (group: witness, enforcer)
```

The `~/.witness/primary/` directory is owned by `witness:witness` with mode `0750`.
The `enforcer` user is in group `witness` so it can read but not write the log.

```bash
# Create users
useradd -r -s /sbin/nologin witness
useradd -r -s /sbin/nologin -G witness enforcer

# Lock down log directory
chown -R witness:witness /opt/witness/primary
chmod 750 /opt/witness/primary

# Set capabilities: witness needs no network; enforcer needs UDP for gossip
setcap '' /usr/local/bin/witness
setcap 'cap_net_bind_service=+ep' /usr/local/bin/enforcer
```
