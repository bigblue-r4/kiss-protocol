# Witness Client — Folder Briefing

## Where I Am
- **This folder:** SGAIL/witness-client/
- **Parent:** SGAIL root (see /home/evillab/CLAUDE.md)
- **Siblings:** bigblue/ (firewall), call-witness/ (phone scam detection)
- **GitHub:** github.com/bigblue-r4/kiss-protocol (private)

## What This Project Is
Witness Client is the Ann / Fair Witness layer of Harborlight. It installs BEFORE any AI agent
on a clean machine, takes a cryptographic genesis snapshot of machine state, then continuously
logs all agent behavior against that baseline. Install order is the core security primitive —
this was built directly in response to a real RAT compromise where the agent had full access
because it was installed before any witness existed.

## Current Status
🟢 Active

**Last worked on:** 2026-04-05
**Current task:** v1 complete — USB built and ready. Next: SGAIL server (laptop) for sync/death broadcast reception.

## Key Files In This Folder
- `cmd/witness/main.go` — CLI entry point: init, start, status, enable-sync, watchdog subcommands
- `internal/genesis/genesis.go` — machine state snapshot + agent preflight scan
- `internal/store/store.go` — AES-256-GCM hash-chained encrypted log (wire format: uint32 len + sealed bytes)
- `internal/soul/soul.go` — soul file load + SHA-256 hash verification (halt on mismatch)
- `internal/death/death.go` — death broadcast: 4 parallel goroutines, 8s deadline
- `internal/pipelock/runner.go` — Pipelock subprocess manager + config generator
- `internal/pipelock/tailer.go` — NDJSON audit log tailer → witness store
- `internal/anomaly/detector.go` — storage probe + network interface monitor
- `internal/backup/secondary.go` — /var/lib/.watcher_state/ fallback ~/.witness/.secondary
- `internal/backup/tertiary.go` — HMAC-derived path, never stored in any config file
- `internal/sgail/sgail.go` — sync/death POST to sentinelproject.ai
- `payload/witness/default-soul.toml` — immutable agent identity for Witness
- `_core.sh` — Harborlight USB installer core (Mac + Linux, offline)
- `make-checksums.sh` — run on BUILD MACHINE to generate VERIFY.txt before copying to USB
- `SESSION_LOG.md` — running log of decisions and dead ends (read before architectural decisions)

## Three-Tier Storage
| Tier | Location | Notes |
|------|----------|-------|
| Primary | ~/.witness/primary/ | AES-256-GCM, hash-chained |
| Secondary | /var/lib/.watcher_state/ | fallback ~/.witness/.secondary |
| Tertiary | HMAC-SHA256(machine-id, secret)[:16] | path never stored anywhere |

## How It Connects To Other Projects
- **Feeds into:** SGAIL server (receives sync payloads + death broadcasts at sentinelproject.ai)
- **Depends on:** Pipelock (proxy audit log), machine-id (/etc/machine-id or macOS equivalent)
- **Shares:** soul file format with all other Harborlight agents

## Standing Orders
- `witness init` is run ONCE, deliberately, by a human, on a clean machine — never automate it
- Soul file mismatch = agent halts immediately — do not patch, investigate
- Tertiary backup path is never written to disk or any config file — HMAC only
- Do not run make-checksums.sh on the target machine — build machine only
- Death broadcast has 8s hard deadline — keep all 4 goroutines fast

## Compact Instructions
When compacting, always preserve:
- Current task state (what was in progress, what was just completed)
- Any architectural decisions made this session
- USB/binary build status
- SGAIL server build status
- File names actively being worked on
- Any errors or blockers encountered
