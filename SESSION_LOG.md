# Session Log — Witness Client

## How To Use This File
- Claude Code appends to this at the end of each session
- Read this at the start of every new session before doing anything
- Keep entries concise — this is a decision trail, not a diary

---

## Log Format

### [DATE] — [Brief description of session]
**What we did:** [1-2 sentences]
**Decisions made:** [bullet list]
**Dead ends / don't repeat:** [what failed and why]
**Left off at:** [exact state when session ended]
**Next step:** [what to do when resuming]

---

## Log Entries

### 2026-04-05 — v1 complete, USB built and pushed to GitHub

**What we did:** Built the full Witness Client v1 from scratch — genesis snapshot, soul verification,
three-tier encrypted log, death broadcast, pipelock integration, anomaly detection, watchdog subprocess,
Harborlight USB offline installer. Cross-compiled all 8 binaries, placed on USB, generated VERIFY.txt.

**Decisions made:**
- Genesis first architecture: witness init runs ONCE before any agent, by human hand — installer does NOT automate it
- Three-tier backup: primary ~/.witness/primary/, secondary /var/lib/.watcher_state/, tertiary HMAC-derived path (never stored)
- AES-256-GCM with HKDF-SHA256 key derivation from /etc/machine-id
- Hash-chained log: each entry contains SHA-256 of previous entry plaintext
- Watchdog subprocess (not goroutine) to handle SIGKILL — polls parent PID every 2s
- Death broadcast: 4 parallel goroutines, 8s hard deadline
- Soul file loaded and hash-verified FIRST at witness init — halt on mismatch or missing
- Pipelock runs in audit-only mode (allow-all policy) — witness handles alerting, not Pipelock
- Harborlight installer job: get files there, verify integrity, nothing more
- USB binaries excluded from git repo via .gitignore — live on USB only
- make-checksums.sh runs on BUILD MACHINE only, never on target

**Dead ends / don't repeat:**
- `go install` cannot cross-compile with GOBIN set — use `go build -o` for cross-compile targets
- `bufio.NewReader` is unreliable for binary length-prefixed records — use `io.ReadFull`
- `pipelock.Config` needs explicit `AuditLogPath()` method — field name alone doesn't satisfy interface
- Unused imports in main.go cause compile failure — clean up before build

**Left off at:** USB complete with VERIFY.txt generated. All source committed and pushed to
github.com/bigblue-r4/kiss-protocol (main branch). Context management files (CLAUDE.md, SESSION_LOG.md,
MAP.md) applied to project tree.

**Next step:** Build SGAIL server on the laptop — receives sync payloads (`/api/v1/witness/sync`)
and death broadcasts (`/api/v1/witness/death`), stores Fair Witness log, exposes ping endpoint.
gRPC on 127.0.0.1:50060, NATS subscriber for multi-agent events.
