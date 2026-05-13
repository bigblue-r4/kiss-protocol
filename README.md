# SGAIL Labs Harborlight Firewall

Tamper-evident machine-state logging for AI agent environments. Witness takes a cryptographic snapshot of your machine **before** any AI agent is installed, then continuously monitors for drift. If the process is killed, tampered with, or detects a storage anomaly, it fires a death broadcast to all backup locations simultaneously.

## Quick start

```bash
# 1. Clone and install (run BEFORE installing any AI agent)
git clone https://github.com/bigblue-r4/kiss-protocol.git
cd kiss-protocol
sudo bash install.sh

# 2. Install your AI agents (Claude Code, Cursor, etc.)

# 3. Start the witness daemon
witness start
```

That's it. Witness is now running and monitoring.

## Works with any AI agent

Witness is **LLM-agnostic**. It monitors machine state and routes agent traffic through [Pipelock](https://github.com/luckyPipewrench/pipelock) — a transparent auditing proxy. Any agent that respects standard HTTP proxy environment variables is supported.

When `witness start` runs it prints the proxy address. Set it in your agent's environment:

```bash
export HTTPS_PROXY=http://127.0.0.1:8889
export HTTP_PROXY=http://127.0.0.1:8889
```

Tested with: Claude Code, Cursor, Aider, and any tool using standard Go/Python/Node HTTP clients.

## Runs standalone — no server required

Witness works completely offline. No SGAIL server, no other nodes, no account needed. Everything stays on your machine across three local backup tiers.

Optional: if you operate a SGAIL server, enable encrypted remote sync with:

```bash
witness enable-sync --endpoint https://your-server:8443
# or via env var (recommended over storing in config):
export WITNESS_SGAIL_TOKEN=your-token
witness enable-sync --endpoint https://your-server:8443
```

## Status view

There is no web dashboard — `witness status` is your view:

```
─────────────────────────────────────────
Machine ID    : <id>
Genesis       : CLEAN
Log entries   : 142
Drift events  : 0
Primary       : ~/.witness/primary
Secondary     : /var/lib/.watcher_state
Tertiary      : [derived — not displayed]
SGAIL sync    : disabled (opt-in only)
Last event    : [INFO] witness / drift_clean (2026-05-13T07:41:02Z)
─────────────────────────────────────────
```

## Public naming

The public name for this stack is **SGAIL Labs Harborlight Firewall**.

The main binary is `witness`. The Go module path is `github.com/bigblue-r4/kiss-protocol`.

## What is here

- `cmd/witness` — CLI entry point
- `internal/` — core packages for genesis, storage, drift, backups, anomaly detection, and sync
- `payload/witness/default-soul.toml` — default soul file payload
- `install.sh`, `usb-setup.sh`, `harborlight-install.sh` — install paths and packaging scripts

## What is Pipelock?

[Pipelock](https://github.com/luckyPipewrench/pipelock) is a transparent HTTP/HTTPS auditing proxy. Witness starts it as a subprocess and tails its audit log, forwarding every agent network event into the encrypted witness log. Install is automatic — `install.sh` handles it.

## Build from source

Requirements: Go 1.22 or newer

```bash
go test ./...
go build ./...
```

## SGAIL remote sync (optional)

Remote sync is opt-in and disabled by default. Prefer the `WITNESS_SGAIL_TOKEN` environment variable over storing the token in `~/.witness/config.json`, which is readable by any process running as your user.

## Website

`projects/sentinel-website/` contains the static build output for
[sentinelproject.ai](https://sentinelproject.ai), deployed via Netlify on push to main.

## License

MIT. See `LICENSE`.
