# Pipelock Integration

The witness daemon integrates with Pipelock — a forward proxy that intercepts,
audits, and optionally blocks agent traffic. Every event Pipelock records is
forwarded into the witness Merkle log as a signed leaf, giving the audit trail
a cryptographically ordered record of what the AI agent requested and when.

## Architecture

```
AI agent (Claude Code, OpenClaw, …)
    │  HTTPS_PROXY / HTTP_PROXY
    ▼
┌─────────────────────────────────┐
│  Pipelock (subprocess)          │
│  listen: 127.0.0.1:8889         │
│  audit: pipelock-audit.log      │
└────────────────┬────────────────┘
                 │  NDJSON audit events
                 ▼
┌─────────────────────────────────┐
│  pipelock_bridge.Bridge         │  ← internal/pipelock_bridge
│  tailer polls pipelock-audit.log│
│  forwards events → Merkle leaf  │
└────────────────┬────────────────┘
                 │  store.Append(level, event, "pipelock", payload)
                 ▼
┌─────────────────────────────────┐
│  Witness Merkle log             │  ← internal/store
│  Signed tree head on each tick  │
└─────────────────────────────────┘
```

## Seam Design

All pipelock wiring is contained in `internal/pipelock_bridge`. The bridge
manages:

- Starting and stopping the Pipelock subprocess (`internal/pipelock.Runner`)
- Tailing the NDJSON audit log (`internal/pipelock.Tailer`)
- Forwarding events into the store as Merkle leaves

`cmd/witness` only calls `bridge.Start()`, `bridge.Stop()`, and
`bridge.ProxyAddr()`. If Pipelock is not installed, `Start()` returns an
error, `Enabled()` returns false, and all subsequent calls are no-ops.

## Migration to Library API

The current implementation spawns Pipelock as a subprocess and tails its log.
When `github.com/luckyPipewrench/pipelock` exposes a stable Go library API:

1. Replace `internal/pipelock.Runner` and `internal/pipelock.Tailer` with
   direct library calls inside `internal/pipelock_bridge/bridge.go`.
2. The pipelock binary no longer needs to be installed separately.
3. Remove pipelock binary installation from `install.sh` (Step 1).
4. No changes required in `cmd/witness` or any other caller.

This is the only file that needs to change for the library swap.

## Agent Configuration

After `witness start`, set the proxy env vars in the agent's environment:

```bash
export HTTPS_PROXY=http://127.0.0.1:8889
export HTTP_PROXY=http://127.0.0.1:8889
```

The witness daemon prints the correct address on startup:

```
[witness] Pipelock proxy running → http://127.0.0.1:8889
[witness] Set HTTPS_PROXY=http://127.0.0.1:8889 HTTP_PROXY=http://127.0.0.1:8889 in your agent environment.
```

## Pipelock Config

The bridge generates a Pipelock YAML config at
`<primary_dir>/pipelock.yaml` via `pipelock.Config.WriteConfig()` during
`witness init`. The config enables:

- **Audit mode** — all traffic logged to NDJSON; Pipelock does not block
- **DLP scanning** — data-loss prevention on outbound payloads
- **Response scanning** — inspect inbound responses
- **Behavioral analysis** — heuristic pattern detection
- **MCP inspection** — Model Context Protocol request/response scanning

The default port is `8889`. Override via `pipelock.DefaultConfig()`.

## Audit Log Format

Each line in `pipelock-audit.log` is a JSON object. Key fields:

| Field | Description |
|-------|-------------|
| `event` | Event name (e.g. `connect`, `dlp_match`, `mcp_request`) |
| `level` | Severity: `info`, `warn`, `error` |
| `ts` | RFC3339 timestamp |
| `method` | HTTP method |
| `url` | Request URL |
| `status` | HTTP response status code |

`DEBUG` and `TRACE` levels are normalized to `INFO` in the witness log.

## Checking Pipelock Events in the Log

```bash
witness verify          # walk the full Merkle log
witness prove <index>   # inclusion proof for a specific leaf
```

To inspect raw entries, look for leaves with `source=pipelock` in the
encrypted log at `<primary_dir>/witness.log`.
