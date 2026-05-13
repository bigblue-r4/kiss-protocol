# SGAIL Labs Harborlight Firewall

SGAIL Labs Harborlight Firewall is a witness-oriented AI security project centered on tamper-evident machine-state logging.

This repository contains the `witness` CLI, the Harborlight install assets, and related support files. The project grew out of incident response work in which AI agents on a host were compromised while the witness log remained intact.

## Status

This codebase is being prepared for public release. The current cleanup pass focuses on:

- stable module and import paths
- reproducible builds and CI
- public documentation
- removal of private operator notes and duplicate source trees

## Public naming

The public name for this stack is **SGAIL Labs Harborlight Firewall**.

For compatibility, the main binary name remains `witness`, and the current repository path remains `github.com/bigblue-r4/kiss-protocol` until the public release rename is completed.

## What is here

- `cmd/witness` — CLI entry point
- `internal/` — core packages for genesis, storage, drift, backups, anomaly detection, and sync
- `payload/witness/default-soul.toml` — default soul file payload
- `install.sh`, `usb-setup.sh`, `harborlight-install.sh` — install paths and packaging scripts

## Build

Requirements:

- Go 1.21 or newer

Build and test:

```bash
go test ./...
go build ./...
```

## SGAIL remote sync (optional)

Remote sync is opt-in. To enable it, run:

```bash
witness enable-sync --endpoint https://your-sgail-server:8443
```

The auth token can be provided interactively or via environment variable:

```bash
export WITNESS_SGAIL_TOKEN=your-token
witness enable-sync --endpoint https://your-sgail-server:8443
```

**Prefer the environment variable over storing the token in config.** The config
file at `~/.witness/config.json` is readable by any process running as your user.
The env var keeps the token out of the filesystem.

## Repository notes

The public cleanup is in progress. This pass standardizes the public-facing name around SGAIL Labs Harborlight Firewall while keeping code paths stable.

## Website

`projects/sentinel-website/` contains the static build output for
[sentinelproject.ai](https://sentinelproject.ai), deployed via Netlify on push to main.

## License

MIT. See `LICENSE`.
