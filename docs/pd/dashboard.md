# Harborlight PD — Dashboard

## Starting the dashboard

```bash
export WITNESS_PD_TOKEN=your-secret-token
witness-pd serve [--port 8890]
```

Open `http://127.0.0.1:8890` in a browser. Enter the token at the login screen.

The server listens on loopback only. To expose it on the network, place nginx or Caddy in front with HTTPS.

## Tabs

### Chief

System overview for department leadership.

- Item count, legal hold count, log entry count, node identity
- Recent activity feed (last 20 events, auto-refreshes every 30s)

### Evidence Room

Day-to-day evidence management.

- **Record Intake** — enter case number, category, description, officer, and node. Generates a unique item ID (`EV-YYYYMMDD-XXXXXXXX`).
- **Transfer Custody** — enter item ID, from/to node, officer, and notes. Blocked if item is under legal hold.
- **Evidence Items** — searchable/filterable table of all items. Click "Hold" on any row to open the hold management panel.
- **Legal Hold Panel** — set or release a hold on a selected item. Requires actor name and reason.

### Tech / Admin

System health and export generation.

- Node identity, department, version, log entry count, last event
- **Export Court Bundle** — enter case number and actor name, optionally sign with Ed25519 key. Downloads bundle to `~/.witness-pd/exports/`.

### Daily Logs

Chronological event feed with date and case number filters.

- Select a date (defaults to today)
- Optionally filter by case number
- Events displayed in reverse chronological order

### Officer View

Case-scoped view for officers tracking their cases.

- Enter a case number to load all items and custody events for that case
- Chain-of-custody timeline showing all transfers, holds, and access events

## Authentication

The dashboard uses a simple Bearer token stored in `sessionStorage`. Closing the browser tab clears the session; the token must be re-entered.

The token is validated on every API call server-side. If the token changes (e.g. rotated via `WITNESS_PD_TOKEN`), existing sessions become invalid immediately on the next API call.
