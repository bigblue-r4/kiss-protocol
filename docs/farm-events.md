# Farm event feed

The witness can record a farm's automation events in its tamper-evident Merkle log. Any system that
can append one JSON object per line to a file can feed it: a controller export, a small adapter
script, a door-access system, a spreadsheet importer. Point the witness at the file with
`farm_events_path` in `config.json` or the `FARM_EVENTS_PATH` environment variable.

## What it gives you

- **A record nobody can quietly edit.** Every event goes into the witness's Merkle log. A changed,
  removed or cut-off entry fails `witness verify`, which recomputes the tree and checks it against
  the signed head. The head is signed on the same machine, so this *detects* tampering rather than
  preventing it. Pushing heads to a transparency mirror (`witness audit`) means a rewritten log
  disagrees with a copy held elsewhere.
- **Nothing lost to a witness restart.** The read position is saved, so events written while the
  witness was stopped are recorded when it starts again, and the log says how much it caught up.
- **A "silent house" alarm.** Every source that has reported before is watched. If one goes quiet
  for longer than `farm_silence_minutes` (default 10), the log records one warning,
  `farm_source_silent`, and `farm_source_resumed` when it reports again.

**What it is not:** it detects and records. It does not control anything and cannot keep
ventilation or feeding running. That stays with the house controllers and their own backups.

## Format

One JSON object per line. Common fields:

| field | required | meaning |
|---|---|---|
| `ts` | recommended | When it happened, RFC 3339 (`2026-10-02T21:00:00Z`). Silence is measured from this; without it, arrival time is used |
| `source` | recommended | Which device or system (`house-3/controller`, `house-3/entry-door`). Silence is tracked per source |
| `kind` | yes | One of the kinds below. Anything else is still recorded, as `farm_event` |

Every field is stored exactly as sent; the kinds only decide how an entry is labelled.

| `kind` | extra fields (suggested) | recorded as |
|---|---|---|
| `reading` | `metric`, `value`, `unit` | INFO `farm_reading:<metric>` |
| `alarm` | `alarm`, `severity`, `value` | **WARN** `farm_alarm:<alarm>` |
| `setting_change` | `setting`, `from`, `to`, `by` | INFO `farm_setting_change:<setting>` |
| `access` | `door`, `person`, `direction` | INFO `farm_access:<door>` |
| `health` | `record` (e.g. `vaccination`), `flock`, `product`, `by` | INFO `farm_health:<record>` |
| `heartbeat` | — | INFO `farm_heartbeat` (keeps a quiet-but-healthy source from being flagged) |

## Examples

```json
{"ts":"2026-10-02T21:00:00Z","source":"house-3/controller","kind":"reading","metric":"ammonia_ppm","value":18.5,"unit":"ppm"}
{"ts":"2026-10-02T21:01:00Z","source":"house-3/controller","kind":"alarm","alarm":"high_temperature","severity":"critical","value":92.1,"unit":"F"}
{"ts":"2026-10-02T21:02:00Z","source":"house-3/controller","kind":"setting_change","setting":"min_ventilation_pct","from":30,"to":10,"by":"remote:jdoe"}
{"ts":"2026-10-02T21:03:00Z","source":"house-3/entry-door","kind":"access","door":"house-3/entry","person":"badge:1042","direction":"in"}
{"ts":"2026-10-02T21:04:00Z","source":"office/records","kind":"health","record":"vaccination","flock":"F-2026-41","product":"example-vaccine","by":"crew:ana"}
{"ts":"2026-10-02T21:05:00Z","source":"house-4/controller","kind":"heartbeat"}
```

## Privacy

The payload is stored as sent, in the witness's encrypted log. Send badge or employee IDs rather
than names if the record does not need names.
