# Event feeds and log export

## Named event feeds

The witness can record any number of NDJSON feeds, each under its own source name. Use one feed per program that has something to put on the record: a dispatcher, an egress monitor, an integrity checker.

```json
{
  "event_feeds": [
    {"path": "/var/log/exp1/dispatch.jsonl", "source": "exp1-dispatch"},
    {"path": "/var/log/exp1/egress.jsonl",   "source": "exp1-egress"}
  ]
}
```

### Line format

One JSON object per line. The whole line is stored unchanged as the record's payload.

| field | meaning |
|---|---|
| `kind` | The event name in the log. Must match `[A-Za-z0-9_.:-]{1,64}`, otherwise the line is recorded as `feed_event` (never dropped). |
| `level` | `WARN` or `CRITICAL` raise the record. Anything else, or none, is `INFO`. |
| anything else | Stored as sent. |

### Who can write as which source

The source is the feed's **configured** name. A `source` field inside a line is just payload. A program can therefore only write as the feeds whose files it can write to: give each producer its own file, owned by its own user and readable by the witness. A program with no write access to `dispatch.jsonl` cannot put an `exp1-dispatch` record in the log.

Rules (a bad list stops `witness start`):
- Source names must match `^[a-z0-9][a-z0-9_.-]{0,31}$` and be unique.
- Each path may be used only once.
- Sources the witness writes itself are reserved: `witness`, `witness-init`, `sbh`, `farm`, `pipelock`, `drift`, `migrate`, `pd`, `pd-system`, `mirror`, `enforcer`, `anomaly`.

### Restarts and new files

A feed resumes from its saved position after a witness restart, so lines written while it was down are recorded, as with the farm and SBH feeds.

**A feed the witness has never seen is read from its end.** Create each feed file (empty) **before** the witness first starts, or anything written ahead of that first start is not recorded.

## Exporting the log

```bash
witness export --pubkey HEX [--since 2026-10-22T00:00:00Z] [--until ...] [--source exp1-egress] --out run.json
witness verify-export run.json --pubkey HEX [--prior head-earlier.json]...
```

`export` writes three things:
- the **signed tree head** exactly as stored,
- **every leaf hash** up to it,
- the **decrypted records** that match the filter.

It only reads, so it is safe while the daemon runs. With `--pubkey` it checks its own output first.

`verify-export` runs anywhere: it needs only the export and the signer's public key, never the machine key or the witness host. It checks that:

1. the root recomputed from the leaf hashes equals the head's root, and the size matches;
2. the head is signed by a pinned key (a pin is required);
3. every record shown hashes to the leaf at its position, so a filtered export still proves each record it shows;
4. each `--prior` head (saved from an earlier export) is a prefix of this log. This is the **append-only** check: a log that was truncated or rewritten after that head left the host fails it.

It exits 0 when intact and 1 on any failure.

**Using it as evidence:** after every run, export and keep the head somewhere other than the witness host. At the end, verify the final export with every kept head as `--prior`. Without a mirror, this shows the log only ever grew while you held it.

Records hold whatever the producers wrote, in plaintext once exported. Treat an export like the log itself.
