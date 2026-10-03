# Poultry house demo

A 30-second, self-contained run of the Harborlight witness against a simulated poultry operation.
It uses the real witness store, tailer and farm feed. Everything happens locally in a temporary
directory: no network, no background services, nothing installed.

```
go run ./examples/poultry-demo           # about 30 seconds
go run ./examples/poultry-demo -keep     # keep the files to inspect
```

## The four scenes

1. **A normal stretch of the day.** Readings, a high-temperature alarm, a remote cut to minimum
   ventilation (30% → 10% by `remote:jdoe`), door access and a vaccination record. All recorded,
   alarms as warnings, and the setting change keeps who made it.
2. **The witness goes down.** It stops while the houses keep logging. On restart it catches up on
   everything written while it was down, and the record itself says it resumed and how much it
   caught up.
3. **A house controller goes quiet.** House 4 keeps reporting; House 3 stops. After the threshold
   (6 seconds in the demo; 10 minutes by default), the record flags House 3 once, then notes when it
   is back. The door reader and records office, which only report when something happens, are
   never flagged.
4. **Someone tries to rewrite the record.** Four attempts on copies of the log: deleting the
   ventilation-cut entry, changing one byte of an alarm, cutting off the end of the log, and cutting
   off the end *and* deleting the signed head file. Each fails verification, the same check
   `witness verify` runs.

## Honest limits (the demo prints these too)

- It **detects and records**. It controls nothing and cannot keep a house running.
- The record is signed on the farm computer. Someone with full control of that computer could
  rewrite the log and re-sign it, because the key lives there too. A copy of the signed head kept
  elsewhere (the transparency mirror, `witness audit`) catches that.
- The demo uses a fixed key; the real witness derives its key from the machine ID.
