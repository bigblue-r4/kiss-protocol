# Errata: Proof-of-Control C07 self-assessment

This corrects `CONFORMANCE_C07.md` as published on the tag
[`c07-assessment-2026-10`](https://github.com/bigblue-r4/kiss-protocol/blob/c07-assessment-2026-10/CONFORMANCE_C07.md)
(commit `f15bc45`), SGAIL's public self-assessment of the Witness against
section C07 of the Proof-of-Control Working Draft v0.1. The tag is a dated record and is not
changed; this document supersedes the passages listed below.

Published 2026-11-26. Found while re-running the C07 test suite for a later
assessment.

## Erratum 1: the `replay` tamper case has failed since v3.3.3

**What the document says.** Row 7.3.1 lists
`TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected` among the passing tests,
"(modify, insert, reorder, delete, replay)". The two updates at the top of the
document (v3.3.3, and PR #33 at `f15bc45`) left that row as it was.

**What is true.**

| Release tested | `modify` | `insert` | `reorder` | `delete` | `replay` | Whole test |
|---|---|---|---|---|---|---|
| v3.3.2 (the original assessment) | pass | pass | pass | pass | **pass** | pass |
| v3.3.3 (first update) | pass | pass | pass | pass | **fail** | **fail** |
| `f15bc45` (second update, PR #33) | pass | pass | pass | pass | **fail** | **fail** |
| `main` at `ae94d66` (2026-11-26) | pass | pass | pass | pass | **fail** | **fail** |

The original v3.3.2 assessment was correct. The two updates were not: they
re-ran the suite and reported the totals, but did not notice that this test had
moved from passing to failing.

**Why it fails.** v3.3.3 fixed a defect the assessment found: an interrupted
write left the log permanently unopenable. Since then, when the log is opened,
anything after the records the signed head covers is treated as a crash tail
if it is a partial record and/or exactly one complete record. It is moved to
`witness.log.crash-tail-<time>` (kept, never deleted), and the daemon records
`WARN log_crash_tail_recovered`. The test's `replay` case appends one copy of
record 0 after the signed head. That is indistinguishable, under this rule,
from one record whose head update was interrupted, so it is quarantined and the
log opens, where the test expects the open to fail.

**Impact.**
- The replayed record never enters the committed, signed history, and it is
  kept for inspection. Detection still holds in that sense.
- But it is reported as a crash, with a WARN, not as tampering. An operator
  reading the log sees an interrupted write, not an attack.
- Only exactly one complete record after the head is handled this way.
  Appending two replayed records still fails the open as tampering (checked on
  `main` at `ae94d66`), as do the `modify`, `insert`, `reorder` and `delete`
  cases.
- Row 7.3.1 stays **PARTIAL**. No requirement's status changes.

## Erratum 2: "all are open gap probes" was wrong in both updates

**What the document says.** "Re-run on v3.3.3: 31 tests, 17 pass, 14 fail
(all 14 are open gap probes)" and "Re-run with PR #33: 31 tests, 18 pass, 13
fail (all 13 are open gap probes)."

**What is true.** The totals are right. The description is not: in each run,
one of the failures is `TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected`,
which tests a property the Witness claims, not an open gap. Corrected:

- v3.3.3: 17 pass, 14 fail = 13 open gap probes + the `replay` case above.
- `f15bc45` (PR #33): 18 pass, 13 fail = 12 open gap probes + the `replay`
  case above.

## Reproducing

The tests are on the tag, behind the `poc_c07` build tag:

```bash
git checkout c07-assessment-2026-10
go test -tags poc_c07 -count=1 -v ./tests/poc_c07/ \
  -run 'TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected'
```

For v3.3.2 and v3.3.3, use the test copies committed with each update
(`972d262` and `021689c` on the tag's history), because later copies call
`store.OpenPinned`, which those releases do not have.

## Planned fix

Report a quarantined tail that is a byte-for-byte or sequence-number duplicate
of a committed record as a replay (ALERT), not as a crash. Not yet scheduled;
until it ships, treat a `log_crash_tail_recovered` WARN that did not follow a
crash, kill or power loss as possible tampering, and inspect the quarantine
file.
