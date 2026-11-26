# Example evaluation (synthetic data)

This is the output of one real run of `pilot/demo.sh` on 2026-11-25, on a development workstation. Local paths are replaced by `<workdir>`.

| File | What it is |
|---|---|
| [`report.html`](report.html) | The verifier's single-file report: result, checks, witness table, completeness, disclosures, run manifest. It has no scripts and opens offline |
| [`report.json`](report.json) | The same result as JSON |
| [`adversarial.json`](adversarial.json) | The 21 adversarial cases: each attack, its expected result and the result it got |
| [`demo-output.txt`](demo-output.txt) | The terminal output of the four demonstration steps |

## What the run shows

1. **VERIFIED, with witness NOT independent.**
   - 2,251 records: the destination-validation upload plus 2,000 events, plus batch 2 (250 events) delivered twice on purpose.
   - The records hash to the signed root.
   - The log signature checks against the pinned key.
   - One fresh cosignature from the (operator-run) omniwitness.
2. **The redelivered batch is visible:** "all 250 entries recorded 2 times (the whole batch was delivered again)". The log is intact; the input was not clean.
3. **FAILED** on a copy with one record changed.
4. **UNVERIFIABLE** once the witness was stopped and its last cosignature became older than the freshness bound.
5. **21 of 21** adversarial cases matched.

## Reproduce

```sh
pilot/demo.sh ./my-run
```

Your keys, timestamps, batch IDs and hashes will differ, because every run makes new keys. The results and the shape of the report should match.

To check the report's claims without trusting the report, verify the evidence again with `harborlight-verify` against the same public directory.
