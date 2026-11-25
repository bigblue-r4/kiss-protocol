# Stage 2 pilot: threat model, security limitations and trust boundaries

2026-11-25. Scope: the pilot components (`harborlight-cf-adapter`, `harborlight-log`, `omniwitness`, `harborlight-verify`).

The existing Witness host-integrity product and its threat model ([`THREAT_MODEL.md`](../../THREAT_MODEL.md)) are unchanged and out of scope here.

## What the pilot claims

1. **Tamper evidence.**
   - Once a record is covered by a checkpoint that an evaluator verified, any change to it (content, order, presence) makes later verification `FAILED`.
   - Any change to the records under a checkpoint the evaluator is verifying also gives `FAILED`.
2. **Detection of conflicting histories**, under the witness assumptions in §3.
   - A history the operator rewrote and re-signed gets no cosignature from an honest witness. An evaluator therefore cannot get `VERIFIED` for it.
   - With `--state`, an evaluator who saw the earlier history gets `FAILED`.
3. **Fail-loud verification.** A missing input, an absent or stale witness, or an unmet quorum gives `UNVERIFIABLE`, never `VERIFIED`.
4. **Shadow mode.** The adapter only receives copies of telemetry. It has no credential for, and no path back to, the source.

It claims **nothing else**. In particular, it makes:
- no certification claim;
- no Proof-of-Control Tier 3 or Tier 4 claim;
- no production security guarantee.

## 1. Assets and trust boundaries

```
 telemetry source ──copies──▶ adapter ──feed──▶ evidence log ──checkpoint+proof──▶ witness
   (Cloudflare or              (operator host: one trust domain)                    (separate trust
    synthetic)                                                                       domain if, and only
                                                                                     if, run by another party)
                                   public directory ──▶ evaluator's verifier (evaluator's machine)
```

| Boundary | Crossing | Protection |
|---|---|---|
| Source → adapter | HTTPS POST of gzip NDJSON | A bearer token, compared in constant time, plus size limits. TLS must be terminated in front of the adapter (Logpush requires HTTPS with a trusted certificate) |
| Adapter → log | An append-only feed file on the same host | File permissions only. Anyone who can write the feed can add records, which are then logged faithfully |
| Log → witness | tlog-witness `add-checkpoint` | The checkpoint signature and an RFC 6962 consistency proof. The witness persists its state before it cosigns |
| Log → evaluator | The public directory over HTTP, or a copy | Nothing is trusted from the channel. Everything is checked against keys the evaluator pinned |
| Evaluator's state | `--state` file | Kept by the evaluator. If they lose it, they lose rollback detection for their next run |

## 2. Attacks, and what the verifier says

Every row is a case in `harborlight-adversarial` (also run by `go test`).

| # | Attack | Result | Why |
|---|---|---|---|
| A02–A06 | Modify, insert, delete, reorder or replay a record under a checkpoint | FAILED | The records no longer hash to the signed root |
| A07, A18 | Truncate or delete checkpointed records | FAILED | Fewer records than the signed size. The log itself also refuses to start |
| A08 | The operator rewrites a record and re-signs with the real log key, for an evaluator with no prior state | UNVERIFIABLE | The witness refuses the inconsistent checkpoint (HTTP 422, also tested against the real omniwitness), so there is no cosignature |
| A09 | The same rewrite, for an evaluator who verified before | FAILED | Their state no longer matches the prefix |
| A10 | Split view: B gets a fork | UNVERIFIABLE for B | The witness cosigns only one lineage |
| A11 | Rollback to an older, genuinely cosigned checkpoint | FAILED with state | The size went backwards against the evaluator's state |
| A12 | Frozen or withheld checkpoint (stale cosignature) | UNVERIFIABLE | The newest cosignature is older than `--max-age` |
| A13 | Witness down | UNVERIFIABLE | The log keeps logging, but the checkpoint carries no cosignature |
| A14 | Forged cosignature bytes | FAILED | A signature under a pinned witness key ID does not verify |
| A15 | Wrong log key | FAILED | |
| A16 | Impostor witness (right name, other key) | UNVERIFIABLE | Unknown keys are ignored, so the quorum is not met |
| A17 | Torn write (power cut) | VERIFIED, with a log notice | The partial line is quarantined, kept, and recorded as a `recovery` record |
| A19 | Flood of garbage and oversized lines | VERIFIED, with rejected counts | Rejected lines are kept as hashes only |
| A20, A21 | Inputs unreachable or withheld | UNVERIFIABLE | |

The adapter's own tests add:
- unauthenticated and wrong-token uploads: 401;
- wrong method;
- bad gzip;
- oversized batches;
- a redelivered batch: reported as duplicate delivery.

## 3. Assumptions and residual risks (disclosed in every report)

1. **Operator.** The log signing key is a software key on the log host. Root on that host can sign anything as the log.
   - What stops a quietly rewritten history being accepted is only the witness quorum together with the evaluator's state.
   - **The operator plus the quorum's witnesses colluding** could still show different histories.
   - The report states the quorum.
2. **The demo witness runs on the operator's host.**
   - It shows the protocol works; it gives **no independence**.
   - The verifier labels such a result *witness NOT independent* when the witness is pinned with `--operator-witness-key`.
   - Real independence needs a witness run by another party. The public witness network is a candidate, and applying to it needs approval: it is an external contact.
3. **First look.** An evaluator with no state can be shown any history that the witness quorum cosigned. With honest witnesses that history is the one history; without them, it may not be.
4. **Completeness is not proven.**
   - The log proves what it received is unaltered, not that it received everything.
   - Cloudflare documents that logs generated while a job is disabled or failing are lost, and it does not document retries, ordering or duplicates.
   - The adapter tags batches by content hash, so the report can show incomplete and repeated batches, but missing *whole batches* are invisible.
5. **Truth of content.** A record shows the adapter received a payload. It does not show that the event happened.
6. **Time.**
   - Record times come from the host clock.
   - A cosignature timestamp, signed by the witness, bounds when a checkpoint existed. It does not bound when an event happened.
7. **Feed file.** Anyone who can write the feed can insert records. A feed that is rotated or truncated is recorded as `feed_reset`. Do **not** rotate the feed during the pilot: lines written after a rotation, but before the log notices it, can be missed.
8. **Plaintext.**
   - Records are published unencrypted (decision D3).
   - The adapter replaces the documented encrypted `RequestBody` and `ResponseBody` with their hashes, but every other field is public.
   - **Synthetic, or explicitly authorised non-sensitive, data only.**
9. **Adapter exposure.**
   - One shared bearer token.
   - Size limits but no rate limit: a client holding the token can fill the disk.
   - Plain HTTP unless the adapter is given a certificate, or fronted by a TLS terminator.
10. **Algorithms.**
    - Ed25519 only.
    - ML-DSA-44 cosignatures (`tlog-cosignature` recommends them for new witnesses) are reported as unsupported, never as verified.
11. **Scale.**
    - The log recomputes the whole tree for each checkpoint.
    - The verifier downloads every record.
    - Measured: about 16–18 s of CPU and under 180 MiB peak memory per million records, for each of the two ([BENCHMARKS-AND-COST.md](BENCHMARKS-AND-COST.md)).
    - Comfortable to roughly 10⁷ records. Beyond that, a tiled log (Tessera) is the planned path (DEFER).
12. **Out of scope.**
    - Hardware key custody (HSM or PIV) and TEE attestation.
    - An inline control on traffic.
    - Per-source origin signatures.
    - RFC 3161 timestamps.
    - The Lucid research harness, which is in no pilot component.
