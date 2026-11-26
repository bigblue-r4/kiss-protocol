# Stage 2 pilot: benchmarks, cost per million events, resources and maintenance

## Benchmarks (measured)

**Run:** 2026-11-25 with `pilot/bench.sh <demo dir> 1000000`, on a small development workstation:
- Intel N95, 4 CPUs, 15 GiB RAM, ext4 on SATA;
- 1,000,000 synthetic `ai_gateway_events` records in 1,000-record gzip uploads;
- one log round over the whole feed (a catch-up case), cosigned by a local omniwitness.

These are one run on one small machine. They have not been repeated, and other hardware was not tried. Re-run the script on the target host before relying on them.

| Stage | Wall | CPU | Peak RSS | Per 1M events |
|---|---|---|---|---|
| Generator plus upload (client side, demo only) | 59.9 s | 23.3 s | 16 MiB | about 16,700 events/s through the adapter |
| Adapter (server side: gunzip, normalise, fsync per batch) | | 41.3 s | | 41 CPU-s |
| Log: ingest, checkpoint, witness cosign | 18.9 s | 17.9 s | 177 MiB | 18 CPU-s, about 53,000 events/s |
| Verifier: full independent verification | 15.3 s | 15.6 s | 180 MiB | 16 CPU-s, about 65,000 events/s |

| Bytes | Per record | Per 1M events |
|---|---|---|
| Feed (adapter output) | 795 B | 0.74 GiB |
| Public `records.jsonl` | 882 B | 0.82 GiB |
| The same, gzip (what an evaluator downloads with compression) | 114 B | 0.11 GiB |
| Checkpoint plus cosignature | about 300 B per checkpoint | independent of volume |

Memory in the log and the verifier is about 32 bytes per record (leaf hashes) plus constant buffers. An earlier, non-streaming version used about 3.4 KiB per record. It was fixed before this measurement.

**Not yet measured:**
- steady-state checkpoint latency at a 30 s interval with a remote witness;
- the Docker image path;
- tree recomputation above 10⁷ records.

## Cost per million events (method, not a quote)

These are resource quantities per million events, from the table above. Multiply them by your own unit prices. Prices are deliberately not filled in: they depend on the provider, region and commitment, and must be looked up when quoting (`[TO VERIFY]`).

| Resource | Quantity per 1M events | Unit price | Cost |
|---|---|---|---|
| Operator compute (adapter plus log) | about 59 CPU-seconds, about 0.016 vCPU-hours | `P_cpu` per vCPU-hour | 0.016 × `P_cpu` |
| Operator storage (feed plus public records) | about 1.56 GiB, kept for the pilot's retention period | `P_disk` per GiB-month | 1.56 × months × `P_disk` |
| Egress to evaluators | about 0.11 GiB per full verification (gzip) × number of verifications | `P_egress` per GiB | 0.11 × V × `P_egress` |
| Witness | one small request per checkpoint interval, independent of event volume | operator's or third party's | — |
| Evaluator compute | about 16 CPU-seconds per full verification | evaluator's own | — |

The fixed costs dominate, not the per-event costs:
- the hosts;
- TLS termination;
- the people time below.

At pilot volumes (≤ 10⁷ events), compute per million events is a fraction of a vCPU-hour.

## Resources and maintenance (founder-led team)

| Item | Effort | Notes |
|---|---|---|
| Build to this point | done | Packages `pkg/tlog` and `pkg/checkpoint`; the binaries `harborlight-log`, `harborlight-verify`, `harborlight-cf-adapter` and `harborlight-adversarial`; the demo, the Compose files and the documents |
| Run the Compose path on a Docker host and fix what breaks | 0.25–0.5 ew | It needs a host with Docker. The development workstation has none |
| Add the pilot binaries to the signed release (cosign, SBOM, provenance) | 0.25 ew | `release.yml` currently builds `witness` and `enforcer` only |
| Keep the pinned witness version current | about 1 h/month | Re-run the interop test (`HL_OMNIWITNESS=...`) on each bump |
| Track C2SP spec changes (cosignature, ML-DSA-44) | about 1 h/month; ML-DSA support 0.5–1 ew when needed | |
| Keep the Cloudflare field list current | about 1 h/quarter | The adapter keeps unknown fields; only the drop list is dataset-specific |
| Pilot operation (per pilot) | about 2–4 h/week | Watching status, answering evaluators, keeping backups |
| Independent witness enrolment | external; needs approval | No code change, configuration only |

**Dependencies added:** one, `golang.org/x/mod` (Go team).

**Integrated without vendoring:** omniwitness, used unmodified at a pinned version, and not linked into our binaries.
