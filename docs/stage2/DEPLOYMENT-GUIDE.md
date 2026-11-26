# Stage 2 pilot: deployment guide

For an operator running a controlled pilot beyond the one-machine demo in [`pilot/README.md`](../../pilot/README.md). Read [THREAT-MODEL.md](THREAT-MODEL.md) first.

## 0. Ground rules for any pilot

- **Data:** synthetic, shadow-mode copies, or workloads someone has explicitly authorised as non-critical and non-sensitive.
  - Records are published in plaintext (decision D3).
  - Real customer data needs a separate, written decision first.
- **Shadow only:** the adapter receives copies. Nothing in the pilot sits in a traffic path or holds a credential that can change the source.
- **No external parties without approval:**
  - Contacting any prospective customer or vendor needs approval.
  - So does enrolling a third-party witness: the public witness network, or a partner's witness.
- **Wording:** describe the result as a pilot evaluation. Do not describe it as a certification, a Proof-of-Control Tier 3/4 conformance, a partnership or an endorsement.

## 1. Hosts

| Role | Minimum | Notes |
|---|---|---|
| Log + adapter (operator) | 2 vCPU, 2 GiB RAM, disk ≈ 1.6 GiB per million events (feed plus records; see the benchmarks) | Linux, a non-root user, and the binaries or the Compose image |
| Witness | Small. A cosign round is one request per checkpoint interval | For the demo, the same host. For independence: **another party's host, under another party's control** |
| Evaluator | Any machine with the verifier | Needs only HTTP access to the public directory |

## 2. Install

**Binaries (Go 1.26):**

```sh
go build -trimpath -o /usr/local/bin/ ./cmd/harborlight-log ./cmd/harborlight-verify ./cmd/harborlight-cf-adapter
```

**Image:** `docker build -f pilot/Dockerfile -t harborlight-pilot .` (base images pinned by digest).

The pilot binaries are not yet part of the signed release set (`witness` and `enforcer`). Adding them to `release.yml` is a follow-up, so that they ship with cosign signatures, an SBOM and provenance like the rest.

## 3. Key ceremony (software keys)

```sh
harborlight-log keygen --origin pilot.example.com/<pilot-name> --out /etc/harborlight/log.key
```

- This writes `log.key` (mode 0600) and `log.key.pub`.
- The **origin** names the log forever. Use a name you control, and never reuse an origin for a different log.
- Record the public key's fingerprint, and give `log.key.pub` to evaluators **through a channel they trust**: a signed email, a meeting, or a document they already trust. Do not rely on the log's own `log.json`.
- Back up `log.key` offline. Losing it ends the log: a new key means a new origin.
- Keep it readable only by the log's user. Root on this host can sign as the log (disclosed).

Adapter token: `head -c 24 /dev/urandom | base64 > /etc/harborlight/adapter.token`, mode 0600.

## 4. Witness enrolment

Each witness needs the log's origin and public key. Each evaluator needs the witness's public key.

**Demo or own witness (no independence).** Run `omniwitness` as in `pilot/compose.yaml`, with `--additional_logs` naming your origin and key.
- Give evaluators its public key with `--operator-witness-key`, so every report says it is not independent.

**Independent witness:** a party other than the operator runs it, and holds its key.
1. Get approval: this is an external contact.
2. Send them the origin and `log.key.pub`, and agree the submission URL.
3. Get their witness public key out of band, and give it to evaluators with `--witness-key`.
4. Configure the log: `--witness '<their vkey>,<their submission URL>'`.

The [public witness network](https://witness-network.org) is the candidate. Its process and acceptance criteria are still to be verified at application time.

**Quorum.** Evaluators choose `--quorum`. With *n* independent witnesses and quorum *k*, a split view needs the operator plus *k* witnesses to collude.

## 5. Run

```sh
harborlight-cf-adapter serve --listen 127.0.0.1:8443 --feed /var/lib/harborlight/feed.jsonl \
  --token-file /etc/harborlight/adapter.token
harborlight-log run --key /etc/harborlight/log.key --data /var/lib/harborlight/log \
  --public /var/lib/harborlight/public --feed /var/lib/harborlight/feed.jsonl \
  --witness '@/etc/harborlight/witness-a.pub,https://witness-a.example/' \
  --interval 30s --listen 127.0.0.1:8080
```

Put a TLS terminator with a publicly trusted certificate in front of:
- the adapter, because Logpush requires HTTPS;
- the public directory, if evaluators reach it over the internet.

Run both programs as an unprivileged user under systemd. Restart the log on failure: it refuses to start if its records no longer match its own signed checkpoint, and that refusal is the point. Do not bypass it; investigate.

## 6. Shadow-mode Logpush configuration (when authorised)

> Use only a Logpush job that someone with authority over that Cloudflare account has approved for the pilot. Setting one up for a prospective customer needs prior approval.

- **Destination:** an HTTP destination whose `destination_conf` is the adapter's HTTPS URL. Pass the token as a header with the documented `header_` parameter, for example: `https://pilot-ingest.example.com/?dataset=ai_gateway_events&header_Authorization=Bearer%20<token>`.
- **Validation:** on creation, Logpush uploads a gzipped validation file containing `{"content":"tests"}`. The adapter accepts it and records it as a `destination_validation` control entry.
- **Fields:** select only the fields the pilot needs. `RequestBody` and `ResponseBody` are encrypted blobs in that dataset; the adapter replaces them with their hashes anyway.
- **Undocumented behaviour:** Cloudflare's documentation does not state retry, duplicate or ordering behaviour. The report shows repeated and incomplete batches. It cannot see whole batches that were never sent.

## 7. Evaluation

Give each evaluator:
- the public directory URL;
- `log.key.pub`;
- each witness's public key, marked independent or operator-run;
- the suggested `--quorum` and `--max-age` (at least two checkpoint intervals plus clock skew).

They run `harborlight-verify ... --state <file> --report report.html` on their own machine, as often as they like, and keep the state file.

## 8. Operations

- **Watch** `public/status.json`: per-witness outcome of the last round. Watch the log's stderr for `witness ...` lines.
- **Witness unreachable:** the log keeps logging, and evaluators get `UNVERIFIABLE` until it is back. This is intended.
- **Back up** the data and public directories together, after a checkpoint.
- **Do not rotate or truncate the feed** during a pilot (THREAT-MODEL §3.7).
- **Disk:** about 0.82 GiB of public records plus 0.74 GiB of feed per million events. Plan the pilot's size, and stop the adapter before the disk fills.

## 9. Rollback and teardown

The pilot is passive, so stopping it never affects traffic.

1. Disable the Logpush job, or point it back at its previous destination. Cloudflare documents that changes can take about 10–15 minutes to take effect.
2. Stop the adapter, then the log, after a final checkpoint.
3. Archive the public directory and give evaluators a final copy.
4. Destroy `log.key` and `adapter.token` if the pilot is over. Keep `log.key.pub` with the archive.
5. Ask witness operators to stop accepting the origin.
