# Harborlight pilot: evaluator quickstart

This directory runs the Stage 2 pilot on one machine, with synthetic data, so that you can:
- install it;
- generate events;
- inspect the signed evidence;
- reproduce the security tests;
- verify the evidence yourself.

**What it is:** tamper-evident, witnessed evidence for telemetry that it receives as copies (shadow mode).

**What it is not:**
- a production security guarantee;
- a certification;
- a Cloudflare product.

The Cloudflare adapter was built from Cloudflare's public Logpush documentation only. It implies no partnership or endorsement.

## Run it

**Without Docker (tested), on Linux or macOS with Go 1.26:**

```sh
pilot/demo.sh ./pilot-demo
```

The first run fetches `transparency-dev/witness` at a pinned version through the Go module proxy, checked against the Go checksum database. After that, nothing leaves the machine.

The script:
1. starts the witness, the evidence log and the adapter;
2. sends 2,000 synthetic Logpush records, delivering one batch twice on purpose;
3. verifies the evidence;
4. tampers with a copy of it;
5. stops the witness;
6. runs the adversarial suite.

**With Docker Compose:**

```sh
docker compose -f pilot/compose.yaml up -d --build
docker compose -f pilot/compose.yaml run --rm synth
sleep 15   # one checkpoint interval
docker compose -f pilot/compose.yaml run --rm verify        # writes pilot/out/report.html
docker compose -f pilot/compose.yaml run --rm adversarial
docker compose -f pilot/compose.yaml down -v                # removes everything, keys included
```

> The Compose files were written on a host without Docker and **have not been run yet**. `demo.sh` runs the same components and is tested.

## Components

| Component | What it does | Origin |
|---|---|---|
| `harborlight-cf-adapter` | Receives Logpush HTTP-destination uploads and writes them to a feed file. It is a sink: it holds no Cloudflare credential and makes no outbound request. `synth` generates synthetic `ai_gateway_events` uploads | built here |
| `harborlight-log` | Puts each feed line, in plaintext, into an RFC 6962 SHA-256 Merkle log. Signs a C2SP checkpoint every interval and has it cosigned by the witness. Serves the public directory read-only on :8080 | built here |
| `omniwitness` | A C2SP `tlog-witness`: it cosigns a checkpoint only if a consistency proof shows it extends the last one it cosigned | [transparency-dev/witness](https://github.com/transparency-dev/witness), unmodified, Apache-2.0 |
| `harborlight-verify` | The standalone verifier. It needs the public directory and public keys only | built here |
| `harborlight-adversarial` | 29 attacks, each with its expected verifier result (2 are pinned known limits) | built here |

## Verify independently

```sh
harborlight-verify --source http://127.0.0.1:8080 \
  --log-key @log.key.pub --operator-witness-key @witness.pub \
  --state my-state.json --report report.html
```

**Results:**

| Result | Meaning | Exit status |
|---|---|---|
| `VERIFIED` | Every check passed | 0 |
| `FAILED` | The evidence is provably wrong | 1 |
| `UNVERIFIABLE` | The verifier could not establish the result: an input is missing, or the witness is absent or stale | 3 |

`UNVERIFIABLE` is never a pass.

**Pin keys you got from a channel you trust.**
- The demo reads them from its own key directory for convenience.
- In a real evaluation, the operator gives you the log key, and each witness operator gives you its witness key, out of band.
- `log.json` in the public directory lists keys for information only. The verifier ignores it.

**Keep `--state` between runs.** That is what turns a rollback or a rewritten history into `FAILED` rather than a first look.

**`--operator-witness-key`** marks a witness that the log operator runs, as in this demo.
- The result still verifies, but it is labelled *witness NOT independent*.
- A witness on the operator's host proves the protocol works. It gives no independence.

## Optional: public anchoring in Rekor

Off by default, and off in the demo. When on, the log also records each new checkpoint (at most once per `--anchor-interval`, default 1 hour) in a Rekor v1 transparency log such as the public Sigstore instance. This gives a third party's signed timestamp for the records, and it catches a rewrite even if the log operator and every witness collude.

**An anchor is public and permanent.** It publishes the log's origin name, a tree size, a root and the anchoring public key; never record content. Pointing a real log at the public Rekor needs SGAIL leadership's approval.

```sh
harborlight-log anchor-keygen --out anchor.key          # ECDSA P-256; use it for nothing else
harborlight-log run ... --rekor-url https://rekor.sigstore.dev --anchor-key anchor.key
```

The log writes `anchor.json` (the latest anchor) and keeps every anchor in `anchors/<size>.json`. A Rekor outage is logged and reported in `status.json`; it never stops logging or witnessing.

To check anchors, pin Rekor's public key and the log's anchoring public key:

```sh
harborlight-verify ... --rekor-key rekor.pub --anchor-key anchor.key.pub              # offline: the latest anchor
harborlight-verify ... --rekor-key rekor.pub --anchor-key anchor.key.pub \
  --rekor-url https://rekor.sigstore.dev                                              # online: every anchor
```

- **Offline** checks Rekor's signed entry timestamp, inclusion proof and signed checkpoint, then recomputes the anchored root from the records.
- **Online** also asks Rekor for every entry made with the anchoring key, verifies each, and fails if any of them matches no prefix of the records. Use it: an operator holding the anchoring key could anchor a rewrite again, and only the earlier anchors in Rekor show that.
- Take Rekor's key from Sigstore's signed trust root (or `GET /api/v1/log/publicKey` once, kept), not from the log's files.

Uploading to a real Rekor has not been run yet. The offline checks are tested against a real entry from the public Sigstore Rekor; the upload and search code is tested against an in-process stand-in. Limits: [`THREAT-MODEL.md`](../docs/stage2/THREAT-MODEL.md) §3 item 12.

## What the evidence looks like

`curl http://127.0.0.1:8080/checkpoint` returns a [C2SP checkpoint](https://c2sp.org/tlog-checkpoint):
- the origin, the size and the root;
- the log's signature;
- the witness's `cosignature/v1` line, which carries the witness's signed timestamp.

`records.jsonl` holds one plaintext record per line. Leaf *i* is `SHA-256(0x00 || line i)`.

Example output from a real run is in [`docs/stage2/example-evaluation/`](../docs/stage2/example-evaluation/).

## Reproduce the security tests

```sh
harborlight-adversarial            # or: go test ./internal/pilot/... ./pkg/tlog ./pkg/checkpoint
```

Every case states its attack and expected result. The suite exits 0 only if all 29 match. Two cases are **known limits**: attacks the pilot does not stop under the stated conditions (collusion without Rekor pins; a re-anchored rewrite checked offline). They pin the disclosed behaviour; they do not mean the attack is stopped.

The interop test against a real omniwitness needs two environment variables:

```sh
HL_OMNIWITNESS=path/to/omniwitness HL_GENERATE_KEYS=path/to/generate_keys \
  go test -run Interop -v ./pkg/checkpoint
```

## Pinned components

- `github.com/transparency-dev/witness` `v0.0.0-20261125093440-4aa9dadc1f0b` (`omniwitness`, `generate_keys`)
- `golang:1.26.11-bookworm@sha256:ea47ee45f1284d60f9cc09cb2c3bb4f508c256b640bd8bb30342ff13d1adcb52` (build stage)
- `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` (runtime)
- Go modules: `golang.org/x/mod` v0.43.0, for signed notes and as a test oracle for the tree

**Further reading:**
- Security limits: [`docs/stage2/THREAT-MODEL.md`](../docs/stage2/THREAT-MODEL.md)
- Deployment beyond this demo: [`docs/stage2/DEPLOYMENT-GUIDE.md`](../docs/stage2/DEPLOYMENT-GUIDE.md)
