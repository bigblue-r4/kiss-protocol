# Transparency Mirror Setup

The witness daemon can push a signed copy of the local Merkle log tree-head to
an external transparency mirror after every drift tick and at daemon start.
An operator or auditor can compare the pinned local log against the mirror
using the strict audit command below. This detects some inconsistencies; it
does not authenticate the remote head or provide full rollback protection.

## Configuration

Add `mirror_url` to `~/.witness/config.json`:

```json
{
  "mirror_url": "https://mirror.example.com/witness"
}
```

Supported URL schemes:

| Scheme | Backend | Notes |
|--------|---------|-------|
| `file://` | Local filesystem | Useful for testing |
| `https://` | HTTP/HTTPS | Standard REST endpoint |
| `http://` | HTTP | Dev/internal only; avoid on untrusted networks |
| `s3://` | S3-compatible object store | Requires `-tags s3` build |

---

## HTTP/HTTPS Mirror

The witness daemon performs a `PUT /tree-head.json` to push and a
`GET /tree-head.json` to fetch. Any server that accepts those two methods
and returns the stored body on GET is compatible.

**Optional bearer token authentication:**

```bash
export WITNESS_MIRROR_TOKEN=<token>
```

If set, the daemon sends `Authorization: Bearer <token>` on every request.

TLS 1.2+ is enforced for `https://` endpoints. Self-signed certs require
the CA to be trusted at the OS level or via `SSL_CERT_FILE`.

---

## S3-Compatible Object Store

Rebuild with the `s3` tag to enable:

```bash
go build -tags s3 ./cmd/witness/...
```

Set `mirror_url` to an S3 bucket URL:

```json
{ "mirror_url": "s3://my-bucket/witness" }
```

The key written is `<prefix>/tree-head.json` (or `tree-head.json` if no prefix
is given).

### Required environment variables

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Access key ID |
| `AWS_SECRET_ACCESS_KEY` | Secret access key |
| `AWS_DEFAULT_REGION` | Region (default: `us-east-1`) |

### Optional

| Variable | Description |
|----------|-------------|
| `AWS_REGION` | Fallback if `AWS_DEFAULT_REGION` is unset |
| `AWS_ENDPOINT_URL` | Custom endpoint for R2, MinIO, etc. |

### AWS S3

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-west-2
# mirror_url: "s3://my-bucket/witness"
```

Grant the IAM user `s3:PutObject` and `s3:GetObject` on
`arn:aws:s3:::my-bucket/witness/*`.

### Cloudflare R2

```bash
export AWS_ENDPOINT_URL=https://<account-id>.r2.cloudflarestorage.com
export AWS_ACCESS_KEY_ID=<r2-access-key>
export AWS_SECRET_ACCESS_KEY=<r2-secret>
export AWS_DEFAULT_REGION=auto
```

### MinIO

```bash
export AWS_ENDPOINT_URL=http://localhost:9000
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin
export AWS_DEFAULT_REGION=us-east-1
```

---

## File Mirror (Testing)

```json
{ "mirror_url": "file:///tmp/witness-mirror" }
```

The directory is created automatically. The file `tree-head.json` inside it
is updated atomically (write to `.tmp`, rename).

### Leaf-hash feed (`leaves.bin`): history continuity off-host

A signed head proves the log's root at one size. On its own, a later head can
describe a completely rewritten history (someone with root on the host holds
the signing key). The file mirror therefore also keeps `leaves.bin`: the
32-byte Merkle leaf hash of every record, in log order, written **before** each
head is pushed, so the feed always covers the published head. Leaf hashes are
BLAKE3 of the record JSON and carry no record content. (Someone who can read
the mirror could still confirm a guessed record.)

An off-host puller keeps **its own copy** of the feed. On each pull it appends
only the leaves after the size it already holds, then checks the signed head
(after verifying its signature itself):

```bash
witness verify-leaves --leaves held-leaves.bin --size N --root HEX   # 0 ok, 1 mismatch, 2 usage/IO
```

A rewrite of any record the puller already holds changes the root, so the
check exits 1. Copying the host's whole feed afresh would defeat this; the
held copy is the point. If the log is re-initialised, the daemon rewrites the
feed and records `mirror_leaf_feed_reset`; the puller must start a new epoch
deliberately.

---

## Auditing

```bash
witness audit --require-pins --pubkey-file /etc/witness/trusted-signers.txt
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Local and mirror agree, or mirror is behind within the tolerated lag (default: 10 leaves) |
| `1` | Local integrity/signer verification or arguments failed, or mirror disagrees (same size with a different root, or larger than local). Investigate the reported reason. |
| `2` | Mirror unreachable/unusable, returned unparseable data, or lags beyond `--max-lag` |

Provision `/etc/witness/trusted-signers.txt` from independently verified
operator keys, using the soul allowlist format (`<label> <64-hex-key>`).
Never obtain the trusted key from the head currently being audited. An empty,
missing, unreadable, malformed, or untrusted pin set fails verification.
Protect both the file and its parent directory against writes by the witness
account. Multiple independently approved keys can be provisioned during rotation.

### Scheduled production audit (Linux/systemd)

The repository includes `witness-audit.service` and `witness-audit.timer`.
The service hard-codes `--require-pins` and the administrator-managed pin file;
there is no unpinned fallback. It runs every five minutes as `witness`, reads
state with `HOME=/var/lib/witness` (matching `witness.service`), and has a
read-only filesystem sandbox. It needs no signing key or hardware token.
The installer does not enable it automatically: provision trusted pins and an
independently hosted HTTPS mirror first.

With a witness binary that supports `--require-pins`, run from the repository
root after configuring `mirror_url` in
`/var/lib/witness/.witness/config.json`:

```bash
# trusted-signers.txt is an independently verified file you provisioned.
sudo install -d -o root -g witness -m 0750 /etc/witness
sudo install -o root -g witness -m 0640 ./trusted-signers.txt /etc/witness/trusted-signers.txt
sudo install -o root -g root -m 0644 packaging/systemd/witness-audit.service /etc/systemd/system/
sudo install -o root -g root -m 0644 packaging/systemd/witness-audit.timer /etc/systemd/system/
sudo systemctl daemon-reload
# This must succeed before scheduling. Missing pins or configuration fail.
sudo systemctl start witness-audit.service
sudo journalctl -u witness-audit.service -n 20 --no-pager
sudo systemctl enable --now witness-audit.timer
```

The optional root-managed `/etc/witness/witness-audit.env` supplies mirror
credentials and CA settings. Create it with mode `0600`, owned by root; systemd
loads it before dropping privileges. Use mirror read-only credentials where the
backend supports them. This service does not inherit the daemon's credential
file and does not write to the mirror.

Both exit 1 and exit 2 leave the oneshot service failed; neither is treated as a
successful audit. A timer alone does not send alerts. Connect service failures
and journal output to your monitoring system, distinguish unavailability from
confirmed integrity failures, and monitor timer execution from another host.
Inspect with `systemctl list-timers witness-audit.timer` and
`journalctl -u witness-audit.service`. To stop scheduling, run
`sudo systemctl disable --now witness-audit.timer` (an already running audit
may finish).

For cron or other orchestration, use the same strict command and preserve its
exit status. Local verification without a mirror should likewise use
`witness verify --require-pins --pubkey-file /etc/witness/trusted-signers.txt`.

---

## Security Notes

- The daemon pushes the tree-head after every drift tick and once at startup.
  Push failures are logged but do not halt the daemon.
- The tree-head JSON contains an ed25519 signature covering the size and root.
  The current audit compares size/root with the pinned local head; it does not
  authenticate the mirror head. An older mirror head within the tolerated lag
  can pass, and coordinated rollback of local and mirrored state can pass.
  Independently retained authenticated checkpoints and continuity verification
  are still required for robust rollback detection. This scheduled job does
  not implement those protections.
- AWS Sig V4 is implemented in-tree with no SDK dependency, consistent with the
  project's minimal third-party surface area principle.
- Store credentials in a secrets manager or environment file with mode `0400`;
  never in `config.json`.
