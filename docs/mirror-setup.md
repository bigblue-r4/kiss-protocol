# Transparency Mirror Setup

The witness daemon can push a signed copy of the local Merkle log tree-head to
an external transparency mirror after every drift tick and at daemon start.
An operator or auditor can then run `witness audit` to compare the local log
against the mirror and detect tampering.

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

---

## Auditing

```bash
witness audit
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Local and mirror agree, or mirror is behind (push pending) |
| `1` | Mirror disagrees — size match but root differs, or mirror claims more entries than local. Investigate for tampering. |
| `2` | Mirror unreachable, misconfigured, or returned unparseable data |

Run `witness audit` from a cron job or monitoring system to provide continuous
verification that the mirror has not been tampered with independently of the
witness process.

---

## Security Notes

- The daemon pushes the tree-head after every drift tick and once at startup.
  Push failures are logged but do not halt the daemon.
- The tree-head JSON contains an ed25519 signature covering the size and root.
  A mirror that silently rolls back the log will be detected when `witness audit`
  sees a size or root mismatch.
- AWS Sig V4 is implemented in-tree with no SDK dependency, consistent with the
  project's minimal third-party surface area principle.
- Store credentials in a secrets manager or environment file with mode `0400`;
  never in `config.json`.
