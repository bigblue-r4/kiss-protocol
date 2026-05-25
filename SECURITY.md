# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v2.x    | Yes       |
| v1.x    | Critical fixes only — upgrade to v2 recommended |

## Reporting a Vulnerability

**Do not open a public GitHub issue with exploit details.**

Use a private channel first:

1. **GitHub Security Advisories (preferred):** Open a private advisory at
   `https://github.com/bigblue-r4/kiss-protocol/security/advisories/new`

2. **Email:** Contact the maintainer through the GitHub profile. Until a
   dedicated security mailbox is published, GitHub Advisories is the fastest
   path.

Please include:

- Affected version or commit SHA
- Reproduction steps (minimal PoC preferred)
- Impact assessment (what an attacker can achieve)
- Any suggested mitigation or patch

## Disclosure Timeline

| Day | Action |
|-----|--------|
| 0   | Report received; acknowledgement within 72 hours |
| 1–7 | Reproduce and triage |
| 7–30 | Develop and test fix |
| 30  | Release patched version |
| 45  | Public disclosure (coordinated with reporter) |

We target 30 days from report to patch. Critical issues affecting active
deployments may warrant an expedited timeline — please say so in the report.

## Scope

In scope for this policy:

- `cmd/witness` daemon and CLI
- `cmd/witness-pd` law enforcement edition
- All `internal/` packages
- Install scripts (`install.sh`, `harborlight-install.sh`)
- Release artifacts (supply-chain / build reproducibility issues)

Out of scope (per `docs/threat-model.md` non-goals):

- Physical extraction of PIV/hardware-token key material
- CPU side-channel attacks (Spectre, Meltdown, etc.)
- Denial of service against the host (Witness is a witness, not an availability guarantee)
- Confidentiality of log payload contents (Witness proves integrity, not secrecy)
- Kernel rootkits / ring-0 code execution (best-effort only; documented honestly)

## Verifying a Release

All release artifacts (v2.x and later) are signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
using GitHub Actions OIDC (keyless). Verification:

```bash
cosign verify-blob \
  --certificate-identity-regexp \
    "https://github.com/bigblue-r4/kiss-protocol/.github/workflows/release.yml" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature witness_linux_amd64.sig \
  --certificate witness_linux_amd64.pem \
  witness_linux_amd64
```

SHA-256 checksums are also published alongside each release artifact.

## Security Architecture

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat model,
attacker capability assumptions, guarantees by mechanism, and explicit non-goals.

See [`docs/audit-prep.md`](docs/audit-prep.md) for a checklist prepared for
external security reviewers.
