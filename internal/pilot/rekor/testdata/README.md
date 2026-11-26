# Test data

- `rekor.sigstore.dev.pub`: the public Sigstore Rekor log key, from
  `GET https://rekor.sigstore.dev/api/v1/log/publicKey` (2026-11-26).
- `public-entry-4132600001.json`: an existing entry, unrelated to this project,
  fetched read-only with `GET /api/v1/log/entries?logIndex=4132600001`
  (2026-11-26). Its certificate names an automated build identity, not a person.

They pin this package's offline checks (signed entry timestamp, UUID,
inclusion proof, signed checkpoint) to what the real service returns. Nothing
was written to Rekor to make them.
