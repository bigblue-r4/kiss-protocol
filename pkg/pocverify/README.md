# pocverify: clean-room Proof-of-Control evidence verifier

A second, independent verifier for Proof-of-Control **Evidence tokens** (JSON
rendering), written in Go with the standard library only. Work package WP-10(b)
of the PoC Phase 2 roadmap (`docs/poc/phase2-roadmap.md` on branch
`poc/phase1-gap-matrix`).

**Pinned specification:** LFDT-ProofOfControl/ov-poc-standard
`54a7bc67140b39c9107216cd390dd47c1d42946d`, Working Draft v0.1.

**Clean room:**
- Written from the specification's prose and schema documents only:
  `schema/README.md`, `schema/canonicalization.md`, `schema/poc-evidence.cddl`
  and `schema/poc-evidence.schema.json`.
- Upstream `validate.py`, `generate_vectors.py` and `impl/` were **not read**.
- Upstream vectors are vendored as test data (Apache-2.0, see `testdata/upstream-54a7bc6/README.md`).

## Use

```bash
go run ./cmd/poc-verify --vectors pkg/pocverify/testdata/upstream-54a7bc6
go run ./cmd/poc-verify --pubkey HEX token.json...     # 0 valid, 1 rejected, 2 usage/IO
```

## What it checks

The first failure wins, and is reported with the same code as upstream's
manifest uses, so "rejected for the stated reason" can be checked exactly.

| Code | Rule | Source |
|---|---|---|
| `duplicate-key` | duplicate member names rejected at any depth, not first- or last-wins | canonicalization.md rule 8 |
| `parse` | strict RFC 8259: UTF-8, no BOM, no lone surrogates, no trailing data | rule 1 |
| `float-in-claims` | no fraction or exponent anywhere in the token | rule 4 |
| `hex-case` | no tagged digest with uppercase hex, including extension claims | rule 6 |
| `schema` | required claims, types, the 8 interception points, verdict/alg/platform enums, tag-and-width digests, the profile URI, URIs, nonce length, absent-not-empty | JSON Schema, CDDL, rule 7 |
| `unsupported-alg` | only `EdDSA` is checked; other algorithms are refused, not passed | — |
| `signature` | Ed25519 over RFC 8785 canonical(token \ {signature}); pretty-printed input still verifies | "What is signed" |
| `tree-size` | `step_index` must be a leaf of a tree of `tree_size` | README negative vectors |
| `modify-unbound` | `MODIFY` must carry `dispatched_snapshot_hash` | JSON Schema |
| `leaf-root` | when `tree_size` is 1, `merkle_root` must equal SHA-256(0x00 ‖ canonical({"snapshot","verdict"})) | "The leaf and the tree" |

RFC 8785 is implemented in full: UTF-16 code-unit key order, minimal string
escaping, and ECMAScript `Number::toString` for numbers. It is tested against
the RFC's own examples and fuzzed for fixed-point stability.

## Results at 54a7bc6

`--vectors`: **16 of 17 agree with the upstream manifest.** The 17th is a
deliberate disagreement:

- `positive/modify-bound.json` is rejected with `leaf-root`. Its verdict is
  `MODIFY` and its `tree_size` is 1, but its `merkle_root` is the leaf for
  verdict `ALLOW`.
- Upstream's validator does not check the leaf-to-root binding, so it accepts
  this vector.
- This is upstream issue #170, fixed by upstream PR #169. When the vector is
  regenerated, `knownDisagreements` in `vectors_test.go` must be emptied (the
  test fails until it is).

**Reverse interop (2026-11-24):**
- Eight tokens built and signed by this package's test helper were run through
  upstream `schema/validate.py` as a black box (`python -I`, empty environment,
  no keys other than the published test key).
- The seven valid ones covered ALLOW, DENY, ESCALATE, MODIFY with
  `dispatched_snapshot_hash`, `tree_size` 3, `INTEL_TDX` with
  `reference_values_uri`, and an extension object with astral-plane and BMP keys.
  Upstream accepted all seven, so the canonical bytes and signatures agree.
- The eighth had an unbound root. We reject it with `leaf-root`; upstream
  accepts it, for the same reason as #170.

## What a VALID result does not mean

The result's `Notes` list these per token:

- **`chain_head` is not checked.** The draft defines it as H(previous_head ‖
  canonical_snapshot_hash ‖ verdict) but does not define the previous head for
  step 0, or the byte encoding of that concatenation.
- **The leaf-to-root binding needs an inclusion proof once `tree_size` > 1,**
  and the token carries none.
- **Hardware attestation is not verified.** A non-`SOFTWARE` platform is
  reported, not trusted: the `measurement` is not compared to reference values.
  `SOFTWARE` evidence supports Tier 2 at most.
- **Not implemented:** the CWT/CBOR rendering, the `poc-capability` and
  `poc-anchor` objects, and `ES256`/ML-DSA signatures.
- **Out of scope:** whether the evidence is *true* (that the action happened
  as recorded) and whether the issuer is trustworthy. A token proves only that
  a holder of the pinned key signed these claims.
