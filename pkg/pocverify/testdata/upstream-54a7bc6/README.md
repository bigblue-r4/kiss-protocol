# Upstream Proof-of-Control test vectors (test data only)

Copied unmodified from `schema/vectors/` of
[LFDT-ProofOfControl/ov-poc-standard](https://github.com/LFDT-ProofOfControl/ov-poc-standard)
at commit `54a7bc67140b39c9107216cd390dd47c1d42946d` (Working Draft v0.1).

- License: Apache License 2.0, © Advanced AI Society and the Proof-of-Control
  contributors. See `UPSTREAM-LICENSE.md`.
- `SHA256SUMS` lists the files as copied; `TestVendoredVectorsUnchanged` checks them.
- `manifest.json` contains a private key seed that upstream **published on
  purpose** for re-signing vectors. It signs nothing but test vectors.
- These are the only upstream files used. The verifier in `pkg/pocverify` was
  written from the specification's prose and schema documents; upstream's
  `validate.py` and `impl/` were not read.
