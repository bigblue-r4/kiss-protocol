# Witness Key Management

## Signing Modes

Witness signs Merkle tree heads with ed25519. Two modes are supported:

| Mode | Flag | Key source | When to use |
|------|------|------------|-------------|
| Dev | `--dev` | `~/.witness/dev-signing.key` | Local testing, staging |
| PIV (hardware) | *(default)* | YubiKey slot 0x9a | Production |

The BLAKE3-keyed MAC over the tree head is always present regardless of mode.
The ed25519 signature is written into `tree-head.json` alongside the MAC and
is verified on every `Open`.

---

## Dev Signer

Key path: `~/.witness/dev-signing.key`  
Format: 32-byte raw ed25519 seed, mode 0400  
Created automatically on first `witness --dev start`

**Never use the dev key on a production machine.** The daemon prints a warning
banner every startup when `--dev` is active.

### Rotation

Delete the key file and restart with `--dev`. A new key is generated and the
next `Append` re-signs the tree head with the new key. Previously written tree
heads remain valid (they embed their own public key).

---

## PIV / YubiKey Signer (build tag `piv`)

The PIV signer is compiled only when you build with `-tags piv`:

```
go build -tags piv ./cmd/witness
```

It requires `libpcsclite` on Linux / `CryptoTokenKit` on macOS.

### Key generation

Generate an ed25519 key in slot 0x9a with a self-signed attestation:

```
ykman piv keys generate --algorithm ED25519 9a pubkey.pem
ykman piv certificates generate --subject "CN=witness" 9a pubkey.pem
```

Then register the public key in the trust allowlist:

```
witness soul trust add --label "$(hostname)-piv" pubkey.pem
```

### PIN policy

DefaultPIN auth is used (PIN required once per session). Set a strong PIN:

```
ykman piv access change-pin
```

### Rotation

1. Generate a new key on the replacement YubiKey (or a new slot).
2. Add the new public key to the allowlist on all verifying machines.
3. Restart `witness` — the next `Append` writes a tree head signed by the new key.
4. Old tree heads remain self-verifiable; they embed their own `signer_key`.
5. Remove the old entry from the allowlist once you are confident no rollback is needed.

---

## Trust Allowlist

Path: `~/.witness/trust/signers.txt` (mode 0400, owned by the `witness` user)

Format — one entry per line, `#` lines are comments:

```
# label  hex-encoded-ed25519-public-key
prod-piv  4a3b...
backup    9f1c...
```

The allowlist is used by `witness soul verify` and by `checkSoulSignature` at
daemon start. It is **not** used by tree head verification — tree heads are
self-describing (they embed the signer's public key).

### Bootstrap

On first setup, add the key that will sign soul files:

```
witness soul trust add --label "$(hostname)-piv" pubkey.pem
```

For dev mode:

```
witness --dev soul trust add --label dev ~/.witness/dev-signing.key.pub
```

---

## Soul File Signing

The soul file (`soul.toml`) must be signed by a key in the allowlist before
the daemon will start in production mode.

```
witness soul sign               # uses PIV key
witness --dev soul sign         # uses dev key

witness soul verify             # checks against allowlist
```

Signature is stored at `soul.toml.sig` alongside the soul file. The `.sig`
file is JSON:

```json
{
  "algorithm":  "ed25519",
  "signer_key": "<hex pubkey>",
  "signature":  "<hex sig>",
  "signed_at":  "2026-01-01T00:00:00Z"
}
```

Re-sign after any edit to `soul.toml`.

---

## Recovery

### Lost dev key

Delete `~/.witness/dev-signing.key`. Restart with `--dev` to generate a fresh key.
Tree head verification continues because the MAC key (derived from the machine
ID via HKDF) is unaffected. The new dev key signs future tree heads.

### Lost or compromised PIV key

1. Remove the compromised entry from the allowlist.
2. Provision a new YubiKey / slot.
3. Add the new public key to the allowlist.
4. Re-sign `soul.toml` with the new key.
5. Restart witness.

Past log integrity is unaffected — tree heads are verified by the key they
embed, not the current allowlist.

### Machine ID loss (factory reset / disk wipe)

The BLAKE3-keyed MAC uses a key derived from the machine ID. If the machine ID
changes, existing tree heads will fail MAC verification. In this scenario:

1. Use `ReadAll` + `InclusionProof` to export a signed snapshot **before** the
   wipe if possible.
2. After re-init, treat the old log as a v1 import: use `migrate.FromV1Log` to
   import into a fresh store on the new machine ID.
