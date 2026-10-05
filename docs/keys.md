# Witness Key Management

## Signing Modes

Witness signs Merkle tree heads with ed25519. Two modes are supported:

| Mode | Flag | Key source | When to use |
|------|------|------------|-------------|
| Dev | `--dev` | `~/.witness/dev-signing.key` | Local testing, staging |
| PIV (hardware) | *(default)* | YubiKey slot 0x9a | Production |

The BLAKE3-keyed MAC over the tree head is always present regardless of mode.
The ed25519 signature is written into `tree-head.json` alongside the MAC and
is verified on every `Open`. When the daemon opens the log it requires the
signature to come from its own signer or from a key in the trust allowlist; the
`signer_key` written in the head file is not taken at its word, because anyone
who can rewrite the log can rewrite that field too. Commands that open the log
without a signer (`witness verify`, `witness audit`, `witness prove`) have no
key to pin to and check the MAC and the signature as written.

---

## Dev Signer

Key path: `~/.witness/dev-signing.key`  
Format: 32-byte raw ed25519 seed, mode 0400  
Created automatically on first `witness --dev start`

**Never use the dev key on a production machine.** The daemon prints a warning
banner every startup when `--dev` is active.

### Rotation

Add the current public key to the trust allowlist if it isn't there already
(`witness soul sign` adds it), then delete the key file and restart with
`--dev`. A new key is generated and the next `Append` re-signs the tree head
with the new key. Without the old key in the allowlist the daemon refuses to
open the log and prints the line to add. Previously written tree
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
4. The current head is still signed by the old key; the daemon accepts it
   because the old key is in the allowlist, and its first entry re-signs the
   head with the new key.
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

The allowlist is used by `witness soul verify`, by `checkSoulSignature` at
daemon start, and by the daemon when it opens the log: a tree head signed by a
key that is neither the daemon's signer nor in the allowlist is rejected
(`ErrUnexpectedSigner`).

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
