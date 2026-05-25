// Package signer provides the signing abstraction used by Witness to
// authenticate tree heads and soul files.
//
// Two backends are provided:
//
//   - dev: software ed25519 key stored at ~/.witness/dev-signing.key.
//     Requires the caller to pass DevMode=true. Prints a warning banner
//     on every use. Never appropriate for production.
//
//   - piv: YubiKey PIV slot (Authentication, 0x9a). Compiled in only
//     with -tags piv and requires pcsclite at runtime. See docs/keys.md.
//
// Phase 2 note: tree head signing upgrades the Phase 1 BLAKE3-keyed MAC
// to an ed25519 signature from the configured signer. The MAC is still
// written alongside the signature for local tamper-detection without the
// public key. Phase 3 hardware binding (capability drops, dedicated user)
// will harden the key storage path.
package signer

import "crypto/ed25519"

// Signer signs arbitrary byte slices with ed25519 and exposes the
// corresponding public key. Implementations must be safe for concurrent use.
type Signer interface {
	// Sign returns a raw 64-byte ed25519 signature over message.
	Sign(message []byte) ([]byte, error)
	// PublicKey returns the signer's ed25519 public key.
	PublicKey() ed25519.PublicKey
}
