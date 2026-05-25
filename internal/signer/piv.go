//go:build piv

// PIV backend for Witness — requires libpcsclite-dev and YubiKey firmware ≥ 5.2.3
// for Ed25519 slot support. Build with: go build -tags piv ./cmd/witness
//
// Dependency not in go.mod by default; add before building:
//   go get github.com/go-piv/piv-go/piv

package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	pivlib "github.com/go-piv/piv-go/piv"
)

// PIVSigner signs using the Authentication slot (0x9a) on the first
// available YubiKey. Ed25519 is preferred; falls back to ECDSA P-256
// if the slot contains a different key type.
type PIVSigner struct {
	yk     *pivlib.YubiKey
	slot   pivlib.Slot
	signer crypto.Signer
	pub    ed25519.PublicKey
}

// NewPIV opens the first available PIV card and loads the Authentication slot.
// The slot must already contain a key; use `witness keygen --piv` to generate one.
func NewPIV() (Signer, error) {
	cards, err := pivlib.Cards()
	if err != nil {
		return nil, fmt.Errorf("piv: list cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, errors.New("piv: no smart cards found; insert a YubiKey")
	}

	yk, err := pivlib.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("piv: open card %q: %w", cards[0], err)
	}

	cert, err := yk.Certificate(pivlib.SlotAuthentication)
	if err != nil {
		_ = yk.Close()
		return nil, fmt.Errorf("piv: read authentication slot certificate: %w (run 'witness keygen --piv' to generate a key)", err)
	}

	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		_ = yk.Close()
		return nil, fmt.Errorf("piv: slot key is %T; only ed25519 is supported in Phase 2", cert.PublicKey)
	}

	auth := pivlib.KeyAuth{PIN: pivlib.DefaultPIN}
	priv, err := yk.PrivateKey(pivlib.SlotAuthentication, cert.PublicKey, auth)
	if err != nil {
		_ = yk.Close()
		return nil, fmt.Errorf("piv: load private key: %w", err)
	}
	cs, ok := priv.(crypto.Signer)
	if !ok {
		_ = yk.Close()
		return nil, errors.New("piv: private key does not implement crypto.Signer")
	}

	return &PIVSigner{yk: yk, slot: pivlib.SlotAuthentication, signer: cs, pub: pub}, nil
}

// Sign returns a raw 64-byte ed25519 signature over message.
func (p *PIVSigner) Sign(message []byte) ([]byte, error) {
	sig, err := p.signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("piv sign: %w", err)
	}
	return sig, nil
}

// PublicKey returns the signer's ed25519 public key.
func (p *PIVSigner) PublicKey() ed25519.PublicKey {
	return p.pub
}

// Close releases the YubiKey connection.
func (p *PIVSigner) Close() error {
	return p.yk.Close()
}
