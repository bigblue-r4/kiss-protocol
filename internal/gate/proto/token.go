package proto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Token lifetimes. The policy picks a class lifetime up to MaxTokenLifetime;
// a token claiming more is malformed whatever its signature.
const (
	DefaultTokenLifetime = 30 * time.Second
	MaxTokenLifetime     = 120 * time.Second
)

// WitnessHead is a witness tree head as signed by the witness: its signature
// covers only size_be8 || root (see docs/gate-arch.md C1), so the timestamp
// and prev_root are deliberately not carried.
type WitnessHead struct {
	Size      uint64 `json:"size"`
	Root      string `json:"root"`       // hex BLAKE3 Merkle root
	Sig       string `json:"sig"`        // hex ed25519 over size_be8 || root
	SignerKey string `json:"signer_key"` // hex; must be a pinned witness key
}

// Witnessed is the commit-wait evidence: the gate's own gate_request record,
// as stored in the witness log, with an inclusion proof against a signed
// head. Entry is the exact JSON the witness hashed into the leaf, so a
// verifier recomputes the leaf from it and reads the action_hash inside.
type Witnessed struct {
	Head      WitnessHead `json:"head"`
	LeafIndex uint64      `json:"leaf_index"` // 0-based
	Entry     string      `json:"entry"`      // the log entry JSON (leaf preimage)
	Proof     []string    `json:"proof"`      // hex sibling hashes, leaf to root
}

// Token is the gate's permission for exactly one action, briefly.
type Token struct {
	V            int        `json:"v"`
	TokenID      string     `json:"token_id"`    // 16 random bytes, hex; replay key
	ActionHash   string     `json:"action_hash"` // hex SHA-256 of the ActionRequest
	IssuedAt     string     `json:"issued_at"`
	ExpiresAt    string     `json:"expires_at"`
	BreakerEpoch uint64     `json:"breaker_epoch"`
	PolicyHash   string     `json:"policy_hash"` // hex SHA-256 of the policy file
	Witnessed    *Witnessed `json:"witnessed,omitempty"`
	GateKey      string     `json:"gate_key"` // hex ed25519
	Sig          string     `json:"sig,omitempty"`
}

// ErrTokenMalformed reports a token whose fields are out of form.
var ErrTokenMalformed = errors.New("token malformed")

// Times returns the issued and expiry times after checking the token's form
// (ids, hashes, keys, lifetime). It does not check the signature.
func (t Token) Times() (issued, expires time.Time, err error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrTokenMalformed, fmt.Sprintf(format, a...))
	}
	if t.V != Version {
		return issued, expires, bad("version %d", t.V)
	}
	if _, err := decodeHex(t.TokenID, 16, "token_id"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if _, err := decodeHex(t.ActionHash, 32, "action_hash"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if _, err := decodeHex(t.PolicyHash, 32, "policy_hash"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if _, err := decodeHex(t.GateKey, ed25519.PublicKeySize, "gate_key"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if issued, err = ParseTime(t.IssuedAt, "issued_at"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if expires, err = ParseTime(t.ExpiresAt, "expires_at"); err != nil {
		return issued, expires, bad("%v", err)
	}
	if life := expires.Sub(issued); life <= 0 || life > MaxTokenLifetime {
		return issued, expires, bad("lifetime %s outside (0, %s]", life, MaxTokenLifetime)
	}
	if w := t.Witnessed; w != nil {
		if w.Head.Size == 0 || w.Head.Size > 1<<48 || w.LeafIndex >= w.Head.Size {
			return issued, expires, bad("witnessed leaf %d outside head size %d", w.LeafIndex, w.Head.Size)
		}
		if w.Entry == "" {
			return issued, expires, bad("witnessed entry is empty")
		}
		if len(w.Proof) > 64 {
			return issued, expires, bad("witnessed proof has %d hashes", len(w.Proof))
		}
	}
	return issued, expires, nil
}

// SignToken fills in GateKey and Sig with s. t.Sig is ignored and replaced.
func SignToken(t Token, s Signer) (Token, error) {
	t.Sig = ""
	t.GateKey = hex.EncodeToString(s.PublicKey())
	if _, _, err := t.Times(); err != nil {
		return Token{}, err
	}
	in, err := sigInput(DomainToken, t)
	if err != nil {
		return Token{}, err
	}
	sig, err := s.Sign(in)
	if err != nil {
		return Token{}, fmt.Errorf("sign token: %w", err)
	}
	t.Sig = hex.EncodeToString(sig)
	return t, nil
}

// VerifyTokenSig checks the token's form and that it is signed by one of the
// pinned gate keys. The gate_key the token names is only trusted if pinned.
func VerifyTokenSig(t Token, gateKeys []ed25519.PublicKey) error {
	if _, _, err := t.Times(); err != nil {
		return err
	}
	pub, _ := hex.DecodeString(t.GateKey)
	if !keyIn(pub, gateKeys) {
		return errors.New("gate proto: token signed by a key that is not a pinned gate key")
	}
	unsigned := t
	unsigned.Sig = ""
	in, err := sigInput(DomainToken, unsigned)
	if err != nil {
		return err
	}
	return verifySig(ed25519.PublicKey(pub), in, t.Sig, "token")
}

// DecodeToken decodes a canonical Token (no signature check).
func DecodeToken(data []byte) (Token, error) {
	var t Token
	return t, decodeCanonical(data, &t)
}
