package proto

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// Reset asks the gate to close one tripped scope. It takes effect only with
// partial signatures from at least M distinct operators (the policy's quorum).
// Each operator signs the same Reset; nonce makes every reset single-use.
type Reset struct {
	V        int    `json:"v"`
	Scope    Scope  `json:"scope"`
	NewEpoch uint64 `json:"new_epoch"` // must be the gate's current epoch + 1
	Reason   string `json:"reason"`
	Nonce    string `json:"nonce"` // 16 random bytes, hex
	TS       string `json:"ts"`
}

// PartialSig is one operator's signature over a Reset.
type PartialSig struct {
	OperatorLabel string `json:"operator_label"`
	Sig           string `json:"sig"`
}

// ResetBundle is a Reset with the partial signatures collected for it.
type ResetBundle struct {
	Reset    Reset        `json:"reset"`
	Partials []PartialSig `json:"partials"`
}

// ErrQuorumNotMet reports a reset without enough distinct operator signatures.
var ErrQuorumNotMet = errors.New("reset quorum not met")

// Validate checks the reset's form.
func (r Reset) Validate() error {
	if r.V != Version {
		return fmt.Errorf("gate proto: reset version %d", r.V)
	}
	if err := r.Scope.Validate(); err != nil {
		return err
	}
	if r.NewEpoch == 0 {
		return errors.New("gate proto: reset new_epoch must be positive")
	}
	if !printable(r.Reason, 1024) {
		return errors.New("gate proto: reset reason must be 1-1024 printable bytes")
	}
	if _, err := decodeHex(r.Nonce, 16, "nonce"); err != nil {
		return err
	}
	_, err := ParseTime(r.TS, "ts")
	return err
}

// SignReset returns label's partial signature over r.
func SignReset(r Reset, label string, s Signer) (PartialSig, error) {
	if err := r.Validate(); err != nil {
		return PartialSig{}, err
	}
	in, err := sigInput(DomainReset, r)
	if err != nil {
		return PartialSig{}, err
	}
	sig, err := s.Sign(in)
	if err != nil {
		return PartialSig{}, fmt.Errorf("sign reset: %w", err)
	}
	return PartialSig{OperatorLabel: label, Sig: hex.EncodeToString(sig)}, nil
}

// VerifyResetQuorum checks that at least m distinct operator keys signed
// b.Reset and returns the labels counted. Invalid partials are skipped, not
// fatal, so one bad file cannot block a reset that otherwise has quorum.
// Nonce reuse and the epoch are the gate's to check: they need its state.
func VerifyResetQuorum(b ResetBundle, ops []Operator, m int) ([]string, error) {
	if m < 1 {
		return nil, errors.New("gate proto: reset quorum must be at least 1")
	}
	if err := b.Reset.Validate(); err != nil {
		return nil, err
	}
	in, err := sigInput(DomainReset, b.Reset)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var labels []string
	for _, p := range b.Partials {
		for _, op := range ops {
			if op.Label != p.OperatorLabel {
				continue
			}
			if verifySig(op.Key, in, p.Sig, "reset") != nil {
				continue
			}
			k := hex.EncodeToString(op.Key)
			if !seen[k] {
				seen[k] = true
				labels = append(labels, op.Label)
			}
			break
		}
	}
	if len(labels) < m {
		return labels, fmt.Errorf("%w: %d valid of %d required", ErrQuorumNotMet, len(labels), m)
	}
	return labels, nil
}

// DecodeResetBundle decodes a canonical ResetBundle (no signature check).
func DecodeResetBundle(data []byte) (ResetBundle, error) {
	var b ResetBundle
	return b, decodeCanonical(data, &b)
}
