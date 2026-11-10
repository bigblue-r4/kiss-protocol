// Package proto defines the gate's wire formats and their pure checks:
// ActionRequest and its action_hash, Approval, Token, Epoch and Reset.
//
// These are the contracts between the gate, the operators who approve and
// reset, and the protected services that verify tokens (pkg/gateenforce). The
// package is pure and stdlib-only: no I/O, no clock reads (callers pass now),
// no dependency on the witness. See docs/gate-arch.md section 4.
//
// Encoding rules, shared by every signed type:
//
//   - canonical JSON = encoding/json of the Go struct (field order fixed by the
//     struct), HTML escaping off, no trailing newline;
//   - no maps and no floats in signed structs; values that are not small
//     counters are strings (amounts are decimal strings, keys and hashes are
//     lowercase hex);
//   - decoders reject unknown fields, trailing data, and any input that is not
//     byte-identical to its own canonical encoding, so one value has exactly
//     one accepted spelling (no duplicate keys, no case-folded keys, no
//     reordered fields);
//   - every signature covers "<domain>\n" || canonical(value without its sig),
//     and the sig field is omitted, not emptied, when unsigned.
package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Version is the only format version this package reads or writes.
const Version = 1

// Signature domains. Each ends in a newline so no domain is a prefix of
// another domain plus content, and none can collide with the witness's
// 40-byte tree-head signature input (size_be8 || root), which has no prefix.
const (
	DomainAction   = "kiss-gate/action/1\n"
	DomainApproval = "kiss-gate/approval/1\n"
	DomainToken    = "kiss-gate/token/1\n"
	DomainEpoch    = "kiss-gate/epoch/1\n"
	DomainReset    = "kiss-gate/reset/1\n"
	DomainPolicy   = "kiss-gate/policy/1\n"
)

// ErrNotCanonical reports input that decodes but is not the canonical
// encoding of what it decodes to.
var ErrNotCanonical = errors.New("gate proto: input is not in canonical form")

// Signer is the signing interface the gate and operators use. It matches
// internal/signer.Signer without importing it.
type Signer interface {
	Sign(message []byte) ([]byte, error)
	PublicKey() ed25519.PublicKey
}

// Canonical returns the canonical JSON encoding of v.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// decodeCanonical decodes data into v strictly and requires data to be v's
// canonical encoding.
func decodeCanonical(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("gate proto: decode: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("gate proto: trailing data after value")
	}
	re, err := Canonical(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(re, data) {
		return ErrNotCanonical
	}
	return nil
}

// sigInput returns domain || canonical(v).
func sigInput(domain string, v any) ([]byte, error) {
	c, err := Canonical(v)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), c...), nil
}

// decodeHex decodes lowercase hex of exactly n bytes.
func decodeHex(s string, n int, what string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n || hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("gate proto: %s must be %d bytes of lowercase hex", what, n)
	}
	return b, nil
}

// FormatTime renders t the way every gate timestamp is written: RFC 3339,
// UTC, nanoseconds with trailing zeros dropped.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ParseTime parses a gate timestamp. Only the FormatTime spelling is accepted.
func ParseTime(s, what string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || FormatTime(t) != s {
		return time.Time{}, fmt.Errorf("gate proto: %s must be an RFC 3339 UTC time as written by FormatTime, got %q", what, s)
	}
	return t, nil
}

// verifySig checks sig (hex) by pub over msg.
func verifySig(pub ed25519.PublicKey, msg []byte, sigHex, what string) error {
	sig, err := decodeHex(sigHex, ed25519.SignatureSize, what+" signature")
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("gate proto: %s signature does not verify", what)
	}
	return nil
}

// keyIn reports whether pub is one of pins.
func keyIn(pub []byte, pins []ed25519.PublicKey) bool {
	for _, p := range pins {
		if bytes.Equal(pub, p) {
			return true
		}
	}
	return false
}

// Operator is one entry of the gate's operator allowlist
// (/etc/gate/trust/operators.txt, "<label> <hex-key>").
type Operator struct {
	Label string
	Key   ed25519.PublicKey
}

// printable reports whether s is non-empty, at most max bytes and free of
// control characters.
func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
