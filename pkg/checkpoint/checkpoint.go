// Package checkpoint reads, writes, signs and verifies C2SP checkpoints
// (c2sp.org/tlog-checkpoint) and their Ed25519 cosignatures
// (c2sp.org/tlog-cosignature, cosignature/v1, signature type 0x04).
//
// The log's own signature is a signed-note Ed25519 signature (type 0x01),
// made and checked with golang.org/x/mod/sumdb/note. Cosignatures are
// checked here, because that package does not implement type 0x04.
//
// ML-DSA-44 cosignatures (type 0x06), which the specification recommends
// for new witnesses, are not supported yet: a verifier pinned to such a key
// reports it as unsupported rather than as verified.
package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
	"golang.org/x/mod/sumdb/note"
)

// Signature types (c2sp.org/signed-note).
const (
	TypeEd25519     = 0x01
	TypeCosignature = 0x04
	TypeMLDSA44     = 0x06
)

// MaxSignatures bounds the signature lines accepted in one note.
const MaxSignatures = 64

// Checkpoint is the signed body of a C2SP checkpoint.
type Checkpoint struct {
	Origin     string
	Size       uint64
	Root       tlog.Hash
	Extensions []string
}

// Text returns the checkpoint body exactly as it is signed.
func (c Checkpoint) Text() []byte {
	var b bytes.Buffer
	b.WriteString(c.Origin + "\n")
	b.WriteString(strconv.FormatUint(c.Size, 10) + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(c.Root[:]) + "\n")
	for _, e := range c.Extensions {
		b.WriteString(e + "\n")
	}
	return b.Bytes()
}

// ValidName reports whether s is a valid origin or key name: non-empty
// UTF-8 of at most 255 bytes, with no Unicode space, no '+' and no control
// character.
func ValidName(s string) error {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return errors.New("checkpoint: name must be 1-255 bytes of UTF-8")
	}
	for _, r := range s {
		if r == '+' || unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return fmt.Errorf("checkpoint: name %q contains a forbidden character", s)
		}
	}
	return nil
}

// ParseText parses a checkpoint body.
func ParseText(text []byte) (Checkpoint, error) {
	if !utf8.Valid(text) || len(text) == 0 || text[len(text)-1] != '\n' {
		return Checkpoint{}, errors.New("checkpoint: body must be UTF-8 ending in a newline")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, errors.New("checkpoint: body has fewer than three lines")
	}
	var c Checkpoint
	c.Origin = lines[0]
	if err := ValidName(c.Origin); err != nil {
		return Checkpoint{}, err
	}
	size, err := parseDecimal(lines[1])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: size: %w", err)
	}
	c.Size = size
	root, err := DecodeHash(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("checkpoint: root: %w", err)
	}
	c.Root = root
	for _, e := range lines[3:] {
		if e == "" {
			return Checkpoint{}, errors.New("checkpoint: empty extension line")
		}
		for _, r := range e {
			if r < 0x20 || r == 0x7f {
				return Checkpoint{}, errors.New("checkpoint: control character in extension line")
			}
		}
		c.Extensions = append(c.Extensions, e)
	}
	return c, nil
}

func parseDecimal(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("not a canonical decimal")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not a canonical decimal")
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

// DecodeHash decodes a canonical standard-base64 SHA-256 hash.
func DecodeHash(s string) (tlog.Hash, error) {
	var h tlog.Hash
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != len(h) || base64.StdEncoding.EncodeToString(b) != s {
		return h, errors.New("not a canonical base64 32-byte hash")
	}
	copy(h[:], b)
	return h, nil
}

// SigLine is one signature line of a signed note.
type SigLine struct {
	Name    string
	KeyID   uint32
	Payload []byte // after the key ID
}

// String renders the line, with its trailing newline.
func (l SigLine) String() string {
	b := make([]byte, 4+len(l.Payload))
	binary.BigEndian.PutUint32(b, l.KeyID)
	copy(b[4:], l.Payload)
	return "— " + l.Name + " " + base64.StdEncoding.EncodeToString(b) + "\n"
}

// Signed is a parsed, not yet verified, signed checkpoint.
type Signed struct {
	Raw        []byte
	Text       []byte
	Checkpoint Checkpoint
	Sigs       []SigLine
}

// Open parses a signed checkpoint note. It verifies nothing.
func Open(raw []byte) (*Signed, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("checkpoint: note is not UTF-8")
	}
	for _, c := range raw {
		if c < 0x20 && c != '\n' || c == 0x7f {
			return nil, errors.New("checkpoint: control character in note")
		}
	}
	i := bytes.LastIndex(raw, []byte("\n\n"))
	if i < 0 {
		return nil, errors.New("checkpoint: note has no signature block")
	}
	text, block := raw[:i+1], raw[i+2:]
	if len(block) == 0 || block[len(block)-1] != '\n' {
		return nil, errors.New("checkpoint: signature block must end in a newline")
	}
	cp, err := ParseText(text)
	if err != nil {
		return nil, err
	}
	s := &Signed{Raw: raw, Text: text, Checkpoint: cp}
	seen := map[[2]any]bool{}
	for _, line := range strings.Split(string(block[:len(block)-1]), "\n") {
		l, err := parseSigLine(line)
		if err != nil {
			return nil, err
		}
		k := [2]any{l.Name, l.KeyID}
		if seen[k] {
			return nil, fmt.Errorf("checkpoint: two signatures from %s with the same key ID", l.Name)
		}
		seen[k] = true
		s.Sigs = append(s.Sigs, l)
		if len(s.Sigs) > MaxSignatures {
			return nil, errors.New("checkpoint: too many signatures")
		}
	}
	return s, nil
}

func parseSigLine(line string) (SigLine, error) {
	rest, ok := strings.CutPrefix(line, "— ")
	if !ok {
		return SigLine{}, errors.New("checkpoint: malformed signature line")
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok || ValidName(name) != nil {
		return SigLine{}, errors.New("checkpoint: malformed signature line")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) < 5 || base64.StdEncoding.EncodeToString(b) != b64 {
		return SigLine{}, errors.New("checkpoint: malformed signature")
	}
	return SigLine{Name: name, KeyID: binary.BigEndian.Uint32(b), Payload: b[4:]}, nil
}

// KeyID computes the signed-note key ID for a key of the given type.
func KeyID(name string, typ byte, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// SignLog signs a checkpoint body as the log, with a note signer from a
// note private key (note.GenerateKey / note.NewSigner).
func SignLog(c Checkpoint, signer note.Signer) ([]byte, error) {
	return note.Sign(&note.Note{Text: string(c.Text())}, signer)
}

// VerifyLog checks the log signature on s with the pinned log verifier key
// (a note verifier key, "name+id+base64"). At least one signature by that
// key must be present, and every one present must verify. The note's other
// signatures (cosignatures) are ignored here.
func (s *Signed) VerifyLog(vkey string) error {
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("checkpoint: log key: %w", err)
	}
	found := false
	for _, l := range s.Sigs {
		if l.Name != v.Name() || l.KeyID != v.KeyHash() {
			continue
		}
		if !v.Verify(s.Text, l.Payload) {
			return errors.New("checkpoint: log signature does not verify")
		}
		found = true
	}
	if !found {
		return errors.New("checkpoint: no signature by the pinned log key")
	}
	return nil
}

// CosignerKey is a pinned witness (cosigner) public key.
type CosignerKey struct {
	Name string
	ID   uint32
	Type byte
	Pub  []byte
}

// ParseCosignerKey parses a verifier key "name+hexid+base64(type||pub)".
// Type 0x04 (Ed25519 cosignature) is supported; type 0x06 (ML-DSA-44) is
// parsed so it can be reported as unsupported.
func ParseCosignerKey(vkey string) (CosignerKey, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 || len(parts[1]) != 8 {
		return CosignerKey{}, errors.New("checkpoint: malformed cosigner key")
	}
	if err := ValidName(parts[0]); err != nil {
		return CosignerKey{}, err
	}
	id, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil || fmt.Sprintf("%08x", id) != parts[1] {
		return CosignerKey{}, errors.New("checkpoint: malformed cosigner key ID")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(b) < 2 {
		return CosignerKey{}, errors.New("checkpoint: malformed cosigner public key")
	}
	k := CosignerKey{Name: parts[0], ID: uint32(id), Type: b[0], Pub: b[1:]}
	switch k.Type {
	case TypeCosignature:
		if len(k.Pub) != ed25519.PublicKeySize {
			return CosignerKey{}, errors.New("checkpoint: Ed25519 cosigner key has the wrong length")
		}
	case TypeMLDSA44:
	default:
		return CosignerKey{}, fmt.Errorf("checkpoint: cosigner key type 0x%02x is not a cosignature type", k.Type)
	}
	if KeyID(k.Name, k.Type, k.Pub) != k.ID {
		return CosignerKey{}, errors.New("checkpoint: cosigner key ID does not match the key")
	}
	return k, nil
}

// String renders the verifier key.
func (k CosignerKey) String() string {
	return fmt.Sprintf("%s+%08x+%s", k.Name, k.ID, base64.StdEncoding.EncodeToString(append([]byte{k.Type}, k.Pub...)))
}

// NewCosignerKey returns the verifier key for an Ed25519 cosigner.
func NewCosignerKey(name string, pub ed25519.PublicKey) CosignerKey {
	return CosignerKey{Name: name, ID: KeyID(name, TypeCosignature, pub), Type: TypeCosignature, Pub: append([]byte(nil), pub...)}
}

// CosignMessage is the cosignature/v1 signed message for a checkpoint body.
func CosignMessage(text []byte, timestamp uint64) []byte {
	return append([]byte("cosignature/v1\ntime "+strconv.FormatUint(timestamp, 10)+"\n"), text...)
}

// Cosign makes an Ed25519 cosignature line over a checkpoint body.
func Cosign(name string, priv ed25519.PrivateKey, text []byte, timestamp uint64) SigLine {
	pub := priv.Public().(ed25519.PublicKey)
	payload := make([]byte, 8, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(payload, timestamp)
	payload = append(payload, ed25519.Sign(priv, CosignMessage(text, timestamp))...)
	return SigLine{Name: name, KeyID: KeyID(name, TypeCosignature, pub), Payload: payload}
}

// Cosignature is the outcome of checking one pinned cosigner on a note.
type Cosignature struct {
	Key       CosignerKey
	Present   bool   // a signature line with this key's name and ID exists
	Valid     bool   // it verified
	Timestamp uint64 // POSIX seconds, signed by the cosigner (valid only)
	Err       string // why it is not valid, if present
}

// Cosignatures checks the note against each pinned cosigner key.
func (s *Signed) Cosignatures(keys []CosignerKey) []Cosignature {
	out := make([]Cosignature, 0, len(keys))
	for _, k := range keys {
		r := Cosignature{Key: k}
		for _, l := range s.Sigs {
			if l.Name != k.Name || l.KeyID != k.ID {
				continue
			}
			r.Present = true
			switch {
			case k.Type != TypeCosignature:
				r.Err = fmt.Sprintf("cosignature type 0x%02x is not supported by this verifier", k.Type)
			case len(l.Payload) != 8+ed25519.SignatureSize:
				r.Err = "cosignature has the wrong length"
			default:
				ts := binary.BigEndian.Uint64(l.Payload[:8])
				if ed25519.Verify(ed25519.PublicKey(k.Pub), CosignMessage(s.Text, ts), l.Payload[8:]) {
					r.Valid, r.Timestamp, r.Err = true, ts, ""
				} else {
					r.Err = "cosignature does not verify"
				}
			}
			if !r.Valid {
				break // a failing signature by a pinned key is never outvoted
			}
		}
		out = append(out, r)
	}
	return out
}
