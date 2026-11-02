// Package accept records operator approvals of known drift (`witness accept`).
//
// An approval pins exact observed values: a file path with the hash it now
// has, a removed path, a path with its new mode, or a process name. Drift that
// matches an approval is no longer listed on every tick; drift that does not
// match (a later change to the same file, say) still is.
//
// Approvals live in the witness log itself, as drift_accepted and
// drift_accept_revoked entries written by the daemon (the log's only writer).
// The CLI hands the daemon a signed request through a spool directory. At
// start the daemon replays those entries, re-checking every signature, so an
// approval cannot be added by editing a file, and a forged entry without a
// valid operator signature is ignored.
//
// See docs/witness-accept-design.md.
package accept

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
)

// Source is the log source of every entry this package's records produce.
// It is reserved (config.reservedSources), so an event feed cannot claim it.
const Source = "operator"

// Log event names.
const (
	EventAccepted = "drift_accepted"
	EventRevoked  = "drift_accept_revoked"
	EventRejected = "drift_accept_rejected"
)

// Request kinds.
const (
	KindAccept = "accept"
	KindRevoke = "revoke"
)

// Request is one signed operator instruction. The signature covers the JSON
// encoding of the request with Sig empty.
type Request struct {
	Version   int            `json:"v"`
	Kind      string         `json:"kind"`
	ID        string         `json:"id"`         // random, unique; names the approval
	MachineID string         `json:"machine_id"` // the box this request is for
	Created   string         `json:"created"`    // RFC3339
	Reason    string         `json:"reason"`
	Changes   []drift.Change `json:"changes,omitempty"` // accept: items approved
	Revokes   string         `json:"revokes,omitempty"` // revoke: ID of an approval
	Signer    string         `json:"signer,omitempty"`  // hex ed25519 public key
	Sig       string         `json:"sig,omitempty"`     // hex ed25519 signature
}

// NewAccept builds an unsigned request approving changes.
func NewAccept(machineID, reason string, changes []drift.Change) (*Request, error) {
	return newRequest(KindAccept, machineID, reason, changes, "")
}

// NewRevoke builds an unsigned request withdrawing the approval named id.
func NewRevoke(machineID, reason, id string) (*Request, error) {
	return newRequest(KindRevoke, machineID, reason, nil, id)
}

func newRequest(kind, machineID, reason string, changes []drift.Change, revokes string) (*Request, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}
	r := &Request{
		Version:   1,
		Kind:      kind,
		ID:        hex.EncodeToString(nonce),
		MachineID: machineID,
		Created:   time.Now().UTC().Format(time.RFC3339),
		Reason:    reason,
		Changes:   changes,
		Revokes:   revokes,
	}
	return r, r.check()
}

// payload is the byte string the signature covers.
func (r *Request) payload() ([]byte, error) {
	c := *r
	c.Sig = ""
	return json.Marshal(&c)
}

// Sign signs r with the ed25519 private key priv, recording its public key.
func (r *Request) Sign(priv ed25519.PrivateKey) error {
	r.Signer = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	p, err := r.payload()
	if err != nil {
		return err
	}
	r.Sig = hex.EncodeToString(ed25519.Sign(priv, p))
	return nil
}

// SignerKey returns the request's signer public key.
func (r *Request) SignerKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(r.Signer)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("signer is not a hex ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// verifySig checks the request's signature against its own Signer field.
func (r *Request) verifySig() error {
	if r.Sig == "" {
		return errors.New("request is not signed")
	}
	pub, err := r.SignerKey()
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(r.Sig)
	if err != nil {
		return errors.New("sig is not hex")
	}
	p, err := r.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, p, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// check validates the request's shape (not its signature).
func (r *Request) check() error {
	if r.Version != 1 {
		return fmt.Errorf("unsupported request version %d", r.Version)
	}
	if r.ID == "" || r.MachineID == "" {
		return errors.New("request needs an id and a machine_id")
	}
	if r.Reason == "" {
		return errors.New("a reason is required")
	}
	switch r.Kind {
	case KindAccept:
		if len(r.Changes) == 0 {
			return errors.New("accept request lists no changes")
		}
		for i, c := range r.Changes {
			if _, err := itemKey(c); err != nil {
				return fmt.Errorf("change %d: %w", i, err)
			}
		}
		if r.Revokes != "" {
			return errors.New("accept request must not name a revoke target")
		}
	case KindRevoke:
		if r.Revokes == "" {
			return errors.New("revoke request names no approval")
		}
		if len(r.Changes) != 0 {
			return errors.New("revoke request must not list changes")
		}
	default:
		return fmt.Errorf("unknown request kind %q", r.Kind)
	}
	return nil
}

// ReadFile loads a request from path.
func ReadFile(path string) (*Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}
	return &r, nil
}

// WriteFile saves r to path (mode 0600).
func (r *Request) WriteFile(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// LoadKey reads an operator key: a 32-byte ed25519 seed file, the format
// `witness accept keygen` writes (and the witness's own signing.key).
func LoadKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a %d-byte ed25519 seed", path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Keygen writes a new operator key seed to path (mode 0400; refuses to
// overwrite) and returns its public key.
func Keygen(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(priv.Seed()); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}
