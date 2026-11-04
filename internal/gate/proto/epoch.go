package proto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Scope kinds: what a breaker trip freezes.
const (
	ScopeGlobal      = "global"
	ScopeClass       = "class"
	ScopePrincipal   = "principal"
	ScopeOriginHost  = "origin_host"
	ScopeDestination = "destination"
	ScopeAsset       = "asset"
)

// Scope is one frozen slice of actions. Global has an empty Value.
type Scope struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Validate checks the scope's form.
func (s Scope) Validate() error {
	switch s.Kind {
	case ScopeGlobal:
		if s.Value != "" {
			return errors.New("gate proto: global scope takes no value")
		}
		return nil
	case ScopeClass, ScopePrincipal, ScopeOriginHost, ScopeAsset:
		if !nameRE.MatchString(s.Value) {
			return fmt.Errorf("gate proto: %s scope value %q must match %s", s.Kind, s.Value, nameRE)
		}
		return nil
	case ScopeDestination:
		if !printable(s.Value, 512) {
			return errors.New("gate proto: destination scope value must be 1-512 printable bytes")
		}
		return nil
	}
	return fmt.Errorf("gate proto: unknown scope kind %q", s.Kind)
}

// Covers reports whether the scope freezes request r.
func (s Scope) Covers(r ActionRequest) bool {
	switch s.Kind {
	case ScopeGlobal:
		return true
	case ScopeClass:
		return r.Class == s.Value
	case ScopePrincipal:
		return r.Principal == s.Value
	case ScopeOriginHost:
		return r.OriginHost == s.Value
	case ScopeDestination:
		return r.Destination == s.Value
	case ScopeAsset:
		return r.Asset == s.Value
	}
	return true // unknown kinds freeze everything: fail closed
}

// String renders the scope as kind or kind:value.
func (s Scope) String() string {
	if s.Value == "" {
		return s.Kind
	}
	return s.Kind + ":" + s.Value
}

// Epoch is the gate's signed statement of which scopes are frozen. The epoch
// number rises on every trip and reset; tokens from an older epoch are void.
type Epoch struct {
	V          int     `json:"v"`
	Epoch      uint64  `json:"epoch"`
	OpenScopes []Scope `json:"open_scopes"` // open breaker = frozen; never null
	IssuedAt   string  `json:"issued_at"`
	GateKey    string  `json:"gate_key"`
	Sig        string  `json:"sig,omitempty"`
}

func (e Epoch) check() (time.Time, error) {
	if e.V != Version {
		return time.Time{}, fmt.Errorf("gate proto: epoch version %d", e.V)
	}
	if e.OpenScopes == nil {
		return time.Time{}, errors.New("gate proto: epoch open_scopes must be a list, not null")
	}
	for _, s := range e.OpenScopes {
		if err := s.Validate(); err != nil {
			return time.Time{}, err
		}
	}
	if _, err := decodeHex(e.GateKey, ed25519.PublicKeySize, "gate_key"); err != nil {
		return time.Time{}, err
	}
	return ParseTime(e.IssuedAt, "issued_at")
}

// SignEpoch fills in GateKey and Sig with s.
func SignEpoch(e Epoch, s Signer) (Epoch, error) {
	e.Sig = ""
	e.GateKey = hex.EncodeToString(s.PublicKey())
	if e.OpenScopes == nil {
		e.OpenScopes = []Scope{}
	}
	if _, err := e.check(); err != nil {
		return Epoch{}, err
	}
	in, err := sigInput(DomainEpoch, e)
	if err != nil {
		return Epoch{}, err
	}
	sig, err := s.Sign(in)
	if err != nil {
		return Epoch{}, fmt.Errorf("sign epoch: %w", err)
	}
	e.Sig = hex.EncodeToString(sig)
	return e, nil
}

// VerifyEpoch checks the epoch's form and its signature by a pinned gate key,
// and returns its issue time.
func VerifyEpoch(e Epoch, gateKeys []ed25519.PublicKey) (time.Time, error) {
	issued, err := e.check()
	if err != nil {
		return time.Time{}, err
	}
	pub, _ := hex.DecodeString(e.GateKey)
	if !keyIn(pub, gateKeys) {
		return time.Time{}, errors.New("gate proto: epoch signed by a key that is not a pinned gate key")
	}
	unsigned := e
	unsigned.Sig = ""
	in, err := sigInput(DomainEpoch, unsigned)
	if err != nil {
		return time.Time{}, err
	}
	return issued, verifySig(ed25519.PublicKey(pub), in, e.Sig, "epoch")
}

// DecodeEpoch decodes a canonical Epoch (no signature check).
func DecodeEpoch(data []byte) (Epoch, error) {
	var e Epoch
	return e, decodeCanonical(data, &e)
}

// Frozen returns the first open scope that covers r, if any.
func (e Epoch) Frozen(r ActionRequest) (Scope, bool) {
	for _, s := range e.OpenScopes {
		if s.Covers(r) {
			return s, true
		}
	}
	return Scope{}, false
}
