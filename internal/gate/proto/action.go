package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// ActionRequest is what a protected service asks the gate to allow. The
// action_hash binds a token to exactly this request: any change to any field
// (amount, destination, asset, nonce...) gives a different hash.
type ActionRequest struct {
	V            int    `json:"v"`
	Class        string `json:"class"`         // policy class, e.g. "withdrawal_hot"
	Target       string `json:"target"`        // the system acted on, e.g. "wallet-svc"
	Asset        string `json:"asset"`         // "" only for actions that move no value
	Amount       string `json:"amount"`        // non-negative decimal string, "0" when no value moves
	Destination  string `json:"destination"`   // address, environment, account...
	RequestNonce string `json:"request_nonce"` // 16 random bytes, lowercase hex
	Principal    string `json:"principal"`     // who asks (service account, user)
	OriginHost   string `json:"origin_host"`   // where the request came from
	TS           string `json:"ts"`            // FormatTime
}

var (
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$`)
	amountRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,77})(\.[0-9]{1,36})?$`)
)

// Validate checks every field's form. It does not consult policy.
func (r ActionRequest) Validate() error {
	switch {
	case r.V != Version:
		return fmt.Errorf("gate proto: action request version %d, want %d", r.V, Version)
	case !nameRE.MatchString(r.Class):
		return fmt.Errorf("gate proto: class %q must match %s", r.Class, nameRE)
	case !nameRE.MatchString(r.Principal):
		return fmt.Errorf("gate proto: principal %q must match %s", r.Principal, nameRE)
	case !nameRE.MatchString(r.OriginHost):
		return fmt.Errorf("gate proto: origin_host %q must match %s", r.OriginHost, nameRE)
	case !printable(r.Target, 512):
		return errors.New("gate proto: target must be 1-512 printable bytes")
	case !printable(r.Destination, 512):
		return errors.New("gate proto: destination must be 1-512 printable bytes")
	case !amountRE.MatchString(r.Amount):
		return fmt.Errorf("gate proto: amount %q must be a non-negative decimal string", r.Amount)
	case r.Asset == "" && strings.Trim(r.Amount, "0.") != "":
		return errors.New("gate proto: a request that moves value must name its asset")
	case r.Asset != "" && !nameRE.MatchString(r.Asset):
		return fmt.Errorf("gate proto: asset %q must match %s", r.Asset, nameRE)
	}
	if _, err := decodeHex(r.RequestNonce, 16, "request_nonce"); err != nil {
		return err
	}
	if _, err := ParseTime(r.TS, "ts"); err != nil {
		return err
	}
	return nil
}

// ActionHash is SHA-256(DomainAction || canonical(r)). SHA-256, not BLAKE3,
// so external signers and HSMs can compute it; BLAKE3 stays inside the
// witness's Merkle log.
func ActionHash(r ActionRequest) ([32]byte, error) {
	if err := r.Validate(); err != nil {
		return [32]byte{}, err
	}
	in, err := sigInput(DomainAction, r)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(in), nil
}

// ActionHashHex is ActionHash in lowercase hex, the form carried in approvals
// and tokens.
func ActionHashHex(r ActionRequest) (string, error) {
	h, err := ActionHash(r)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}

// DecodeActionRequest decodes and validates a canonical ActionRequest.
func DecodeActionRequest(data []byte) (ActionRequest, error) {
	var r ActionRequest
	if err := decodeCanonical(data, &r); err != nil {
		return ActionRequest{}, err
	}
	return r, r.Validate()
}

// ParseAmount converts a decimal amount string into an integer count of the
// asset's smallest unit (decimals digits after the point). An amount with
// more fractional digits than the asset has is an error, never rounded.
// Amounts are never parsed as floating point.
func ParseAmount(s string, decimals int) (*big.Int, error) {
	if decimals < 0 || decimals > 36 {
		return nil, fmt.Errorf("gate proto: asset decimals %d out of range 0-36", decimals)
	}
	if !amountRE.MatchString(s) {
		return nil, fmt.Errorf("gate proto: amount %q must be a non-negative decimal string", s)
	}
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > decimals {
		if strings.TrimRight(frac[decimals:], "0") != "" {
			return nil, fmt.Errorf("gate proto: amount %q has more than %d decimal places", s, decimals)
		}
		frac = frac[:decimals]
	}
	frac += strings.Repeat("0", decimals-len(frac))
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok {
		return nil, fmt.Errorf("gate proto: amount %q is not a number", s)
	}
	return n, nil
}
