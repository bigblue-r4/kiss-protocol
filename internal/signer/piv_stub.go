//go:build !piv

package signer

import "errors"

// NewPIV returns an error when PIV support has not been compiled in.
// To enable: install libpcsclite-dev and rebuild with -tags piv.
// See docs/keys.md for full instructions.
func NewPIV() (Signer, error) {
	return nil, errors.New("PIV support not compiled; rebuild with -tags piv (see docs/keys.md)")
}
