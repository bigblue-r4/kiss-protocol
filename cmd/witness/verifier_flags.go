package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/bigblue-r4/kiss-protocol/internal/soul"
)

// parseVerifierPins removes pin flags while preserving command-specific arguments.
func parseVerifierPins(args []string) ([]ed25519.PublicKey, []string, error) {
	var pins []ed25519.PublicKey
	var rest []string
	requested := false
	for i := 0; i < len(args); i++ {
		name, value, equal := strings.Cut(args[i], "=")
		if name != "--pubkey" && name != "--pubkey-file" {
			rest = append(rest, args[i])
			continue
		}
		requested = true
		if !equal {
			i++
			if i == len(args) {
				return nil, nil, fmt.Errorf("%s requires a value", name)
			}
			value = args[i]
		}
		if name == "--pubkey" {
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return nil, nil, fmt.Errorf("--pubkey requires a 32-byte Ed25519 public key in hex")
			}
			pins = append(pins, ed25519.PublicKey(raw))
		} else {
			entries, err := soul.LoadAllowlist(value)
			if err != nil {
				return nil, nil, fmt.Errorf("--pubkey-file: %w", err)
			}
			for _, entry := range entries {
				pins = append(pins, entry.PubKey)
			}
		}
	}
	if requested && len(pins) == 0 {
		return nil, nil, fmt.Errorf("--pubkey-file contains no public keys")
	}
	return pins, rest, nil
}

func verifierPins(args []string) ([]ed25519.PublicKey, []string) {
	pins, rest, err := parseVerifierPins(args)
	if err != nil {
		fatal("%v", err)
	}
	if len(pins) == 0 {
		fmt.Fprintln(os.Stderr, "NOTE  signer not pinned: pass --pubkey to check who signed this log")
	}
	return pins, rest
}
