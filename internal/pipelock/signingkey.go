package pipelock

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// Pipelock's flight_recorder loads an Ed25519 signing key from a small,
// versioned text file: a header line naming the key type, then the base64
// (std, padded) key material. keygen writes a public sidecar next to it in the
// same shape. These constants match `pipelock keygen`'s on-disk format so a key
// witness provisions itself is byte-compatible with one Pipelock generated.
const (
	pipelockPrivateHeader = "pipelock-ed25519-private-v1"
	pipelockPublicHeader  = "pipelock-ed25519-public-v1"
)

// EnsureSigningKey makes sure a Pipelock-format Ed25519 signing key exists at
// path, generating one (and its .pub sidecar) if it is missing. It reports
// whether a new key was created.
//
// Provisioning a key by default matters: with no flight_recorder.signing_key_path
// Pipelock's recorder is inert and writes no evidence at all, so the witness log
// would silently miss every decision receipt. Generating the key natively (no
// pipelock subprocess) keeps witness's third-party surface minimal while
// guaranteeing evidence is always emitted and signed.
func EnsureSigningKey(path string) (generated bool, err error) {
	if path == "" {
		return false, nil
	}
	if _, statErr := os.Stat(path); statErr == nil {
		return false, nil // already provisioned
	} else if !os.IsNotExist(statErr) {
		return false, fmt.Errorf("stat signing key %s: %w", path, statErr)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false, fmt.Errorf("generate signing key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, fmt.Errorf("create key dir: %w", err)
	}
	// Private key: 0600, seed||public (the 64-byte Go ed25519.PrivateKey).
	privBody := pipelockPrivateHeader + "\n" + base64.StdEncoding.EncodeToString(priv) + "\n"
	if err := os.WriteFile(path, []byte(privBody), 0600); err != nil {
		return false, fmt.Errorf("write signing key: %w", err)
	}
	// Public sidecar: 0644, shareable, pinned by verifiers with --key.
	pubBody := pipelockPublicHeader + "\n" + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path+".pub", []byte(pubBody), 0644); err != nil {
		return false, fmt.Errorf("write public sidecar: %w", err)
	}
	return true, nil
}
