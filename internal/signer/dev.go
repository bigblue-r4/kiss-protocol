package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const devKeyFilename = "dev-signing.key" // 32-byte ed25519 seed, mode 0400

// DevSigner is a software ed25519 signer for development and testing.
// It is NOT suitable for production use: the private key is stored in
// plaintext on disk. Prints a warning banner every time it is constructed.
//
// Only construct a DevSigner when the operator has explicitly passed --dev.
type DevSigner struct {
	mu   sync.Mutex
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewDev loads or generates a dev signing key at keyDir/dev-signing.key.
// Always prints a 5-line warning banner to stderr.
func NewDev(keyDir string) (*DevSigner, error) {
	printDevBanner()

	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("dev signer: create key dir: %w", err)
	}

	path := filepath.Join(keyDir, devKeyFilename)
	seed, err := loadOrGenerateSeed(path)
	if err != nil {
		return nil, fmt.Errorf("dev signer: %w", err)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return &DevSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Sign returns a raw 64-byte ed25519 signature over message.
func (d *DevSigner) Sign(message []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return ed25519.Sign(d.priv, message), nil
}

// PublicKey returns the signer's ed25519 public key.
func (d *DevSigner) PublicKey() ed25519.PublicKey {
	return d.pub
}

func loadOrGenerateSeed(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) == ed25519.SeedSize {
		return data, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key: %w", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}
	if err := os.WriteFile(path, seed, 0400); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	return seed, nil
}

func printDevBanner() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  ╔══════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(os.Stderr, "  ║  WARNING: DEV SIGNER ACTIVE — NOT FOR PRODUCTION USE        ║")
	fmt.Fprintln(os.Stderr, "  ║  Signing key is a plaintext file on disk. Tree heads and    ║")
	fmt.Fprintln(os.Stderr, "  ║  soul signatures provide NO hardware-rooted trust.          ║")
	fmt.Fprintln(os.Stderr, "  ║  Use a YubiKey PIV token for any real deployment.           ║")
	fmt.Fprintln(os.Stderr, "  ╚══════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(os.Stderr, "")
}

const softwareKeyFilename = "signing.key" // 32-byte ed25519 seed, mode 0400

// NewSoftware loads or generates an on-disk ed25519 signing key at
// keyDir/signing.key for installs without a hardware token (config
// "signer": "software"). Unlike NewDev this is a deliberate operating mode,
// not a development shortcut: production checks stay on. Its limit is the
// same, though, and the banner says so: the key sits on the machine it
// protects, so someone with full control of that machine can use it. The
// transparency mirror is what catches that.
func NewSoftware(keyDir string) (*DevSigner, error) {
	fmt.Fprintln(os.Stderr, "[witness] Software signing key (pilot grade): the key is a file on this machine.")
	fmt.Fprintln(os.Stderr, "[witness] A hardware token (YubiKey PIV build) keeps it off the disk; the mirror catches a re-signed log.")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("software signer: create key dir: %w", err)
	}
	seed, err := loadOrGenerateSeed(filepath.Join(keyDir, softwareKeyFilename))
	if err != nil {
		return nil, fmt.Errorf("software signer: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &DevSigner{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}
