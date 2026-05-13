// Package export generates signed, tamper-evident court export bundles.
package export

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Bundle is a signed, tamper-evident export package for court submission.
type Bundle struct {
	BundleID    string        `json:"bundle_id"`
	GeneratedAt time.Time     `json:"generated_at"`
	CaseNumber  string        `json:"case_number"`
	Department  string        `json:"department"`
	NodeID      string        `json:"node_id"`
	EntryCount  int           `json:"entry_count"`
	SHA256Chain string        `json:"sha256_chain"`        // SHA-256 over all entries concatenated
	Signature   string        `json:"signature,omitempty"` // Ed25519, hex-encoded; covers all fields except signature itself
	Entries     []store.Entry `json:"entries"`
}

// Generate builds a bundle from log entries that belong to caseNumber.
func Generate(entries []store.Entry, caseNumber, department, nodeID string) (*Bundle, error) {
	var filtered []store.Entry
	for _, e := range entries {
		if matchesCase(e, caseNumber) {
			filtered = append(filtered, e)
		}
	}
	chainHash := computeChain(filtered)
	id, err := newBundleID()
	if err != nil {
		return nil, err
	}
	return &Bundle{
		BundleID:    id,
		GeneratedAt: time.Now().UTC(),
		CaseNumber:  caseNumber,
		Department:  department,
		NodeID:      nodeID,
		EntryCount:  len(filtered),
		SHA256Chain: chainHash,
		Entries:     filtered,
	}, nil
}

// Sign signs the bundle with the given Ed25519 private key (64-byte hex).
func Sign(b *Bundle, privKeyHex string) error {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key must be %d bytes (%d hex chars)", ed25519.PrivateKeySize, ed25519.PrivateKeySize*2)
	}
	payload, err := bundlePayload(b)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), payload)
	b.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify verifies the bundle's Ed25519 signature against the given public key (32-byte hex).
func Verify(b *Bundle, pubKeyHex string) error {
	if b.Signature == "" {
		return fmt.Errorf("bundle is not signed")
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	sigBytes, err := hex.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := bundlePayload(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// WriteNDJSON writes the bundle as newline-delimited JSON.
// First line: bundle header (no entries). Subsequent lines: one entry each.
func WriteNDJSON(b *Bundle, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Header line: everything except the entries array.
	header := *b
	header.Entries = nil
	hdr, err := json.Marshal(header)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s\n", hdr); err != nil {
		return err
	}
	for _, e := range b.Entries {
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
			return err
		}
	}
	return nil
}

// GenerateKeyPair creates a new Ed25519 signing key pair.
// Returns (pubHex, privHex) where privHex is the 64-byte seed+pub concatenation.
func GenerateKeyPair() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// bundlePayload returns the canonical JSON bytes for signing (signature field zeroed).
func bundlePayload(b *Bundle) ([]byte, error) {
	tmp := *b
	tmp.Signature = ""
	return json.Marshal(tmp)
}

// computeChain returns SHA-256 of all entry JSON payloads concatenated.
func computeChain(entries []store.Entry) string {
	h := sha256.New()
	for _, e := range entries {
		b, _ := json.Marshal(e)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// matchesCase returns true if the log entry's Data contains the given case_number.
func matchesCase(e store.Entry, caseNumber string) bool {
	if e.Data == nil {
		return false
	}
	var payload struct {
		CaseNumber string `json:"case_number"`
	}
	if err := json.Unmarshal(e.Data, &payload); err != nil {
		return false
	}
	return payload.CaseNumber == caseNumber
}

func newBundleID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("BUNDLE-%s-%s", time.Now().UTC().Format("20060102"), hex.EncodeToString(b[:])), nil
}
