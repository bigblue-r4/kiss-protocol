package soul

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

const defaultAllowlistPath = "~/.witness/trust/signers.txt"

// SoulSig is the detached signature file stored alongside a soul file.
type SoulSig struct {
	Algorithm string `json:"algorithm"`  // always "ed25519"
	SignerKey string `json:"signer_key"` // hex-encoded ed25519 public key
	Signature string `json:"signature"`  // hex-encoded raw ed25519 signature
	SignedAt  string `json:"signed_at"`  // RFC3339
}

// AllowlistEntry is one line from the trust allowlist.
type AllowlistEntry struct {
	Label  string
	PubKey ed25519.PublicKey
}

// SigPath returns the path of the detached signature file for a soul file.
func SigPath(soulPath string) string {
	return soulPath + ".sig"
}

// AllowlistPath returns the expanded default allowlist path.
func AllowlistPath() string {
	return expandHome(defaultAllowlistPath)
}

// LoadAllowlist reads the trust allowlist at path.
// Lines starting with # are comments. Each data line is "<label> <hex-pubkey>".
func LoadAllowlist(path string) ([]AllowlistEntry, error) {
	f, err := os.Open(expandHome(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("trust allowlist not found at %s — run 'witness soul sign' to initialise", path)
		}
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer f.Close()

	var entries []AllowlistEntry
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return nil, fmt.Errorf("allowlist line %d: expected '<label> <hex-pubkey>', got %q", lineNum, line)
		}
		raw, err := hex.DecodeString(parts[1])
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("allowlist line %d: invalid public key %q", lineNum, parts[1])
		}
		entries = append(entries, AllowlistEntry{Label: parts[0], PubKey: ed25519.PublicKey(raw)})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	return entries, nil
}

// AppendAllowlist adds a new entry to the allowlist file, creating it if needed.
// Skips the entry if the same pubkey is already present.
func AppendAllowlist(path, label string, pub ed25519.PublicKey) error {
	path = expandHome(path)
	if err := os.MkdirAll(strings.TrimSuffix(path, "/"+lastSegment(path)), 0700); err != nil {
		return err
	}

	// Check for duplicate.
	existing, err := LoadAllowlist(path)
	if err != nil && !os.IsNotExist(errors.Unwrap(err)) {
		// File may not exist yet — that's fine.
		existing = nil
	}
	pubHex := hex.EncodeToString(pub)
	for _, e := range existing {
		if hex.EncodeToString(e.PubKey) == pubHex {
			return nil // already present
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open allowlist: %w", err)
	}
	defer f.Close()

	// Write header comment on first creation.
	fi, _ := f.Stat()
	if fi.Size() == 0 {
		fmt.Fprintln(f, "# SGAIL Labs Harborlight — trust allowlist")
		fmt.Fprintln(f, "# One entry per line: <label> <hex-ed25519-public-key>")
		fmt.Fprintln(f, "# This file is the bootstrap trust root. Verify it out-of-band.")
		fmt.Fprintln(f, "#")
	}
	_, err = fmt.Fprintf(f, "%s %s\n", label, pubHex)
	return err
}

// SignSoul signs soulPath with s and writes the detached signature to soulPath+".sig".
func SignSoul(soulPath string, s signer.Signer) error {
	data, err := os.ReadFile(expandHome(soulPath))
	if err != nil {
		return fmt.Errorf("read soul file: %w", err)
	}
	sig, err := s.Sign(data)
	if err != nil {
		return fmt.Errorf("sign soul: %w", err)
	}
	ss := SoulSig{
		Algorithm: "ed25519",
		SignerKey: hex.EncodeToString(s.PublicKey()),
		Signature: hex.EncodeToString(sig),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	out, err := json.MarshalIndent(ss, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(SigPath(expandHome(soulPath)), out, 0600)
}

// VerifySoulSignature checks that the detached signature at soulPath+".sig"
// is a valid ed25519 signature over soulPath's contents by a key in allowlist.
// Returns nil only if all checks pass.
func VerifySoulSignature(soulPath string, allowlist []AllowlistEntry) error {
	soulPath = expandHome(soulPath)

	soulData, err := os.ReadFile(soulPath)
	if err != nil {
		return fmt.Errorf("read soul file: %w", err)
	}

	sigData, err := os.ReadFile(SigPath(soulPath))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("soul signature file not found at %s — run 'witness soul sign'", SigPath(soulPath))
		}
		return fmt.Errorf("read soul signature: %w", err)
	}

	var ss SoulSig
	if err := json.Unmarshal(sigData, &ss); err != nil {
		return fmt.Errorf("parse soul signature: %w", err)
	}
	if ss.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", ss.Algorithm)
	}

	signerPubBytes, err := hex.DecodeString(ss.SignerKey)
	if err != nil || len(signerPubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("soul signature: malformed signer_key")
	}
	signerPub := ed25519.PublicKey(signerPubBytes)

	rawSig, err := hex.DecodeString(ss.Signature)
	if err != nil || len(rawSig) != ed25519.SignatureSize {
		return fmt.Errorf("soul signature: malformed signature")
	}

	// Verify the signature cryptographically.
	if !ed25519.Verify(signerPub, soulData, rawSig) {
		return errors.New("soul signature: cryptographic verification failed — soul file may have been tampered")
	}

	// Check the signing key is in the allowlist.
	signerHex := ss.SignerKey
	for _, e := range allowlist {
		if hex.EncodeToString(e.PubKey) == signerHex {
			return nil // allowlist check passed
		}
	}
	return fmt.Errorf("soul signature: signing key %s...%s is not in the trust allowlist", signerHex[:8], signerHex[len(signerHex)-8:])
}

func lastSegment(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return path
	}
	return path[i+1:]
}
