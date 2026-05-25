package soul

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

// testSigner wraps a raw ed25519 key for testing without the dev banner.
type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &testSigner{priv: priv, pub: pub}
}

func (s *testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *testSigner) PublicKey() ed25519.PublicKey    { return s.pub }

var _ signer.Signer = (*testSigner)(nil)

func writeSoulFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "soul.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write soul: %v", err)
	}
	return path
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	s := newTestSigner(t)
	soulPath := writeSoulFile(t, dir, "[identity]\nagent_name = \"test\"\n")

	if err := SignSoul(soulPath, s); err != nil {
		t.Fatalf("SignSoul: %v", err)
	}

	allowlist := []AllowlistEntry{{Label: "test-key", PubKey: s.PublicKey()}}
	if err := VerifySoulSignature(soulPath, allowlist); err != nil {
		t.Fatalf("VerifySoulSignature: %v", err)
	}
}

func TestVerifyMissingSigFile(t *testing.T) {
	dir := t.TempDir()
	soulPath := writeSoulFile(t, dir, "[identity]\n")
	if err := VerifySoulSignature(soulPath, nil); err == nil {
		t.Fatal("expected error for missing sig file, got nil")
	}
}

func TestVerifyTamperedSoulFile(t *testing.T) {
	dir := t.TempDir()
	s := newTestSigner(t)
	soulPath := writeSoulFile(t, dir, "[identity]\nagent_name = \"test\"\n")
	_ = SignSoul(soulPath, s)

	// Tamper the soul file after signing.
	_ = os.WriteFile(soulPath, []byte("[identity]\nagent_name = \"evil\"\n"), 0600)

	allowlist := []AllowlistEntry{{Label: "test-key", PubKey: s.PublicKey()}}
	if err := VerifySoulSignature(soulPath, allowlist); err == nil {
		t.Fatal("expected error after soul file tampered, got nil")
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	dir := t.TempDir()
	s := newTestSigner(t)
	soulPath := writeSoulFile(t, dir, "[identity]\n")
	_ = SignSoul(soulPath, s)

	// Allowlist has a different key.
	other := newTestSigner(t)
	allowlist := []AllowlistEntry{{Label: "other", PubKey: other.PublicKey()}}
	if err := VerifySoulSignature(soulPath, allowlist); err == nil {
		t.Fatal("expected error for key not in allowlist, got nil")
	}
}

func TestAllowlistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signers.txt")

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	if err := AppendAllowlist(path, "operator", pub1); err != nil {
		t.Fatalf("AppendAllowlist 1: %v", err)
	}
	if err := AppendAllowlist(path, "backup", pub2); err != nil {
		t.Fatalf("AppendAllowlist 2: %v", err)
	}
	// Duplicate — should be silently skipped.
	if err := AppendAllowlist(path, "operator2", pub1); err != nil {
		t.Fatalf("AppendAllowlist dup: %v", err)
	}

	entries, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (dup skipped), got %d", len(entries))
	}
	if hex.EncodeToString(entries[0].PubKey) != hex.EncodeToString(pub1) {
		t.Error("entry 0 pubkey mismatch")
	}
	if hex.EncodeToString(entries[1].PubKey) != hex.EncodeToString(pub2) {
		t.Error("entry 1 pubkey mismatch")
	}
}

func TestAllowlistComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signers.txt")
	content := "# this is a comment\n\n  # another comment\noperator " +
		hex.EncodeToString(make([]byte, ed25519.PublicKeySize)) + "\n"
	_ = os.WriteFile(path, []byte(content), 0600)

	entries, err := LoadAllowlist(path)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Label != "operator" {
		t.Errorf("wrong label: %q", entries[0].Label)
	}
}
