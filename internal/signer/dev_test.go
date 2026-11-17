package signer

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestDevSignerRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDev(dir)
	if err != nil {
		t.Fatalf("NewDev: %v", err)
	}

	message := []byte("test tree head payload")
	sig, err := s.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(s.PublicKey(), message, sig) {
		t.Fatal("signature verification failed")
	}
}

func TestDevSignerPersistence(t *testing.T) {
	dir := t.TempDir()

	s1, _ := NewDev(dir)
	pub1 := s1.PublicKey()

	s2, err := NewDev(dir)
	if err != nil {
		t.Fatalf("second NewDev: %v", err)
	}
	pub2 := s2.PublicKey()

	if string(pub1) != string(pub2) {
		t.Fatal("public key changed between loads — key is not persisted correctly")
	}
}

func TestDevSignerWrongMessage(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewDev(dir)

	sig, _ := s.Sign([]byte("message a"))
	if ed25519.Verify(s.PublicKey(), []byte("message b"), sig) {
		t.Fatal("signature verified against wrong message — should fail")
	}
}

func TestDevSignerDifferentDirs(t *testing.T) {
	dir1, dir2 := t.TempDir(), t.TempDir()
	s1, _ := NewDev(dir1)
	s2, _ := NewDev(dir2)

	if string(s1.PublicKey()) == string(s2.PublicKey()) {
		t.Fatal("two independent signers have the same public key — keys are not independent")
	}
}

func TestDevImplementsInterface(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewDev(dir)
	var _ Signer = s // compile-time check
}

// A key file of the wrong length must stop the signer, not be replaced:
// replacing it would silently change the signing identity.
func TestBadKeyFileIsRefusedNotReplaced(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", []byte("short")},
		{"too long", make([]byte, ed25519.SeedSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mk := range []struct {
				file string
				ctor func(string) (*DevSigner, error)
			}{
				{devKeyFilename, NewDev},
				{softwareKeyFilename, NewSoftware},
			} {
				dir := t.TempDir()
				path := filepath.Join(dir, mk.file)
				if err := os.WriteFile(path, tc.data, 0600); err != nil {
					t.Fatal(err)
				}
				if s, err := mk.ctor(dir); err == nil || s != nil {
					t.Fatalf("%s: want an error for a %d-byte key file, got signer=%v err=%v", mk.file, len(tc.data), s != nil, err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, tc.data) {
					t.Fatalf("%s: key file was changed (now %d bytes, err %v)", mk.file, len(after), err)
				}
			}
		})
	}
}

// A missing key file is still generated, at mode 0400, and reloads the same.
func TestMissingKeyIsGenerated(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewSoftware(dir)
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, softwareKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != ed25519.SeedSize || info.Mode().Perm() != 0400 {
		t.Fatalf("new key: size %d mode %o, want %d and 0400", info.Size(), info.Mode().Perm(), ed25519.SeedSize)
	}
	s2, err := NewSoftware(dir)
	if err != nil || !bytes.Equal(s1.PublicKey(), s2.PublicKey()) {
		t.Fatalf("reload: err %v, same key %v", err, err == nil && bytes.Equal(s1.PublicKey(), s2.PublicKey()))
	}
}

// An unreadable key file (here: a directory in its place) is an error too.
func TestUnreadableKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, softwareKeyFilename), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSoftware(dir); err == nil {
		t.Fatal("want an error when the key path is not a readable file")
	}
}
