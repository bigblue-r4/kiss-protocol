package signer

import (
	"crypto/ed25519"
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
