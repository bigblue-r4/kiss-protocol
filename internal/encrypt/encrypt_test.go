package encrypt

import (
	"bytes"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	k1, err := DeriveKey("test-machine-id")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey("test-machine-id")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveKey: same input produced different keys")
	}
	if len(k1) != keyLen {
		t.Fatalf("DeriveKey: want %d bytes, got %d", keyLen, len(k1))
	}
}

func TestDeriveKeyDistinct(t *testing.T) {
	k1, _ := DeriveKey("machine-a")
	k2, _ := DeriveKey("machine-b")
	if bytes.Equal(k1, k2) {
		t.Fatal("DeriveKey: different machine IDs produced the same key")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key, _ := DeriveKey("roundtrip-machine")
	plain := []byte("witness log entry — tamper evident")

	sealed, err := Seal(plain, key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(sealed, plain) {
		t.Fatal("Seal: ciphertext equals plaintext")
	}

	got, err := Open(sealed, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Open: got %q, want %q", got, plain)
	}
}

func TestOpenWrongKey(t *testing.T) {
	key, _ := DeriveKey("machine-a")
	wrongKey, _ := DeriveKey("machine-b")
	plain := []byte("secret log")

	sealed, _ := Seal(plain, key)
	_, err := Open(sealed, wrongKey)
	if err == nil {
		t.Fatal("Open: expected error with wrong key, got nil")
	}
}

func TestOpenTruncated(t *testing.T) {
	key, _ := DeriveKey("test-machine")
	sealed, _ := Seal([]byte("data"), key)
	_, err := Open(sealed[:4], key)
	if err == nil {
		t.Fatal("Open: expected error on truncated ciphertext, got nil")
	}
}

func TestSealNonDeterministic(t *testing.T) {
	key, _ := DeriveKey("test-machine")
	plain := []byte("same plaintext")
	s1, _ := Seal(plain, key)
	s2, _ := Seal(plain, key)
	if bytes.Equal(s1, s2) {
		t.Fatal("Seal: produced identical ciphertext for same input (nonce reuse)")
	}
}
