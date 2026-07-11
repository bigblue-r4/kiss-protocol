package pipelock

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureSigningKeyFormat checks the generated key matches the on-disk shape
// `pipelock keygen` produces: a header line plus base64 material, a 64-byte
// private key (seed||public) at 0600, and a public sidecar whose key is the
// tail of the private key.
func TestEnsureSigningKeyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "id_ed25519")

	generated, err := EnsureSigningKey(path)
	if err != nil {
		t.Fatalf("EnsureSigningKey: %v", err)
	}
	if !generated {
		t.Fatal("expected a key to be generated on first call")
	}

	priv := readKeyBody(t, path, pipelockPrivateHeader)
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	pub := readKeyBody(t, path+".pub", pipelockPublicHeader)
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if !strings.EqualFold(base64.StdEncoding.EncodeToString(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)),
		base64.StdEncoding.EncodeToString(pub)) {
		t.Fatal("public sidecar does not match the private key")
	}

	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0600 {
		t.Errorf("private key perms = %o, want 600", fi.Mode().Perm())
	}
}

// TestEnsureSigningKeyIdempotent verifies an existing key is left untouched.
func TestEnsureSigningKeyIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if _, err := EnsureSigningKey(path); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)

	generated, err := EnsureSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if generated {
		t.Error("second call should not regenerate an existing key")
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Error("existing key was overwritten")
	}
}

// TestEnsureSigningKeyEmptyPath is a no-op (evidence leg deliberately disabled).
func TestEnsureSigningKeyEmptyPath(t *testing.T) {
	generated, err := EnsureSigningKey("")
	if err != nil || generated {
		t.Fatalf("empty path: generated=%v err=%v, want false/nil", generated, err)
	}
}

func readKeyBody(t *testing.T, path, wantHeader string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("%s: missing header line", path)
	}
	if sc.Text() != wantHeader {
		t.Fatalf("%s: header = %q, want %q", path, sc.Text(), wantHeader)
	}
	if !sc.Scan() {
		t.Fatalf("%s: missing key material line", path)
	}
	raw, err := base64.StdEncoding.DecodeString(sc.Text())
	if err != nil {
		t.Fatalf("%s: base64 decode: %v", path, err)
	}
	return raw
}
