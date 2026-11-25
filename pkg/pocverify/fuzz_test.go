package pocverify

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseCanonical: Parse and Verify never panic, and canonical form is a
// fixed point (canonicalizing canonical bytes changes nothing).
func FuzzParseCanonical(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(vectorDir, "*", "*.json"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"a":[1,2.5,-0,1e300,"😀"]}`))
	key := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Verify(data, []ed25519.PublicKey{key})
		v, err := Parse(data)
		if err != nil {
			return
		}
		c1, err := Canonical(v)
		if err != nil {
			t.Fatalf("canonicalize parsed value: %v", err)
		}
		v2, err := Parse(c1)
		if err != nil {
			t.Fatalf("canonical output does not parse: %v\n%s", err, c1)
		}
		c2, err := Canonical(v2)
		if err != nil || !bytes.Equal(c1, c2) {
			t.Fatalf("canonical form not a fixed point:\n%s\n%s", c1, c2)
		}
	})
}
