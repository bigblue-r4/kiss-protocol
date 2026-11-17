package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	// FIPS 180-2 test vectors.
	cases := map[string]string{
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	for in, want := range cases {
		if got := SHA256Hex([]byte(in)); got != want {
			t.Errorf("SHA256Hex(%q) = %s, want %s", in, got, want)
		}
	}
}

func FuzzSHA256HexMatchesStdlib(f *testing.F) {
	f.Add([]byte("witness-fallback:host"))
	f.Fuzz(func(t *testing.T, data []byte) {
		sum := sha256.Sum256(data)
		if got, want := SHA256Hex(data), hex.EncodeToString(sum[:]); got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	})
}
