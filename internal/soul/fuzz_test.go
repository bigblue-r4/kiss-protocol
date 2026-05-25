package soul

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad fuzzes the TOML parser and soul verifier with arbitrary bytes.
// It must not panic regardless of input.
func FuzzLoad(f *testing.F) {
	// Seed corpus: valid soul structure, empty file, pure garbage.
	f.Add([]byte(`
[identity]
agent_name = "test"
agent_version = "0.1"
soul_version = "1"
hash = ""
`))
	f.Add([]byte{})
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte(`[identity]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "soul.toml")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Skip()
		}
		// Load must not panic regardless of input.
		_, _ = Load(p)
	})
}

// FuzzHash fuzzes the hash verifier with arbitrary file contents.
func FuzzHash(f *testing.F) {
	f.Add([]byte("valid content"), "deadbeef")
	f.Add([]byte{}, "")
	f.Add([]byte("\xff\xfe"), "not-hex")

	f.Fuzz(func(t *testing.T, data []byte, expected string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f.toml")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Skip()
		}
		// Hash must not panic.
		_, _ = Hash(p)
		// verify (unexported) is called inside Load; exercise it here directly.
		_ = verify(data, expected)
	})
}
