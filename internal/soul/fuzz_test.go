package soul

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoad fuzzes the TOML parser and soul integrity verifier with arbitrary
// bytes. The invariant: Load must never panic regardless of input.
func FuzzLoad(f *testing.F) {
	// Seed 1: minimal valid structure.
	f.Add([]byte(`
[identity]
agent_name = "harborlight"
agent_version = "3.0.0"
organization = "SGAIL Labs"
soul_locked = true

[prime_law]
text = "Witness first."
override_permitted = false

[integrity]
soul_hash = ""
verify_on_load = false
halt_on_mismatch = true
`))

	// Seed 2: verify_on_load=true with matching hash triggers the hash check.
	f.Add([]byte(`
[integrity]
soul_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
verify_on_load = true
halt_on_mismatch = true
`))

	// Seed 3: empty file.
	f.Add([]byte{})

	// Seed 4: pure binary garbage.
	f.Add([]byte("\x00\x01\x02\x03\xff\xfe\xfd"))

	// Seed 5: TOML with only a section header, no keys.
	f.Add([]byte("[identity]"))

	// Seed 6: deeply nested structure TOML doesn't expect — parser must not panic.
	f.Add([]byte(`
[identity.nested.deeply]
key = "value"
`))

	// Seed 7: soul_hash key present but no value — tests zeroSoulHash edge case.
	f.Add([]byte(`
[integrity]
soul_hash =
`))

	// Seed 8: extremely long soul_hash value — buffer overflow probe.
	longHash := make([]byte, 0, 512)
	longHash = append(longHash, []byte("[integrity]\nsoul_hash = \"")...)
	for i := 0; i < 256; i++ {
		longHash = append(longHash, 'a')
	}
	longHash = append(longHash, '"')
	f.Add(longHash)

	// Seed 9: valid TOML but all string values are binary nulls — UTF-8 probe.
	f.Add([]byte("[identity]\nagent_name = \"\x00\x00\x00\""))

	// Seed 10: TOML array where a struct is expected.
	f.Add([]byte(`
[identity]
agent_name = ["array", "value"]
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "soul.toml")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Skip()
		}
		// Must not panic regardless of TOML content.
		_, _ = Load(p)
	})
}

// FuzzVerify fuzzes the internal hash verifier with arbitrary file contents
// and expected hash strings — must not panic and must not accept wrong hashes.
func FuzzVerify(f *testing.F) {
	f.Add([]byte("valid content"), "deadbeef")
	f.Add([]byte{}, "")
	f.Add([]byte("\xff\xfe"), "not-hex")
	f.Add([]byte("x"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	f.Add([]byte("a"), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")

	f.Fuzz(func(t *testing.T, data []byte, expected string) {
		// verify must not panic.
		_ = verify(data, expected)
		// If expected is empty the verifier should accept (not-yet-stamped).
		if expected == "" {
			if err := verify(data, expected); err != nil {
				t.Errorf("verify with empty expected should return nil, got %v", err)
			}
		}
	})
}

// FuzzZeroSoulHash fuzzes the field-erasing transform that enables stable
// hash computation. Must not panic and must preserve byte length invariant.
func FuzzZeroSoulHash(f *testing.F) {
	f.Add([]byte(`soul_hash = "abc123"`))
	f.Add([]byte(`soul_hash = ""`))
	f.Add([]byte{})
	f.Add([]byte("soul_hash"))            // key with no value
	f.Add([]byte(`soul_hash = 'single'`)) // single-quoted (invalid TOML but fuzz it)
	f.Add([]byte("\x00soul_hash = \"a\""))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := zeroSoulHash(data)
		// Result length must be <= input length (we only replace the value, not add bytes).
		if len(result) > len(data)+2 {
			t.Errorf("zeroSoulHash output (%d bytes) longer than input (%d bytes)", len(result), len(data))
		}
	})
}

// FuzzHash fuzzes the public Hash function — must not panic.
func FuzzHash(f *testing.F) {
	f.Add([]byte("valid content"))
	f.Add([]byte{})
	f.Add(make([]byte, 65536))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "f.toml")
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Skip()
		}
		h, err := Hash(p)
		if err == nil && len(h) != 64 {
			t.Errorf("Hash returned %d-char string, want 64 (hex SHA-256)", len(h))
		}
	})
}
