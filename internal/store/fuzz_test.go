package store

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzAppend fuzzes the store's Append path with arbitrary level/event/source
// and JSON-encodable data. Must not panic and must leave the store in a state
// where VerifyIntegrity passes.
func FuzzAppend(f *testing.F) {
	f.Add("INFO", "test_event", "fuzz", []byte(`{"key":"value"}`))
	f.Add("WARN", "", "src", []byte(`{}`))
	f.Add("", "e", "s", []byte(`null`))
	f.Add("DEATH", "kill", "witness", []byte(`{"detail":"fuzz"}`))
	f.Add("INFO", "long", "source", []byte(`{"a":"`+string(make([]byte, 1024))+`"}`))

	f.Fuzz(func(t *testing.T, level, event, source string, raw []byte) {
		dir := t.TempDir()
		key := make([]byte, 32)
		s, err := Open(dir, key, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		// raw may not be valid JSON — that's fine, Append marshals data as-is.
		// Use a plain string so the JSON encoder always succeeds.
		_ = s.Append(level, event, source, string(raw))

		// The log must remain internally consistent after every append.
		if _, err := s.VerifyIntegrity(); err != nil {
			t.Errorf("VerifyIntegrity after fuzz append: %v", err)
		}
	})
}

// FuzzReadAll fuzzes the log reader against arbitrary byte slices written
// directly to the log file. Must not panic.
func FuzzReadAll(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\x00\x00\x00\x04{}\n\x00"))
	f.Add([]byte("\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		key := make([]byte, 32)
		// Write raw bytes directly to the log file — bypasses the store.
		_ = os.WriteFile(filepath.Join(dir, logFilename), data, 0600)
		// ReadAll must not panic on garbage input.
		_, _ = ReadAll(dir, key)
	})
}
