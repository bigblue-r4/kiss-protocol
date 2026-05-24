package store

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func openFresh(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, testKey())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func TestAppendAndReadAll(t *testing.T) {
	s, dir := openFresh(t)
	key := testKey()

	for i := 0; i < 5; i++ {
		if err := s.Append("INFO", "test_event", "test", map[string]int{"i": i}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	_ = s.Close()

	entries, err := ReadAll(dir, key)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Errorf("entry %d: seq=%d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestVerifyIntegrityClean(t *testing.T) {
	s, _ := openFresh(t)
	for i := 0; i < 8; i++ {
		_ = s.Append("INFO", "ev", "src", nil)
	}
	n, err := s.VerifyIntegrity()
	if err != nil {
		t.Fatalf("VerifyIntegrity: %v", err)
	}
	if n != 8 {
		t.Errorf("expected 8 verified leaves, got %d", n)
	}
}

func TestTamperLeafDetected(t *testing.T) {
	_, dir := openFresh(t)
	key := testKey()

	s2, _ := Open(dir, key)
	for i := 0; i < 4; i++ {
		_ = s2.Append("INFO", "ev", "src", nil)
	}
	_ = s2.Close()

	// Flip a bit in the middle of the log file.
	logPath := filepath.Join(dir, logFilename)
	data, _ := os.ReadFile(logPath)
	data[len(data)/2] ^= 0xff
	_ = os.WriteFile(logPath, data, 0600)

	s3, err := Open(dir, key)
	if err == nil {
		_ = s3.Close()
		t.Fatal("expected error opening tampered log, got nil")
	}
}

func TestTruncationDetected(t *testing.T) {
	_, dir := openFresh(t)
	key := testKey()

	s2, _ := Open(dir, key)
	for i := 0; i < 6; i++ {
		_ = s2.Append("INFO", "ev", "src", nil)
	}
	_ = s2.Close()

	// Truncate the log to the number of bytes for 3 entries by reading
	// all entries, then writing back only the first half of the file bytes.
	logPath := filepath.Join(dir, logFilename)
	data, _ := os.ReadFile(logPath)
	_ = os.WriteFile(logPath, data[:len(data)/2], 0600)

	// Tree head still claims 6 entries but log now has fewer — mismatch.
	s3, err := Open(dir, key)
	if err == nil {
		_ = s3.Close()
		t.Fatal("expected error opening truncated log, got nil")
	}
}

func TestTreeHeadTamperDetected(t *testing.T) {
	_, dir := openFresh(t)
	key := testKey()

	s2, _ := Open(dir, key)
	_ = s2.Append("INFO", "ev", "src", nil)
	_ = s2.Close()

	// Flip a bit in the tree head file.
	thPath := filepath.Join(dir, treeHeadFilename)
	data, _ := os.ReadFile(thPath)
	data[len(data)/2] ^= 0xff
	_ = os.WriteFile(thPath, data, 0600)

	s3, err := Open(dir, key)
	if err == nil {
		_ = s3.Close()
		t.Fatal("expected error opening store with tampered tree head, got nil")
	}
}

func TestInclusionProofRoundtrip(t *testing.T) {
	s, _ := openFresh(t)
	for i := 0; i < 7; i++ {
		_ = s.Append("INFO", "ev", "src", map[string]int{"i": i})
	}

	// Obtain the current root from the head.
	head := s.Head()
	rootBytes, _ := hex.DecodeString(head.Root)
	var root [32]byte
	copy(root[:], rootBytes)

	// Prove and verify each leaf.
	entries, _ := ReadAll(s.Path()[:len(s.Path())-len(logFilename)], testKey())
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}

	for idx := range entries {
		proof, entry, err := s.InclusionProof(uint64(idx))
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		lh := leafHash(entry)
		if err := merkle.Verify(root, lh, proof); err != nil {
			t.Fatalf("Verify leaf %d: %v", idx, err)
		}
	}
}

func TestReorderDetected(t *testing.T) {
	_, dir := openFresh(t)
	key := testKey()

	s2, _ := Open(dir, key)
	for i := 0; i < 4; i++ {
		_ = s2.Append("INFO", "ev", "src", map[string]int{"i": i})
	}
	_ = s2.Close()

	// Read raw encrypted records, swap record 0 and record 1.
	logPath := filepath.Join(dir, logFilename)
	records := readRawRecords(t, logPath)
	if len(records) < 2 {
		t.Skip("not enough records to reorder")
	}
	records[0], records[1] = records[1], records[0]
	writeRawRecords(t, logPath, records)

	s3, err := Open(dir, key)
	if err == nil {
		_ = s3.Close()
		t.Fatal("expected error after reordering log entries, got nil")
	}
}

func TestV1CompatibilityDecode(t *testing.T) {
	// A v1-format entry (with prev_hash field) must decode without error.
	v1Entry := map[string]interface{}{
		"seq":       float64(1),
		"ts":        "2026-05-24T00:00:00Z",
		"level":     "INFO",
		"event":     "test",
		"source":    "test",
		"prev_hash": "abc123",
	}
	b, _ := json.Marshal(v1Entry)
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("v1 entry decode failed: %v", err)
	}
	if e.Seq != 1 || e.Level != "INFO" {
		t.Fatalf("v1 entry fields not decoded correctly: %+v", e)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readRawRecords(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readRawRecords: %v", err)
	}
	var records [][]byte
	for len(data) >= 4 {
		l := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		data = data[4:]
		if l > len(data) {
			break
		}
		rec := make([]byte, l)
		copy(rec, data[:l])
		records = append(records, rec)
		data = data[l:]
	}
	return records
}

func writeRawRecords(t *testing.T, path string, records [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("writeRawRecords: %v", err)
	}
	defer f.Close()
	for _, rec := range records {
		var lenBuf [4]byte
		lenBuf[0] = byte(len(rec) >> 24)
		lenBuf[1] = byte(len(rec) >> 16)
		lenBuf[2] = byte(len(rec) >> 8)
		lenBuf[3] = byte(len(rec))
		_, _ = f.Write(lenBuf[:])
		_, _ = f.Write(rec)
	}
}
