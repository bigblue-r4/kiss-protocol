package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func appendN(t *testing.T, dir string, n int) {
	t.Helper()
	s, err := Open(dir, make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := s.Append("INFO", "e", "test", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// truncateRecords keeps the first n [len][sealed] records of the log.
func truncateRecords(t *testing.T, dir string, n int) {
	t.Helper()
	path := filepath.Join(dir, logFilename)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for i := 0; i < n; i++ {
		l := int(uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3]))
		off += 4 + l
	}
	if err := os.WriteFile(path, b[:off], 0600); err != nil {
		t.Fatal(err)
	}
}

// The gap: cut the end off the log and delete the signed head. Before this fix
// both Open and VerifyIntegrity passed.
func TestTruncationWithDeletedHeadIsDetected(t *testing.T) {
	dir := t.TempDir()
	appendN(t, dir, 5)
	truncateRecords(t, dir, 2)
	if err := os.Remove(filepath.Join(dir, treeHeadFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, make([]byte, 32), nil); !errors.Is(err, ErrMissingTreeHead) {
		t.Fatalf("Open = %v, want ErrMissingTreeHead", err)
	}
}

func TestDeletedHeadOnAnIntactLogIsDetected(t *testing.T) {
	dir := t.TempDir()
	appendN(t, dir, 3)
	if err := os.Remove(filepath.Join(dir, treeHeadFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, make([]byte, 32), nil); !errors.Is(err, ErrMissingTreeHead) {
		t.Fatalf("Open = %v, want ErrMissingTreeHead", err)
	}
}

func TestEmptyStoreWithoutHeadStillOpens(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("fresh store: %v", err)
	}
	if n, err := s.VerifyIntegrity(); err != nil || n != 0 {
		t.Fatalf("VerifyIntegrity on empty store = %d, %v", n, err)
	}
	if err := s.Append("INFO", "first", "test", nil); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(dir, make([]byte, 32), nil); err != nil {
		t.Fatalf("reopen after first append: %v", err)
	}
}
