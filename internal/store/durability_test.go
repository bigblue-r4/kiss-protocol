package store

import (
	"os"
	"testing"
)

// The log must be synced before the head that covers the new record is
// written; otherwise a power cut can leave the head ahead of the log (the
// 2026-11-19 OptiPlex failure: the witness refused to start, "log tampered").
func TestAppendSyncsLogBeforeHead(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append("info", "first", "test", nil); err != nil {
		t.Fatal(err)
	}

	orig := syncLog
	defer func() { syncLog = orig }()
	calls := 0
	syncLog = func(f *os.File) error {
		calls++
		h, err := readStoredHead(dir)
		if err != nil {
			t.Fatalf("read head during sync: %v", err)
		}
		if h.Size != 1 {
			t.Errorf("head already covers %d records when the log is synced; want the old head (1)", h.Size)
		}
		return orig(f)
	}
	if err := st.Append("info", "second", "test", nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("log synced %d times in one Append, want 1", calls)
	}
	if h, _ := readStoredHead(dir); h.Size != 2 {
		t.Fatalf("head size after Append = %d, want 2", h.Size)
	}
}

// A failed sync must not advance the head: the record may not be durable.
func TestAppendSyncFailureLeavesHead(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append("info", "first", "test", nil); err != nil {
		t.Fatal(err)
	}
	orig := syncLog
	defer func() { syncLog = orig }()
	syncLog = func(*os.File) error { return os.ErrClosed }
	if err := st.Append("info", "second", "test", nil); err == nil {
		t.Fatal("Append succeeded although the log sync failed")
	}
	if h, _ := readStoredHead(dir); h.Size != 1 {
		t.Fatalf("head advanced to %d after a failed sync, want 1", h.Size)
	}
}
