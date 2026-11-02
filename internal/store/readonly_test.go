package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// witness verify, prove and audit open the log with OpenPinned, often while
// the daemon is appending. That open used to read the log and then the head:
// a record written in between made the head look stale ("root mismatch"), and
// a head written in between made the newest record look like a crash tail,
// which was cut out of the live log.

func pinsOf(s *testDevSigner) []ed25519.PublicKey { return []ed25519.PublicKey{s.PublicKey()} }

func TestPinnedLeavesUncommittedRecordInPlace(t *testing.T) {
	dir, s := signedStore(t, 3)
	appendRaw(t, dir, frameFor(t, Entry{Seq: 4, Level: "INFO", Event: "e", Source: "test"}))
	before, _ := os.ReadFile(logPath(dir))

	st, err := OpenPinned(dir, testKey(), pinsOf(s))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if u := st.Uncovered(); u.Records != 1 || u.Bytes == 0 {
		t.Fatalf("uncovered = %+v, want the one record", u)
	}
	if h := st.Head(); h.Size != 3 {
		t.Fatalf("head size = %d, want 3 (the covered records)", h.Size)
	}
	if after, _ := os.ReadFile(logPath(dir)); !bytes.Equal(before, after) {
		t.Fatal("a read-only open changed the log")
	}
	if q, _ := filepath.Glob(logPath(dir) + ".crash-tail-*"); len(q) != 0 {
		t.Fatalf("quarantine file written: %v", q)
	}
	if err := st.Append("INFO", "e", "test", nil); err == nil {
		t.Fatal("read-only store appended")
	}
}

func TestPinnedStillCatchesTruncationAndMissingHead(t *testing.T) {
	dir, s := signedStore(t, 3)
	data, _ := os.ReadFile(logPath(dir))
	frame := len(frameFor(t, Entry{Seq: 3, Level: "INFO", Event: "e", Source: "test"}))
	if err := os.WriteFile(logPath(dir), data[:len(data)-frame], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPinned(dir, testKey(), pinsOf(s)); err == nil {
		t.Fatal("truncated log verified")
	}

	dir, s = signedStore(t, 2)
	if err := os.Remove(filepath.Join(dir, treeHeadFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPinned(dir, testKey(), pinsOf(s)); !errors.Is(err, ErrMissingTreeHead) {
		t.Fatalf("missing head: %v", err)
	}
}

func TestPinnedIsSafeBesideARunningWriter(t *testing.T) {
	dir, s := signedStore(t, 50)
	w, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := w.Append("INFO", "e", "test", map[string]int{"i": i}); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	deadline := time.Now().Add(time.Second)
	var checks int
	var checkErr error
	for checkErr == nil && time.Now().Before(deadline) {
		st, err := OpenPinned(dir, testKey(), pinsOf(s))
		if err == nil {
			_, err = st.VerifyIntegrity()
			_ = st.Close()
		}
		if err != nil {
			checkErr = fmt.Errorf("check %d: %w", checks, err)
		}
		checks++
	}
	close(stop)
	wg.Wait()
	if checkErr != nil {
		t.Fatal(checkErr)
	}

	if q, _ := filepath.Glob(logPath(dir) + ".crash-tail-*"); len(q) != 0 {
		t.Fatalf("a check moved records out of the live log: %v", q)
	}
	all, err := ReadAll(dir, testKey())
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("record %d has seq %d: the log lost records", i, e.Seq)
		}
	}
	if _, err := OpenPinned(dir, testKey(), pinsOf(s)); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d checks beside %d appends", checks, len(all)-50)
}
