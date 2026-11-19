package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

type statusTestSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s statusTestSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s statusTestSigner) PublicKey() ed25519.PublicKey    { return s.pub }

func statusTestStore(t *testing.T, n int) (string, []byte, *store.Store) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	dir := t.TempDir()
	w, err := store.Open(dir, key, statusTestSigner{priv, pub})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Append("INFO", "e", "test", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	return dir, key, w
}

// status runs beside the live daemon. Before it opened the log read-only it
// reported "tree head root mismatch: log tampered" on a busy log (seen on a
// real box), because it read the log and the head at different moments.
func TestStatusIntegrityBesideARunningWriter(t *testing.T) {
	dir, key, w := statusTestStore(t, 50)
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
			if err := w.Append("DRIFT", "drift", "drift_detected", map[string]int{"i": i}); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	deadline := time.Now().Add(time.Second)
	var checks int
	var checkErr error
	for checkErr == nil && time.Now().Before(deadline) {
		if _, _, err := statusIntegrity(dir, key); err != nil {
			checkErr = fmt.Errorf("status check %d: %w", checks, err)
		}
		checks++
	}
	close(stop)
	wg.Wait()
	if checkErr != nil {
		t.Fatal(checkErr)
	}
	if q, _ := filepath.Glob(filepath.Join(dir, "witness.log.crash-tail-*")); len(q) != 0 {
		t.Fatalf("status moved records out of the live log: %v", q)
	}
	all, err := store.ReadAll(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range all {
		if e.Seq != uint64(i+1) {
			t.Fatalf("record %d has seq %d: the log lost records", i, e.Seq)
		}
	}
}

// Bytes after the signed head (a write in progress, or a torn tail) are
// reported, never moved: only the daemon's Open recovers a crash tail.
func TestStatusIntegrityLeavesATailInPlace(t *testing.T) {
	dir, key, w := statusTestStore(t, 5)
	_ = w.Close()
	log := filepath.Join(dir, "witness.log")
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("torn-tail")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	before, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}

	head, u, err := statusIntegrity(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if head.Size != 5 {
		t.Fatalf("head size %d, want 5", head.Size)
	}
	if u.Bytes != int64(len("torn-tail")) {
		t.Fatalf("uncovered bytes %d, want %d", u.Bytes, len("torn-tail"))
	}
	after, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("status changed the log")
	}
	if q, _ := filepath.Glob(log + ".crash-tail-*"); len(q) != 0 {
		t.Fatalf("status moved the tail aside: %v", q)
	}
}
