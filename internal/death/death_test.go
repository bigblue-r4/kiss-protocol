package death

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) (string, []byte, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	log := bytes.Repeat([]byte("encrypted log bytes\n"), 300000)
	genesis := bytes.Repeat([]byte("encrypted baseline"), 35000)
	head := []byte(`{"size":42,"root":"abc","sig":"signed-head","signer_key":"key"}`)
	for name, data := range map[string][]byte{"witness.log": log, "genesis.enc": genesis, "tree-head.json": head} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, log, genesis, head
}

func records(t *testing.T, dir string) []Record {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "death_*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatalf("partial/invalid record: %v", err)
		}
		st, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("permissions: %v", st.Mode())
		}
		if st.Size() > 4096 {
			t.Fatalf("record too large: %d", st.Size())
		}
		out = append(out, r)
	}
	return out
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestRecordContentsAndNoCopies(t *testing.T) {
	dir, log, genesis, head := fixture(t)
	legacy := filepath.Join(dir, "death_old_witness.log")
	if err := os.WriteFile(legacy, []byte("legacy evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(dir, "machine-7").Fire("signal_received"); err != nil {
		t.Fatal(err)
	}
	rs := records(t, dir)
	if len(rs) != 1 {
		t.Fatalf("records: %d", len(rs))
	}
	r := rs[0]
	if r.Format != "witness-death/1" || r.Trigger != "signal_received" || r.MachineID != "machine-7" || r.Timestamp == "" {
		t.Fatalf("metadata: %+v", r)
	}
	var got, want any
	if err := json.Unmarshal(r.TreeHead, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(head, &want); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !bytes.Equal(gb, wb) {
		t.Fatal("head changed")
	}
	if r.LogBytes != int64(len(log)) || r.LogHash.Status != "complete" || r.LogHash.SHA256 != digest(log) {
		t.Fatalf("log: %+v", r)
	}
	if r.GenesisHash.Status != "complete" || r.GenesisHash.SHA256 != digest(genesis) {
		t.Fatalf("genesis: %+v", r.GenesisHash)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("unexpected copies/temp files: %v", entries)
	}
	for path, want := range map[string][]byte{legacy: []byte("legacy evidence"), filepath.Join(dir, "witness.log"): log, filepath.Join(dir, "genesis.enc"): genesis} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("source/legacy changed: %s: %v", path, err)
		}
	}
}

func TestDeadlinePublishesCompleteJSON(t *testing.T) {
	dir, log, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(dir, "machine").fire(ctx, "storage_anomaly"); err != nil {
		t.Fatal(err)
	}
	rs := records(t, dir)
	if len(rs) != 1 {
		t.Fatalf("records: %d", len(rs))
	}
	r := rs[0]
	if len(r.TreeHead) == 0 || r.LogBytes != int64(len(log)) || r.LogHash.Status != "incomplete" || r.LogHash.SHA256 != "" || r.GenesisHash.Status != "incomplete" {
		t.Fatalf("deadline record: %+v", r)
	}
	temps, _ := filepath.Glob(filepath.Join(dir, ".death_*"))
	if len(temps) != 0 {
		t.Fatal(temps)
	}
}

type cancellingReader struct {
	cancel context.CancelFunc
	calls  int
}

func (r *cancellingReader) Read(p []byte) (int, error) {
	r.calls++
	copy(p, "part")
	r.cancel()
	return 4, nil
}
func TestStreamingCancellationDiscardsPartialDigest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancellingReader{cancel: cancel}
	sum, err := streamHash(ctx, r, -1)
	if err != context.Canceled || sum != "" || r.calls != 1 {
		t.Fatalf("partial hash: %q, %v, calls %d", sum, err, r.calls)
	}
}

func TestStreamingHashMultiMBAndShortRead(t *testing.T) {
	dir, log, _, _ := fixture(t)
	h := hashFile(context.Background(), filepath.Join(dir, "witness.log"), int64(len(log)))
	if h.Status != "complete" || h.SHA256 != digest(log) {
		t.Fatalf("hash: %+v", h)
	}
	// Later appends are excluded from the captured byte length.
	h = hashFile(context.Background(), filepath.Join(dir, "witness.log"), 123)
	if h.SHA256 != digest(log[:123]) {
		t.Fatalf("prefix: %+v", h)
	}
	if sum, err := streamHash(context.Background(), strings.NewReader("short"), 100); err != io.ErrUnexpectedEOF || sum != "" {
		t.Fatalf("short file: %s, %v", sum, err)
	}
}

func TestMissingEvidenceStillRecordsErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tree-head.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(dir, "machine").Fire("watchdog_parent_exit"); err != nil {
		t.Fatal(err)
	}
	rs := records(t, dir)
	if len(rs) != 1 {
		t.Fatal(len(rs))
	}
	r := rs[0]
	if r.TreeHeadError == "" || r.LogBytes != -1 || r.LogHash.Status != "error" || r.GenesisHash.Status != "error" {
		t.Fatalf("missing evidence: %+v", r)
	}
}

func TestConcurrentPublicationNeverExposesPartialJSON(t *testing.T) {
	dir, _, _, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errors <- New(dir, "machine").fire(ctx, "concurrent") }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		records(t, dir) // Every visible final filename must contain complete JSON.
		select {
		case <-done:
			close(errors)
			for err := range errors {
				if err != nil {
					t.Fatal(err)
				}
			}
			if n := len(records(t, dir)); n != 8 {
				t.Fatalf("filename collisions: %d", n)
			}
			return
		default:
		}
	}
}
