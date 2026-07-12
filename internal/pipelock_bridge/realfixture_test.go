package pipelock_bridge

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// fixturePath points at a hand-authored but schema-faithful sample of Pipelock
// v3.0.0 flight_recorder evidence. Each row matches the real recorder.Entry
// envelope (v/seq/ts/session_id/type/event_kind/detail/prev_hash/hash) and the
// receipt/decision/checkpoint detail shapes from the v3.0.0 source. Values like
// hashes/signatures are illustrative — witness re-hashes every entry into its
// own Merkle log, so pipelock's inner chain need not verify for these tests.
const fixturePath = "testdata/pipelock_v3_evidence.jsonl"

func readFixture(t *testing.T) []pipelock.AuditEvent {
	t.Helper()
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	var evts []pipelock.AuditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var evt pipelock.AuditEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			t.Fatalf("unmarshal fixture line: %v", err)
		}
		evts = append(evts, evt)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	return evts
}

// TestClassifyReceiptRealFixture runs the real v3.0.0 evidence envelope through
// classifyReceipt. It guards issue #10 bug #1 against the actual schema (not
// hand-authored guesses): the action verb wins over the generic action_receipt
// type, the decision row's verdict — which lives at detail.verdict, not under
// action_record — still elevates the level, and the checkpoint is labelled.
func TestClassifyReceiptRealFixture(t *testing.T) {
	evts := readFixture(t)
	if len(evts) != 3 {
		t.Fatalf("expected 3 fixture entries, got %d", len(evts))
	}

	want := []struct {
		level string
		event string
	}{
		{"INFO", "pipelock_receipt:write"},          // action_receipt, verdict allow
		{"WARN", "pipelock_receipt:proxy_decision"}, // decision, detail.verdict block → WARN
		{"INFO", "pipelock_receipt:checkpoint"},     // final shutdown checkpoint
	}
	for i, evt := range evts {
		level, event := classifyReceipt(evt)
		if level != want[i].level || event != want[i].event {
			t.Errorf("entry %d: got (%s, %s), want (%s, %s)", i, level, event, want[i].level, want[i].event)
		}
	}
}

// TestCleanShutdownIngestion is the end-to-end regression guard for issue #10
// bug #2: the final checkpoint Pipelock writes on clean shutdown must reach the
// witness log. It drives the real evidence path — EvidenceTailer → bridge
// forward() → classifyReceipt → store — and writes the closing checkpoint just
// before stopping, so only the drain-on-stop can capture it.
func TestCleanShutdownIngestion(t *testing.T) {
	s := openTestStore(t)
	dir := t.TempDir()
	cfg := pipelock.DefaultConfig(dir)
	b := New(cfg, s) // cfg.EvidenceDir is set, so b.evidence exists

	if b.evidence == nil {
		t.Fatal("expected an evidence tailer for the default config")
	}
	b.evidence.SetPollEvery(20 * time.Millisecond)

	evts := readFixture(t)
	if err := os.MkdirAll(cfg.EvidenceDir, 0700); err != nil {
		t.Fatalf("mkdir evidence dir: %v", err)
	}
	evFile := filepath.Join(cfg.EvidenceDir, "evidence-sess-7f3a.jsonl")

	// Start just the evidence tailer + forwarder (no pipelock subprocess), and
	// let the first (empty) directory scan complete so the evidence file is
	// discovered as a new file and read from the start rather than skipped.
	b.enabled = true
	go b.forward()
	go b.evidence.Run()
	time.Sleep(80 * time.Millisecond)

	// Stream the receipts, holding back the closing checkpoint (last entry), and
	// wait — by polling the store, not a fixed sleep — until they are ingested.
	// This keeps the test deterministic on slow CI runners.
	for _, evt := range evts[:len(evts)-1] {
		writeJSONL(t, evFile, evt)
	}
	waitForSize(t, s, uint64(len(evts)-1), 5*time.Second)

	// Pipelock's final checkpoint, written immediately before shutdown.
	writeJSONL(t, evFile, evts[len(evts)-1])
	b.evidence.Stop() // must drain to EOF, capturing the checkpoint

	close(b.stopForward)
	<-b.done

	entries, err := store.ReadAll(filepath.Dir(s.Path()), testKey())
	if err != nil {
		t.Fatalf("store.ReadAll: %v", err)
	}
	if len(entries) != len(evts) {
		t.Fatalf("ingested %d entries, want %d", len(entries), len(evts))
	}
	var sawCheckpoint bool
	for _, e := range entries {
		if e.Event == "pipelock_receipt:checkpoint" {
			sawCheckpoint = true
		}
	}
	if !sawCheckpoint {
		t.Fatal("final shutdown checkpoint did not reach the witness log")
	}
}

// waitForSize blocks until the store holds at least want leaves or timeout.
func waitForSize(t *testing.T, s *store.Store, want uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Head().Size >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("store did not reach %d leaves within %s (have %d)", want, timeout, s.Head().Size)
}

func writeJSONL(t *testing.T, path string, evt pipelock.AuditEvent) {
	t.Helper()
	b, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	_ = f.Close()
}
