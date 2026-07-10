package pipelock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeLine appends one JSONL entry to path.
func writeLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	_ = f.Close()
}

// collect reads up to n events from ch within timeout, returning what arrived.
func collect(ch chan AuditEvent, n int, timeout time.Duration) []AuditEvent {
	var got []AuditEvent
	deadline := time.After(timeout)
	for len(got) < n {
		select {
		case evt := <-ch:
			got = append(got, evt)
		case <-deadline:
			return got
		}
	}
	return got
}

func newFastTailer(dir string, ch chan AuditEvent) *EvidenceTailer {
	et := NewEvidenceTailer(dir, ch)
	et.pollEvery = 20 * time.Millisecond
	return et
}

// Pre-existing files are followed from the end: entries written before start
// are skipped, entries appended after start are forwarded.
func TestEvidenceTailerSkipsHistoryFollowsNew(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "evidence-sess-1.jsonl")
	writeLine(t, f, `{"type":"receipt","decision":"allow","seq":1}`) // historical

	ch := make(chan AuditEvent, 16)
	et := newFastTailer(dir, ch)
	go et.Run()
	defer et.Stop()

	time.Sleep(80 * time.Millisecond) // let it open and seek to end
	writeLine(t, f, `{"type":"receipt","decision":"block","seq":2}`)

	got := collect(ch, 1, time.Second)
	if len(got) != 1 {
		t.Fatalf("expected 1 new event, got %d", len(got))
	}
	if got[0]["seq"].(float64) != 2 {
		t.Errorf("expected only the post-start entry (seq 2), got %v", got[0])
	}
}

// A file that appears after the tailer starts is read from the beginning.
func TestEvidenceTailerReadsNewFileFromStart(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan AuditEvent, 16)
	et := newFastTailer(dir, ch)
	go et.Run()
	defer et.Stop()

	time.Sleep(80 * time.Millisecond)
	f := filepath.Join(dir, "evidence-sess-2.jsonl")
	writeLine(t, f, `{"type":"receipt","seq":1}`)
	writeLine(t, f, `{"type":"receipt","seq":2}`)

	got := collect(ch, 2, time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 events from new file, got %d", len(got))
	}
}

// Rotation to a second evidence file is picked up.
func TestEvidenceTailerRotation(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan AuditEvent, 16)
	et := newFastTailer(dir, ch)
	go et.Run()
	defer et.Stop()

	time.Sleep(80 * time.Millisecond)
	writeLine(t, filepath.Join(dir, "evidence-sess-3-0.jsonl"), `{"seq":1}`)
	writeLine(t, filepath.Join(dir, "evidence-sess-3-1.jsonl"), `{"seq":2}`)

	got := collect(ch, 2, time.Second)
	if len(got) != 2 {
		t.Fatalf("expected 2 events across rotated files, got %d", len(got))
	}
}

// Malformed lines are skipped without stalling the stream.
func TestEvidenceTailerSkipsMalformed(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan AuditEvent, 16)
	et := newFastTailer(dir, ch)
	go et.Run()
	defer et.Stop()

	time.Sleep(80 * time.Millisecond)
	f := filepath.Join(dir, "evidence-sess-4.jsonl")
	writeLine(t, f, `not json`)
	writeLine(t, f, `{"seq":7}`)

	got := collect(ch, 1, time.Second)
	if len(got) != 1 || got[0]["seq"].(float64) != 7 {
		t.Fatalf("expected only the valid entry (seq 7), got %v", got)
	}
}

// Stop is clean even when the directory never appears.
func TestEvidenceTailerStopNoDir(t *testing.T) {
	ch := make(chan AuditEvent, 1)
	et := newFastTailer(filepath.Join(t.TempDir(), "does-not-exist"), ch)
	go et.Run()
	done := make(chan struct{})
	go func() { et.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not return within 1s")
	}
}
