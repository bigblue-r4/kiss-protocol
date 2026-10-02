package pipelock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// These tests pin the resume contract: with a state file, nothing written while
// the witness was stopped is lost. Delivery is at-least-once — a crash may
// repeat an entry, never skip one.

type resumeRig struct {
	t      *testing.T
	log    string
	state  string
	mu     sync.Mutex
	opened []OpenInfo
}

func newResumeRig(t *testing.T) *resumeRig {
	dir := t.TempDir()
	return &resumeRig{t: t, log: filepath.Join(dir, "feed.jsonl"), state: filepath.Join(dir, "state", "feed.json")}
}

// run starts a resumable tailer, waits until it has opened the file, and returns it.
func (r *resumeRig) run(ch chan AuditEvent) *Tailer {
	r.t.Helper()
	tl := NewTailer(r.log, ch)
	tl.SetStateFile(r.state)
	opened := make(chan struct{}, 4)
	tl.OnOpen(func(i OpenInfo) {
		r.mu.Lock()
		r.opened = append(r.opened, i)
		r.mu.Unlock()
		opened <- struct{}{}
	})
	go tl.Run()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		r.t.Fatal("tailer never opened the file")
	}
	return tl
}

func (r *resumeRig) lastOpen() OpenInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened[len(r.opened)-1]
}

func seqs(evts []AuditEvent) []int {
	out := make([]int, len(evts))
	for i, e := range evts {
		out[i] = int(e["seq"].(float64))
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// consume reads n events, acking each one (as a bridge does after storing it).
func consume(t *testing.T, tl *Tailer, ch chan AuditEvent, n int) []AuditEvent {
	t.Helper()
	got := collect(ch, n, 5*time.Second)
	for range got {
		tl.Ack()
	}
	return got
}

func TestFirstRunWithoutStateStartsAtEnd(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":1}`) // history before the witness ever ran: skipped, as before
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	if o := r.lastOpen(); o.Mode != "fresh" {
		t.Fatalf("mode = %q, want fresh", o.Mode)
	}
	writeLine(t, r.log, `{"seq":2}`)
	got := consume(t, tl, ch, 1)
	tl.Stop()
	tl.Flush()
	if !equalInts(seqs(got), []int{2}) {
		t.Fatalf("got %v, want [2]", seqs(got))
	}
}

// The gap this closes: lines written while the witness is down.
func TestLinesWrittenWhileStoppedAreDeliveredOnRestart(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	writeLine(t, r.log, `{"seq":1}`)
	writeLine(t, r.log, `{"seq":2}`)
	consume(t, tl, ch, 2)
	tl.Stop()
	tl.Flush() // clean shutdown

	// Witness is down. The feed keeps writing.
	for _, l := range []string{`{"seq":3}`, `{"seq":4}`, `{"seq":5}`} {
		writeLine(t, r.log, l)
	}

	ch2 := make(chan AuditEvent, 16)
	tl2 := r.run(ch2)
	if o := r.lastOpen(); o.Mode != "resumed" || o.FileSize-o.From == 0 {
		t.Fatalf("open = %+v, want resumed with bytes to catch up", o)
	}
	got := consume(t, tl2, ch2, 3)
	tl2.Stop()
	tl2.Flush()
	if !equalInts(seqs(got), []int{3, 4, 5}) {
		t.Fatalf("after restart got %v, want [3 4 5] (no loss, no duplicates)", seqs(got))
	}
	if extra := collect(ch2, 1, 300*time.Millisecond); len(extra) != 0 {
		t.Fatalf("duplicate delivered after clean restart: %v", seqs(extra))
	}
}

// A crash loses the unflushed position, never the data: entries may repeat.
func TestCrashRepeatsRatherThanSkips(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	tl.Flush() // position saved right after open, before anything is consumed
	writeLine(t, r.log, `{"seq":1}`)
	writeLine(t, r.log, `{"seq":2}`)
	consume(t, tl, ch, 2) // acked, but under the flush thresholds: not yet on disk
	tl.Stop()             // "crash": no final Flush

	writeLine(t, r.log, `{"seq":3}`)
	ch2 := make(chan AuditEvent, 16)
	tl2 := r.run(ch2)
	got := consume(t, tl2, ch2, 3)
	tl2.Stop()
	if !equalInts(seqs(got), []int{1, 2, 3}) {
		t.Fatalf("after crash got %v, want [1 2 3] (repeats allowed, nothing skipped)", seqs(got))
	}
}

// An event the consumer never stored is never committed past.
func TestUnackedEventsAreRedelivered(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	for _, l := range []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`} {
		writeLine(t, r.log, l)
	}
	collect(ch, 3, 5*time.Second)
	tl.Ack() // only seq 1 was stored
	tl.Stop()
	tl.Flush()

	ch2 := make(chan AuditEvent, 16)
	tl2 := r.run(ch2)
	got := consume(t, tl2, ch2, 2)
	tl2.Stop()
	if !equalInts(seqs(got), []int{2, 3}) {
		t.Fatalf("got %v, want [2 3]", seqs(got))
	}
}

func TestFileReplacedWhileStoppedIsReadFromStart(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	writeLine(t, r.log, `{"seq":1}`)
	consume(t, tl, ch, 1)
	tl.Stop()
	tl.Flush()

	// Rotated while down: a new file (new inode) at the same path.
	if err := os.Rename(r.log, r.log+".1"); err != nil {
		t.Fatal(err)
	}
	writeLine(t, r.log, `{"seq":10}`)
	writeLine(t, r.log, `{"seq":11}`)

	ch2 := make(chan AuditEvent, 16)
	tl2 := r.run(ch2)
	if o := r.lastOpen(); o.Mode != "restarted" || o.From != 0 {
		t.Fatalf("open = %+v, want restarted from 0", o)
	}
	got := consume(t, tl2, ch2, 2)
	tl2.Stop()
	if !equalInts(seqs(got), []int{10, 11}) {
		t.Fatalf("got %v, want [10 11]", seqs(got))
	}
}

func TestFileTruncatedWhileStoppedIsReadFromStart(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	writeLine(t, r.log, `{"seq":1,"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)
	consume(t, tl, ch, 1)
	tl.Stop()
	tl.Flush()

	if err := os.Truncate(r.log, 0); err != nil { // same inode, shorter than the saved offset
		t.Fatal(err)
	}
	writeLine(t, r.log, `{"seq":20}`)

	ch2 := make(chan AuditEvent, 16)
	tl2 := r.run(ch2)
	if o := r.lastOpen(); o.Mode != "restarted" || o.From != 0 {
		t.Fatalf("open = %+v, want restarted from 0", o)
	}
	got := consume(t, tl2, ch2, 1)
	tl2.Stop()
	if !equalInts(seqs(got), []int{20}) {
		t.Fatalf("got %v, want [20]", seqs(got))
	}
}

// A line caught half-written is delivered once, whole — not dropped.
func TestPartialLineIsDeliveredWhole(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)

	f, err := os.OpenFile(r.log, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"seq":7,"note":"first ha`)
	time.Sleep(500 * time.Millisecond) // the tailer polls and sees an unterminated line
	_, _ = f.WriteString(`lf"}` + "\n")
	_ = f.Close()

	got := consume(t, tl, ch, 1)
	tl.Stop()
	if len(got) != 1 || got[0]["note"] != "first half" {
		t.Fatalf("got %v, want one intact event", got)
	}
}

// Blank and non-JSON lines are skipped without stalling the saved position.
func TestSkippedLinesDoNotBlockTheCommit(t *testing.T) {
	r := newResumeRig(t)
	writeLine(t, r.log, `{"seq":0}`)
	ch := make(chan AuditEvent, 16)
	tl := r.run(ch)
	writeLine(t, r.log, `not json`)
	writeLine(t, r.log, `{"seq":1}`)
	consume(t, tl, ch, 1)
	tl.Stop()
	tl.Flush()

	var st tailState
	data, err := os.ReadFile(r.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(r.log)
	if st.Offset != fi.Size() {
		t.Fatalf("saved offset %d, want end of file %d", st.Offset, fi.Size())
	}
}
