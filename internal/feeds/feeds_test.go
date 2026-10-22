package feeds

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

func testKey() []byte { return make([]byte, 32) }

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func waitSize(t *testing.T, s *store.Store, n uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.Head().Size < n {
		if time.Now().After(deadline) {
			t.Fatalf("store reached %d entries, want %d", s.Head().Size, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		line, level, event string
	}{
		{`{"kind":"egress_hit","level":"WARN"}`, "WARN", "egress_hit"},
		{`{"kind":"dispatch_start"}`, "INFO", "dispatch_start"},
		{`{"kind":"integrity_breach","level":"CRITICAL"}`, "CRITICAL", "integrity_breach"},
		{`{"kind":"x","level":"debug"}`, "INFO", "x"},
		{`{"kind":"has space"}`, "INFO", "feed_event"},
		{`{"level":"WARN"}`, "WARN", "feed_event"},
		{`{"kind":42}`, "INFO", "feed_event"},
	} {
		var evt pipelock.AuditEvent
		if err := json.Unmarshal([]byte(c.line), &evt); err != nil {
			t.Fatal(err)
		}
		l, e := Classify(evt)
		if l != c.level || e != c.event {
			t.Errorf("%s: got %s %s, want %s %s", c.line, l, e, c.level, c.event)
		}
	}
}

// Two feeds, two sources: each line is stored under its feed's configured name,
// whatever "source" the line itself claims.
func TestFeedsRecordUnderTheirConfiguredSource(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "log"), testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, b := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "b.jsonl")
	// Feeds exist before the witness first starts (a fresh feed is read from its end).
	appendLine(t, a, `{"kind":"before_start"}`)
	appendLine(t, b, `{"kind":"before_start"}`)

	ba, bb := New(a, "exp1-dispatch", s), New(b, "exp1-egress", s)
	ba.ResumeFrom(filepath.Join(dir, "a.state"))
	bb.ResumeFrom(filepath.Join(dir, "b.state"))
	ba.Start()
	bb.Start()
	waitSize(t, s, 2) // the two open records
	appendLine(t, a, `{"kind":"dispatch_start","trial_id":"T-A-0001"}`)
	appendLine(t, b, `{"kind":"egress_hit","level":"WARN","source":"dispatch","token_id":"HT-GATE-0001"}`)
	waitSize(t, s, 4)
	ba.Stop()
	bb.Stop()

	entries, err := store.ReadAll(filepath.Join(dir, "log"), testKey())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if e.Event == "dispatch_start" || e.Event == "egress_hit" {
			got[e.Event] = e.Source + "/" + e.Level
		}
	}
	if got["dispatch_start"] != "exp1-dispatch/INFO" || got["egress_hit"] != "exp1-egress/WARN" {
		t.Fatalf("got %v", got)
	}
	if _, err := s.VerifyIntegrity(); err != nil {
		t.Fatal(err)
	}
}

func TestFeedResumesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "log")
	feed, state := filepath.Join(dir, "f.jsonl"), filepath.Join(dir, "f.state")
	count := func() int {
		entries, _ := store.ReadAll(logDir, testKey())
		n := 0
		for _, e := range entries {
			if e.Event == "tick" {
				n++
			}
		}
		return n
	}

	s, _ := store.Open(logDir, testKey(), nil)
	appendLine(t, feed, `{"kind":"before_start"}`)
	br := New(feed, "exp1", s)
	br.ResumeFrom(state)
	br.Start()
	waitSize(t, s, 1)
	appendLine(t, feed, `{"kind":"tick","n":1}`)
	waitSize(t, s, 2)
	br.Stop()
	_ = s.Close()

	appendLine(t, feed, `{"kind":"tick","n":2}`) // written while the witness is down

	s, _ = store.Open(logDir, testKey(), nil)
	defer s.Close()
	before := s.Head().Size
	br = New(feed, "exp1", s)
	br.ResumeFrom(state)
	br.Start()
	waitSize(t, s, before+2)
	br.Stop()
	if n := count(); n != 2 {
		t.Fatalf("ticks recorded %d, want 2 (none lost, none doubled)", n)
	}
}
