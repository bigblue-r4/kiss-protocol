package farm

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// testdata/farm_events.jsonl is the "Examples" block of docs/farm-events.md,
// byte for byte (TestFixtureIsTheDocumentedExamples keeps them in step). There is
// no external producer of this format yet: the documented examples are the spec.

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

func fixture(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "farm_events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
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

func entries(t *testing.T, s *store.Store) []store.Entry {
	t.Helper()
	es, err := store.ReadAll(filepath.Dir(s.Path()), testKey())
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// clock is a controllable time source for the silence monitor.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// startBridge opens a store and a resumable bridge on a fresh feed file, and
// waits for the tailer to open it (its tail_fresh entry is the readiness signal).
func startBridge(t *testing.T, threshold time.Duration, c *clock) (*Bridge, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "store"), testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	feed := filepath.Join(dir, "farm.jsonl")
	appendLine(t, feed, "")
	b := New(feed, s, threshold)
	b.checkEvery = 50 * time.Millisecond
	b.now = c.now
	b.ResumeFrom(filepath.Join(dir, "tail-state", "farm_events.json"))
	b.Start()
	waitSize(t, s, 1)
	return b, s, feed
}

func TestDocumentedExamplesAreRecordedAndLabelled(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 2, 21, 6, 0, 0, time.UTC)}
	b, s, feed := startBridge(t, time.Hour, c)
	lines := fixture(t)
	for _, l := range lines {
		appendLine(t, feed, l)
	}
	waitSize(t, s, uint64(1+len(lines)))
	b.Stop()

	es := entries(t, s)[1:] // after tail_fresh
	want := []struct{ level, event string }{
		{"INFO", "farm_reading:ammonia_ppm"},
		{"WARN", "farm_alarm:high_temperature"},
		{"INFO", "farm_setting_change:min_ventilation_pct"},
		{"INFO", "farm_access:house-3/entry"},
		{"INFO", "farm_health:vaccination"},
		{"INFO", "farm_heartbeat"},
	}
	if len(es) != len(want) {
		t.Fatalf("got %d entries, want %d", len(es), len(want))
	}
	for i, w := range want {
		if es[i].Level != w.level || es[i].Event != w.event || es[i].Source != "farm" {
			t.Errorf("entry %d = %s/%s/%s, want %s/%s/farm", i, es[i].Level, es[i].Event, es[i].Source, w.level, w.event)
		}
	}
	// The payload is the event exactly as sent: who changed the ventilation, and from what.
	var p map[string]interface{}
	if err := json.Unmarshal(es[2].Data, &p); err != nil {
		t.Fatal(err)
	}
	if p["by"] != "remote:jdoe" || p["from"].(float64) != 30 || p["to"].(float64) != 10 {
		t.Errorf("setting change payload = %v", p)
	}
	if n, err := s.VerifyIntegrity(); err != nil || n != uint64(1+len(want)) {
		t.Fatalf("VerifyIntegrity = %d, %v", n, err)
	}
}

func TestUnknownKindIsRecordedNotDropped(t *testing.T) {
	if l, e := Classify(pipelock.AuditEvent{"kind": "egg_count", "value": 41000.0}); l != "INFO" || e != "farm_event" {
		t.Fatalf("got %s/%s", l, e)
	}
	if l, e := Classify(pipelock.AuditEvent{}); l != "INFO" || e != "farm_event" {
		t.Fatalf("no kind: got %s/%s", l, e)
	}
}

// The "frozen house" check, end to end.
func TestQuietHouseIsFlaggedOnceThenResumes(t *testing.T) {
	t0 := time.Date(2026, 10, 2, 21, 0, 0, 0, time.UTC)
	c := &clock{t: t0}
	b, s, feed := startBridge(t, 10*time.Minute, c)

	appendLine(t, feed, `{"ts":"2026-10-02T21:00:00Z","source":"house-3/controller","kind":"heartbeat"}`)
	appendLine(t, feed, `{"ts":"2026-10-02T21:00:00Z","source":"house-4/controller","kind":"heartbeat"}`)
	waitSize(t, s, 3)

	// house-4 keeps reporting inside the threshold; house-3 goes quiet.
	c.set(t0.Add(9 * time.Minute))
	appendLine(t, feed, `{"ts":"2026-10-02T21:09:00Z","source":"house-4/controller","kind":"heartbeat"}`)
	waitSize(t, s, 4)
	c.set(t0.Add(11 * time.Minute))    // house-3: 11 min quiet; house-4: 2 min
	waitSize(t, s, 5)                  // exactly one silence warning
	time.Sleep(300 * time.Millisecond) // several more checks: must not repeat the warning
	if got := s.Head().Size; got != 5 {
		t.Fatalf("silence warning repeated or extra entries: size %d, want 5", got)
	}

	// house-3 comes back.
	c.set(t0.Add(15 * time.Minute))
	appendLine(t, feed, `{"ts":"2026-10-02T21:15:00Z","source":"house-3/controller","kind":"heartbeat"}`)
	waitSize(t, s, 7)
	b.Stop()

	var names []string
	for _, e := range entries(t, s) {
		names = append(names, e.Level+" "+e.Event)
	}
	want := []string{
		"INFO tail_fresh",
		"INFO farm_heartbeat", "INFO farm_heartbeat",
		"INFO farm_heartbeat",
		"WARN farm_source_silent",
		"INFO farm_heartbeat",
		"INFO farm_source_resumed",
	}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("record =\n  %v\nwant\n  %v", names, want)
	}
	var p map[string]interface{}
	_ = json.Unmarshal(entries(t, s)[4].Data, &p)
	if p["source"] != "house-3/controller" {
		t.Errorf("silent source = %v, want house-3/controller", p["source"])
	}
}

func TestMonitorUsesTheEventsOwnTime(t *testing.T) {
	m := NewMonitor(10 * time.Minute)
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	// Caught up after a restart: an hour-old event arriving now must not count as "just seen".
	m.Seen("house-1", "heartbeat", t0)
	if got := m.Check(t0.Add(time.Hour)); len(got) != 1 || got[0].Data["source"] != "house-1" {
		t.Fatalf("Check = %v, want house-1 silent", got)
	}
	if got := m.Check(t0.Add(2 * time.Hour)); len(got) != 0 {
		t.Fatalf("flagged twice: %v", got)
	}
	if tr := m.Seen("house-1", "reading", t0.Add(2*time.Hour)); tr == nil || tr.Event != "farm_source_resumed" {
		t.Fatalf("Seen after silence = %v, want resumed", tr)
	}
	if got := m.Check(t0.Add(2*time.Hour + time.Minute)); len(got) != 0 {
		t.Fatalf("flagged right after resuming: %v", got)
	}
}

func TestNeverSeenSourceIsNeverFlagged(t *testing.T) {
	m := NewMonitor(time.Minute)
	if got := m.Check(time.Now().Add(24 * time.Hour)); len(got) != 0 {
		t.Fatalf("Check on an empty monitor = %v", got)
	}
}

func TestFixtureIsTheDocumentedExamples(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "farm-events.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)## Examples\n\n```json\n(.*?)```").FindSubmatch(doc)
	if m == nil {
		t.Fatal("docs/farm-events.md has no Examples block")
	}
	data, err := os.ReadFile(filepath.Join("testdata", "farm_events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(m[1]) != string(data) {
		t.Fatal("testdata/farm_events.jsonl no longer matches the documented examples; regenerate it from the doc")
	}
}

// A door reader or the records office reports only when something happens; being
// quiet is normal for them, so they must never be flagged.
func TestEventDrivenSourcesAreNeverFlaggedSilent(t *testing.T) {
	m := NewMonitor(time.Minute)
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	m.Seen("house-3/entry-door", "access", t0)
	m.Seen("office/records", "health", t0)
	m.Seen("house-3/controller", "alarm", t0) // alarm alone doesn't make it periodic either
	if got := m.Check(t0.Add(24 * time.Hour)); len(got) != 0 {
		t.Fatalf("event-driven sources flagged: %v", got)
	}
	// Once a source shows it reports on a schedule, it is watched, and any report counts.
	m.Seen("house-3/controller", "reading", t0)
	m.Seen("house-3/controller", "alarm", t0.Add(30*time.Second))
	got := m.Check(t0.Add(2 * time.Minute))
	if len(got) != 1 || got[0].Data["source"] != "house-3/controller" {
		t.Fatalf("Check = %v, want only house-3/controller", got)
	}
}
