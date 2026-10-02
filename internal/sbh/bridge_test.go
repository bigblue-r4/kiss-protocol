package sbh

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

// The fixtures in testdata/ are written by split-brain-harness's own serializers
// (AuditEntry, SessionLogEntry, DecisionLogEntry), not by hand. Regenerate with:
//
//	SBH_WITNESS_FIXTURE_DIR=<this dir>/testdata \
//	  cargo test --test witness_fixture        # in split-brain-harness
//
// Hand-authored fixtures would only prove the fixture matches the test; this repo
// has been bitten by that before (the Pipelock decision envelopes).

func testKey() []byte { return make([]byte, 32) }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir(), testKey(), nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func fixtureLines(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s (regenerate it — see this file's header): %v", name, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		t.Fatalf("fixture %s is empty", name)
	}
	return out
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// waitReady blocks until the tailer is following logPath. The tailer seeks to the
// end of the file when it opens it, so lines appended before that are skipped by
// design; a fixed sleep made this kind of test flaky on slow CI runners before.
// Probe lines are appended until one reaches the store, then the store size is
// allowed to settle. Returns how many entries the probes produced.
func waitReady(t *testing.T, logPath string, s *store.Store) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for s.Head().Size == 0 {
		if time.Now().After(deadline) {
			t.Fatal("tailer never picked up a probe line")
		}
		appendLine(t, logPath, `{"event":"readiness_probe"}`)
		time.Sleep(100 * time.Millisecond)
	}
	for {
		before := s.Head().Size
		time.Sleep(400 * time.Millisecond)
		if s.Head().Size == before {
			return before
		}
	}
}

// ingest drives every fixture line through the real tailer and bridge into a store,
// and returns the entries the fixture produced (probe entries excluded).
func ingest(t *testing.T, fixture string, mk func(string, *store.Store) *Bridge) []store.Entry {
	t.Helper()
	s := openTestStore(t)
	logPath := filepath.Join(t.TempDir(), fixture)
	appendLine(t, logPath, "") // the log exists before the bridge starts, as in production
	b := mk(logPath, s)
	b.Start()
	probes := waitReady(t, logPath, s)
	lines := fixtureLines(t, fixture)
	for _, l := range lines {
		appendLine(t, logPath, l)
	}
	want := probes + uint64(len(lines))
	deadline := time.Now().Add(10 * time.Second)
	for s.Head().Size < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	b.Stop()
	if got := s.Head().Size; got != want {
		t.Fatalf("store holds %d entries, want %d (%d probes + %d fixture lines)", got, want, probes, len(lines))
	}
	entries, err := store.ReadAll(filepath.Dir(s.Path()), testKey())
	if err != nil {
		t.Fatalf("store.ReadAll: %v", err)
	}
	return entries[probes:]
}

func payload(t *testing.T, e store.Entry) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(e.Data, &m); err != nil {
		t.Fatalf("payload of %s: %v", e.Event, err)
	}
	return m
}

func TestDecisionLogReachesTheWitnessClassified(t *testing.T) {
	entries := ingest(t, "decisions.jsonl", NewDecisionLog)
	want := []struct{ level, event string }{
		{"INFO", "sbh_decision:pass"},         // low risk, no stop
		{"WARN", "sbh_decision:stop_and_ask"}, // the gate stopped
		{"WARN", "sbh_decision:pass"},         // escalated turn, no stop
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, w := range want {
		e := entries[i]
		if e.Level != w.level || e.Event != w.event || e.Source != "sbh" {
			t.Errorf("entry %d = %s/%s/%s, want %s/%s/sbh", i, e.Level, e.Event, e.Source, w.level, w.event)
		}
		p := payload(t, e)
		if p["input_fingerprint"] == nil || p["session_id"] != "farm-ops-7" {
			t.Errorf("entry %d payload lost SBH fields: %v", i, p)
		}
		if _, leaked := p["input"]; leaked {
			t.Errorf("entry %d carries raw input", i)
		}
	}
}

func TestSessionEscalationsReachTheWitnessAsWarnings(t *testing.T) {
	entries := ingest(t, "session_escalations.jsonl", NewSessionLog)
	for _, e := range entries {
		if e.Level != "WARN" || e.Event != "sbh_escalation" || e.Source != "sbh" {
			t.Errorf("got %s/%s/%s, want WARN/sbh_escalation/sbh", e.Level, e.Event, e.Source)
		}
		if p := payload(t, e); p["current_risk"] != "high" {
			t.Errorf("escalation payload lost current_risk: %v", p)
		}
	}
}

// The forge bridge shipped without tests; this pins its existing behaviour.
func TestForgeAuditReachesTheWitnessClassified(t *testing.T) {
	entries := ingest(t, "forge_audit.jsonl", New)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if e := entries[0]; e.Level != "INFO" || e.Event != "forge_run:parse ammonia sensor csv" {
		t.Errorf("successful run = %s/%s", e.Level, e.Event)
	}
	if e := entries[1]; e.Level != "WARN" || e.Event != "forge_run:write controller setpoint" {
		t.Errorf("failed run = %s/%s", e.Level, e.Event)
	}
}

func TestStoreChainStillVerifiesAfterIngestion(t *testing.T) {
	s := openTestStore(t)
	logPath := filepath.Join(t.TempDir(), "decisions.jsonl")
	appendLine(t, logPath, "")
	b := NewDecisionLog(logPath, s)
	b.Start()
	probes := waitReady(t, logPath, s)
	lines := fixtureLines(t, "decisions.jsonl")
	for _, l := range lines {
		appendLine(t, logPath, l)
	}
	want := probes + uint64(len(lines))
	deadline := time.Now().Add(10 * time.Second)
	for s.Head().Size < want && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	b.Stop()
	n, err := s.VerifyIntegrity()
	if err != nil || n != want {
		t.Fatalf("VerifyIntegrity = %d, %v (want %d)", n, err, want)
	}
}

func TestClassifyDecision(t *testing.T) {
	cases := []struct {
		evt          pipelock.AuditEvent
		level, event string
	}{
		{pipelock.AuditEvent{"stop_and_ask": false, "manipulation_risk": "low"}, "INFO", "sbh_decision:pass"},
		{pipelock.AuditEvent{"stop_and_ask": true, "manipulation_risk": "low"}, "WARN", "sbh_decision:stop_and_ask"},
		{pipelock.AuditEvent{"stop_and_ask": false, "manipulation_risk": "high"}, "WARN", "sbh_decision:pass"},
		{pipelock.AuditEvent{"stop_and_ask": false, "manipulation_risk": "low", "escalation": true}, "WARN", "sbh_decision:pass"},
		{pipelock.AuditEvent{}, "INFO", "sbh_decision:pass"}, // malformed line: recorded, not dropped
	}
	for i, c := range cases {
		if l, e := ClassifyDecision(c.evt); l != c.level || e != c.event {
			t.Errorf("case %d: got %s/%s, want %s/%s", i, l, e, c.level, c.event)
		}
	}
}

func TestClassifyForge(t *testing.T) {
	if l, e := ClassifyForge(pipelock.AuditEvent{"succeeded": true, "capability": "x"}); l != "INFO" || e != "forge_run:x" {
		t.Errorf("got %s/%s", l, e)
	}
	if l, e := ClassifyForge(pipelock.AuditEvent{"succeeded": false}); l != "WARN" || e != "forge_run" {
		t.Errorf("got %s/%s", l, e)
	}
}
