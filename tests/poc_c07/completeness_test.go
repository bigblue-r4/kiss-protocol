//go:build poc_c07

package poc_c07

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/farm"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// gaps is a third-party sequence check: the seq values that are missing.
func gaps(entries []store.Entry) []uint64 {
	var missing []uint64
	for i := 1; i < len(entries); i++ {
		for s := entries[i-1].Seq + 1; s < entries[i].Seq; s++ {
			missing = append(missing, s)
		}
	}
	if len(entries) > 0 {
		for s := uint64(1); s < entries[0].Seq; s++ {
			missing = append(missing, s)
		}
	}
	return missing
}

// ── 7.6.2 monotonic sequence numbers make a missing record detectable ───────

func TestC07_7_6_2_SequenceIsMonotonicFromOne(t *testing.T) {
	key := machineKey(t)
	dir := writeLog(t, key, newSigner(t), 50)
	e := readEntries(t, dir, key)
	for i, x := range e {
		if x.Seq != uint64(i+1) {
			t.Fatalf("entry %d has seq %d, want %d", i, x.Seq, i+1)
		}
	}
}

// Delete a record and re-sign the head with the witness key (the attack that
// passes the local Merkle check): the gap is still visible from seq alone.
func TestC07_7_6_2_DeletionLeavesADetectableGap(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 10)
	e := readEntries(t, dir, key)
	rewriteLog(t, dir, key, append(e[:6:6], e[7:]...))
	forgeHead(t, dir, key, s)
	got := gaps(readEntries(t, dir, key))
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("third-party gap check found %v, want [7]", got)
	}
}

// Probe: the published verifier does not run that check. A deleted-and-re-signed
// log verifies cleanly even though the gap is plain in the data.
func TestC07_7_6_2_Probe_PublishedVerifierFlagsSequenceGaps(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 10)
	e := readEntries(t, dir, key)
	rewriteLog(t, dir, key, append(e[:6:6], e[7:]...))
	forgeHead(t, dir, key, s)
	if st, err := store.Open(dir, key, s); err == nil {
		n, verr := st.VerifyIntegrity()
		_ = st.Close()
		if verr == nil {
			t.Fatalf("store.Open + VerifyIntegrity accepted %d records with seq 7 missing; no seq-continuity check exists", n)
		}
	}
}

// Probe: sequence numbers are per log, not per source. A gap in one source's
// events is not visible when other sources keep writing.
func TestC07_7_6_2_Probe_SequenceIsPerSource(t *testing.T) {
	key := machineKey(t)
	dir := writeLog(t, key, newSigner(t), 0)
	st, _ := store.Open(dir, key, nil)
	for i := 0; i < 3; i++ {
		_ = st.Append("INFO", "a", "source-a", nil)
		_ = st.Append("INFO", "b", "source-b", nil)
	}
	_ = st.Close()
	var aSeqs []uint64
	for _, e := range readEntries(t, dir, key) {
		if e.Source == "source-a" {
			aSeqs = append(aSeqs, e.Seq)
		}
	}
	if fmt.Sprint(aSeqs) != "[1 2 3]" {
		t.Fatalf("source-a's records carry seq %v (one counter shared by all sources), not a per-source sequence [1 2 3]", aSeqs)
	}
}

// ── Completeness: events suppressed before they reach the witness ───────────

func startFarm(t *testing.T, feed string, key []byte) (*store.Store, *farm.Bridge, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := farm.New(feed, st, 200*time.Millisecond)
	b.SetCheckEvery(50 * time.Millisecond)
	b.ResumeFrom(filepath.Join(dir, "tail-state", "farm.json"))
	b.Start()
	return st, b, dir
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		_, _ = f.WriteString(l + "\n")
	}
	_ = f.Close()
}

func waitFor(t *testing.T, dir string, key []byte, pred func([]store.Entry) bool) []store.Entry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e, _ := store.ReadAll(dir, key)
		if pred(e) || time.Now().After(deadline) {
			return e
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func countEvent(e []store.Entry, prefix string) int {
	n := 0
	for _, x := range e {
		if strings.HasPrefix(x.Event, prefix) {
			n++
		}
	}
	return n
}

// A source that reports on a schedule and is silenced upstream is noticed:
// the witness records farm_source_silent.
func TestC07_Completeness_SilencedPeriodicSourceIsFlagged(t *testing.T) {
	key := machineKey(t)
	feed := filepath.Join(t.TempDir(), "farm.jsonl")
	appendLines(t, feed)
	st, b, dir := startFarm(t, feed, key)
	defer func() { b.Stop(); _ = st.Close() }()
	time.Sleep(150 * time.Millisecond)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	appendLines(t, feed, fmt.Sprintf(`{"ts":%q,"source":"house-1/controller","kind":"heartbeat"}`, now))
	// ... and then nothing: the controller is suppressed upstream.
	e := waitFor(t, dir, key, func(e []store.Entry) bool { return countEvent(e, "farm_source_silent") > 0 })
	if countEvent(e, "farm_source_silent") == 0 {
		t.Fatal("a periodic source that went quiet was not flagged")
	}
}

// Probe: a single event suppressed upstream, while the source keeps reporting
// around it, leaves no trace. The farm feed carries no source sequence number,
// so nothing can show it existed.
func TestC07_Completeness_Probe_SingleSuppressedEventIsDetectable(t *testing.T) {
	key := machineKey(t)
	feed := filepath.Join(t.TempDir(), "farm.jsonl")
	appendLines(t, feed)
	st, b, dir := startFarm(t, feed, key)
	defer func() { b.Stop(); _ = st.Close() }()
	time.Sleep(150 * time.Millisecond)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	appendLines(t, feed,
		fmt.Sprintf(`{"ts":%q,"source":"house-1/controller","kind":"reading","metric":"temp","value":80}`, now),
		// the alarm at this point is suppressed upstream and never written
		fmt.Sprintf(`{"ts":%q,"source":"house-1/controller","kind":"reading","metric":"temp","value":81}`, now))
	e := waitFor(t, dir, key, func(e []store.Entry) bool { return countEvent(e, "farm_reading") >= 2 })
	for _, x := range e {
		if strings.Contains(x.Event, "gap") || strings.Contains(x.Event, "missing") || x.Level == "WARN" {
			return // something flagged it
		}
	}
	t.Fatalf("an event suppressed upstream between two recorded readings left no trace in %d records: "+
		"completeness rests entirely on the source", len(e))
}

// ── 7.2.1 contemporaneous: capture time and write timing ────────────────────

func TestC07_7_2_1_SourceCaptureTimestampIsPreserved(t *testing.T) {
	key := machineKey(t)
	feed := filepath.Join(t.TempDir(), "farm.jsonl")
	appendLines(t, feed)
	st, b, dir := startFarm(t, feed, key)
	defer func() { b.Stop(); _ = st.Close() }()
	time.Sleep(150 * time.Millisecond)
	capture := "2026-10-02T21:02:00.123456Z"
	appendLines(t, feed, fmt.Sprintf(`{"ts":%q,"source":"house-3/controller","kind":"alarm","alarm":"x"}`, capture))
	e := waitFor(t, dir, key, func(e []store.Entry) bool { return countEvent(e, "farm_alarm") > 0 })
	for _, x := range e {
		if strings.HasPrefix(x.Event, "farm_alarm") {
			var d map[string]any
			_ = json.Unmarshal(x.Data, &d)
			if d["ts"] != capture {
				t.Fatalf("capture ts %q stored as %v", capture, d["ts"])
			}
			return
		}
	}
	t.Fatal("alarm not recorded")
}

// Probe: C7.2.1 wants evidence written "within the executing transaction",
// not batch-reconstructed. The witness reads feeds after the fact, and after a
// restart it catches up in a batch: the record's own ts is the catch-up time.
func TestC07_7_2_1_Probe_EvidenceIsNotBatchReconstructed(t *testing.T) {
	key := machineKey(t)
	feed := filepath.Join(t.TempDir(), "farm.jsonl")
	appendLines(t, feed)
	st, b, dir := startFarm(t, feed, key)
	time.Sleep(150 * time.Millisecond)
	b.Stop() // witness down
	_ = st.Close()

	written := time.Now().UTC()
	for i := 0; i < 5; i++ {
		appendLines(t, feed, fmt.Sprintf(`{"ts":%q,"source":"h","kind":"access","door":"d%d"}`,
			written.Format(time.RFC3339Nano), i))
	}
	time.Sleep(1200 * time.Millisecond) // the actions happened; the witness is still down

	st2, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	b2 := farm.New(feed, st2, time.Hour)
	b2.ResumeFrom(filepath.Join(dir, "tail-state", "farm.json"))
	b2.Start()
	defer func() { b2.Stop(); _ = st2.Close() }()
	e := waitFor(t, dir, key, func(e []store.Entry) bool { return countEvent(e, "farm_access") >= 5 })
	for _, x := range e {
		if strings.HasPrefix(x.Event, "farm_access") && x.Timestamp.Sub(written) > time.Second {
			t.Fatalf("record written %v after the action (batch catch-up after restart); "+
				"the witness is an asynchronous reader, not part of the action's transaction",
				x.Timestamp.Sub(written).Round(time.Millisecond))
		}
	}
}
