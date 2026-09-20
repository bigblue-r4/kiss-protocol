package pipelock

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// HIFAS (Hawaii Integrated Fraud Analytics) writes its fraud verdicts to a
// BLAKE3 hash-chained NDJSON log and describes that log as "Witness
// tailer-compatible". It is a FEEDER, not a second witness: the same role
// Pipelock's flight_recorder plays, with the Merkle log on this side being what
// folds the stream into tamper-evident storage.
//
// That compatibility claim had never been executed — it was true by inspection
// and nothing more. These tests run it.
//
// testdata/hifas_verdicts.jsonl is produced by hifas-witness's own serializer,
// not written by hand. Regenerate it with:
//
//	HIFAS_TAILER_FIXTURE_OUT=<this dir>/testdata/hifas_verdicts.jsonl \
//	  cargo test -p hifas-witness every_line_satisfies
//
// Hand-authoring the fixture would prove only that the fixture matches the
// test. This repo has been bitten by exactly that before: the earlier
// hand-authored Pipelock `decision` envelopes did not match the real
// recorder.Entry shape, and the fix was a schema-faithful fixture.

const hifasFixture = "testdata/hifas_verdicts.jsonl"

// copyFixtureLines writes the fixture's lines into path one at a time, the way
// HIFAS would append them, so the tailer sees appends rather than a file that
// existed all along.
func copyFixtureLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(hifasFixture)
	if err != nil {
		t.Fatalf("open fixture (regenerate it — see this file's header): %v", err)
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		writeLine(t, path, line)
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if n == 0 {
		t.Fatal("fixture is empty")
	}
	return n
}

// TestHifasVerdictsFlowThroughTailer drives real hifas-witness output through
// the real Tailer and asserts the entries arrive classified correctly rather
// than falling back to the generic defaults.
func TestHifasVerdictsFlowThroughTailer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hifas-verdicts.jsonl")

	// The tailer seeks to the end on open, so create the file first and append
	// afterwards — matching how a live HIFAS process would write into it.
	writeLine(t, path, `{"event":"bootstrap","level":"info"}`)

	ch := make(chan AuditEvent, 32)
	tl := NewTailer(path, ch)
	go tl.Run()
	defer tl.Stop()
	time.Sleep(120 * time.Millisecond) // open, seek to end, reach EOF

	want := copyFixtureLines(t, path)

	got := collect(ch, want, 2*time.Second)
	if len(got) != want {
		t.Fatalf("tailer delivered %d of %d HIFAS verdict lines", len(got), want)
	}

	for i, evt := range got {
		// EventName and Level are the only two fields the tailer reads. If HIFAS
		// ever stops emitting them these silently become "pipelock_event" and
		// "info", and its verdicts arrive in the witness log indistinguishable
		// from everything else being tailed — which is the failure this guards.
		if name := evt.EventName(); name != "hifas_verdict" {
			t.Errorf("line %d: event = %q, want %q (falling back to the default means the rows arrive unlabelled)", i+1, name, "hifas_verdict")
		}
		if lvl := evt.Level(); lvl != "info" {
			t.Errorf("line %d: level = %q, want %q", i+1, lvl, "info")
		}

		// The verdict payload must survive decoding intact — the point of
		// ingesting these at all is that the chain fields are auditable later.
		for _, field := range []string{"seq", "claim_id", "verdict_hash", "input_hash", "prev_hash", "entry_hash", "source"} {
			if _, ok := evt[field]; !ok {
				t.Errorf("line %d: field %q did not survive the tailer", i+1, field)
			}
		}
	}
}

// TestHifasChainFieldsArriveUnmodified checks the hash-chain linkage is intact
// on this side of the tailer. HIFAS's chain is what makes its stream
// tamper-evident before ingestion; if the tailer mangled these the witness log
// would be recording unverifiable claims.
func TestHifasChainFieldsArriveUnmodified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hifas-verdicts.jsonl")
	writeLine(t, path, `{"event":"bootstrap","level":"info"}`)

	ch := make(chan AuditEvent, 32)
	tl := NewTailer(path, ch)
	go tl.Run()
	defer tl.Stop()
	time.Sleep(120 * time.Millisecond)

	want := copyFixtureLines(t, path)
	got := collect(ch, want, 2*time.Second)
	if len(got) != want {
		t.Fatalf("got %d of %d lines", len(got), want)
	}

	// Each entry's prev_hash must equal its predecessor's entry_hash, and the
	// first must be the all-zero genesis value.
	const genesis = "0000000000000000000000000000000000000000000000000000000000000000"
	prev := genesis
	for i, evt := range got {
		gotPrev, _ := evt["prev_hash"].(string)
		if gotPrev != prev {
			t.Fatalf("line %d: prev_hash = %q, want %q — the chain did not survive ingestion", i+1, gotPrev, prev)
		}
		entryHash, _ := evt["entry_hash"].(string)
		if entryHash == "" {
			t.Fatalf("line %d: entry_hash missing", i+1)
		}
		prev = entryHash

		if seq, ok := evt["seq"].(float64); !ok || int(seq) != i+1 {
			t.Errorf("line %d: seq = %v, want %d", i+1, evt["seq"], i+1)
		}
	}
}
