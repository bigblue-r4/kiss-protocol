package pipelock

import (
	"path/filepath"
	"testing"
	"time"
)

// TestTailerDrainsFinalRecordOnStop guards issue #10 bug #2: pipelock writes a
// final transcript_root/checkpoint on clean shutdown, and Stop must read to EOF
// so that record reaches the witness log instead of being dropped.
func TestTailerDrainsFinalRecordOnStop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	writeLine(t, path, `{"event":"start","seq":1}`) // historical — skipped (seek to end)

	ch := make(chan AuditEvent, 16)
	tl := NewTailer(path, ch)
	go tl.Run()
	time.Sleep(120 * time.Millisecond) // open, seek to end, reach EOF

	// Pipelock's clean-shutdown checkpoint, written just before it exits.
	writeLine(t, path, `{"event":"transcript_root","seq":2}`)

	// Stop drains to EOF before returning; the buffered channel holds the record.
	tl.Stop()

	got := collect(ch, 1, time.Second)
	if len(got) != 1 || got[0]["seq"].(float64) != 2 {
		t.Fatalf("final shutdown record not drained on stop; got %v", got)
	}
}

// TestEvidenceTailerDrainsFinalReceiptOnStop is the flight_recorder analogue:
// the final signed receipt written before shutdown must be drained on Stop.
func TestEvidenceTailerDrainsFinalReceiptOnStop(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "evidence-sess-1.jsonl")
	writeLine(t, f, `{"type":"action_receipt","seq":1}`) // historical

	ch := make(chan AuditEvent, 16)
	et := newFastTailer(dir, ch)
	go et.Run()
	time.Sleep(120 * time.Millisecond) // discover + seek to end

	writeLine(t, f, `{"type":"action_receipt","event_kind":"session_close","seq":2}`)
	et.Stop()

	got := collect(ch, 1, time.Second)
	if len(got) != 1 || got[0]["seq"].(float64) != 2 {
		t.Fatalf("final receipt not drained on stop; got %v", got)
	}
}

// TestEvidenceTailerFinalScanOnStop guards the final directory scan: a receipt
// file pipelock creates at the last moment (after the poll loop's last tick)
// must still be discovered and drained when Stop runs.
func TestEvidenceTailerFinalScanOnStop(t *testing.T) {
	dir := t.TempDir()
	ch := make(chan AuditEvent, 16)
	et := NewEvidenceTailer(dir, ch)
	et.pollEvery = time.Hour // only the final scan on Stop can discover new files

	go et.Run()
	time.Sleep(80 * time.Millisecond) // let the first scan run and then park on the poll

	// File appears after the (single) poll tick — only Stop's final scan sees it.
	writeLine(t, filepath.Join(dir, "evidence-sess-last.jsonl"), `{"type":"action_receipt","seq":9}`)
	et.Stop()

	got := collect(ch, 1, time.Second)
	if len(got) != 1 || got[0]["seq"].(float64) != 9 {
		t.Fatalf("last-moment evidence file not drained via final scan; got %v", got)
	}
}
