package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
)

// A witness killed mid-write used to leave a log that never opened again:
// later records sat behind the partial frame and the head no longer matched.
// Open now moves a crash tail aside (never deletes it, never signs it).

func logPath(dir string) string { return filepath.Join(dir, logFilename) }

func appendRaw(t *testing.T, dir string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(logPath(dir), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// frameFor encrypts and frames an entry exactly as Append does.
func frameFor(t *testing.T, e Entry) []byte {
	t.Helper()
	plain, _ := json.Marshal(e)
	sealed, err := encrypt.Seal(plain, testKey())
	if err != nil {
		t.Fatal(err)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(sealed))), sealed...)
}

func signedStore(t *testing.T, n int) (string, *testDevSigner) {
	t.Helper()
	s := newTestDevSigner(t)
	dir := t.TempDir()
	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := st.Append("INFO", "e", "test", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()
	return dir, s
}

func TestTornWriteIsRecoveredAndLaterRecordsSurvive(t *testing.T) {
	dir, s := signedStore(t, 3)
	torn := append(binary.BigEndian.AppendUint32(nil, 500), []byte("abcdef")...) // length says 500, 6 bytes follow
	appendRaw(t, dir, torn)

	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatalf("log with a torn tail did not open: %v", err)
	}
	r := st.Recovered()
	if r.Bytes != int64(len(torn)) || r.UncommittedRecords != 0 {
		t.Fatalf("recovery = %+v, want %d bytes, 0 records", r, len(torn))
	}
	if q, err := os.ReadFile(r.QuarantineFile); err != nil || !bytes.Equal(q, torn) {
		t.Fatalf("quarantined bytes = %q (%v), want the torn frame", q, err)
	}
	for i := 0; i < 2; i++ {
		if err := st.Append("INFO", "after-crash", "test", nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()

	got, _ := ReadAll(dir, testKey())
	if len(got) != 5 || got[3].Seq != 4 || got[4].Seq != 5 {
		t.Fatalf("after recovery and 2 appends: %d records, want 5 with seq 4, 5", len(got))
	}
	st, err = Open(dir, testKey(), s)
	if err != nil {
		t.Fatalf("reopen after recovery: %v", err)
	}
	if st.Recovered().Bytes != 0 {
		t.Fatal("a clean log reported a recovery")
	}
	_ = st.Close()
}

// Killed after the record was written but before its head: exactly one
// complete record the head doesn't cover. It is moved aside, not signed.
func TestUncommittedRecordIsQuarantinedNotSigned(t *testing.T) {
	dir, s := signedStore(t, 3)
	headBefore, _ := os.ReadFile(filepath.Join(dir, treeHeadFilename))
	extra := frameFor(t, Entry{Seq: 4, Timestamp: time.Now().UTC(), Level: "INFO", Event: "uncommitted", Source: "test"})
	appendRaw(t, dir, extra)

	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatalf("log with one uncommitted record did not open: %v", err)
	}
	r := st.Recovered()
	if r.UncommittedRecords != 1 || r.Bytes != int64(len(extra)) {
		t.Fatalf("recovery = %+v, want 1 record, %d bytes", r, len(extra))
	}
	if q, _ := os.ReadFile(r.QuarantineFile); !bytes.Equal(q, extra) {
		t.Fatal("quarantine file does not hold the uncommitted record")
	}
	if head, _ := os.ReadFile(filepath.Join(dir, treeHeadFilename)); !bytes.Equal(head, headBefore) {
		t.Fatal("opening re-signed the head over the uncommitted record")
	}
	if err := st.Append("INFO", "next", "test", nil); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	for _, e := range mustReadAll(t, dir) {
		if e.Event == "uncommitted" {
			t.Fatal("the uncommitted record ended up in the signed log")
		}
	}
}

// Two unaccounted records is not a crash: still tampering.
func TestTwoExtraRecordsAreStillTampering(t *testing.T) {
	dir, s := signedStore(t, 3)
	appendRaw(t, dir, frameFor(t, Entry{Seq: 4, Timestamp: time.Now().UTC(), Event: "x", Source: "test"}))
	appendRaw(t, dir, frameFor(t, Entry{Seq: 5, Timestamp: time.Now().UTC(), Event: "y", Source: "test"}))
	if _, err := Open(dir, testKey(), s); err == nil {
		t.Fatal("two records beyond the head opened cleanly")
	}
}

// An uncommitted record followed by an undecryptable complete frame is not a
// clean crash tail: nothing is moved and the head must cover everything.
func TestUncommittedRecordWithJunkAfterItIsTampering(t *testing.T) {
	dir, s := signedStore(t, 3)
	appendRaw(t, dir, frameFor(t, Entry{Seq: 4, Timestamp: time.Now().UTC(), Event: "x", Source: "test"}))
	junk := append(binary.BigEndian.AppendUint32(nil, 40), make([]byte, 40)...)
	appendRaw(t, dir, junk)
	before, _ := os.Stat(logPath(dir))
	if _, err := Open(dir, testKey(), s); err == nil {
		t.Fatal("opened cleanly")
	}
	if after, _ := os.Stat(logPath(dir)); after.Size() != before.Size() {
		t.Fatal("a failed open modified the log")
	}
}

// With the wrong key every record fails to decrypt. That is not a crash tail:
// nothing may be moved.
func TestWrongKeyMovesNothing(t *testing.T) {
	dir, _ := signedStore(t, 3)
	before, _ := os.Stat(logPath(dir))
	st, err := Open(dir, make([]byte, 32), nil)
	if err == nil {
		if st.Recovered().Bytes != 0 {
			t.Fatal("wrong key quarantined the log")
		}
		_ = st.Close()
	}
	if after, _ := os.Stat(logPath(dir)); after.Size() != before.Size() {
		t.Fatalf("log size changed from %d to %d", before.Size(), after.Size())
	}
}

// A tampered log with a torn tail is refused, and the evidence left as found.
func TestTamperedLogWithTornTailIsNotModified(t *testing.T) {
	dir, s := signedStore(t, 4)
	entries := mustReadAll(t, dir)
	entries[1].Event = "edited"
	var out []byte
	for _, e := range entries {
		out = append(out, frameFor(t, e)...)
	}
	out = append(out, binary.BigEndian.AppendUint32(nil, 300)...)
	_ = os.WriteFile(logPath(dir), out, 0600)
	if _, err := Open(dir, testKey(), s); err == nil {
		t.Fatal("tampered log opened")
	}
	if after, _ := os.ReadFile(logPath(dir)); !bytes.Equal(after, out) {
		t.Fatal("a refused log was modified")
	}
}

func TestRootAtMatchesEarlierHeads(t *testing.T) {
	dir, s := signedStore(t, 5)
	h5 := mustHead(t, dir)
	st, _ := Open(dir, testKey(), s)
	for i := 0; i < 3; i++ {
		_ = st.Append("INFO", "more", "test", nil)
	}
	got, err := st.RootAt(5)
	if err != nil || got != h5.Root {
		t.Fatalf("RootAt(5) = %s, %v; want the size-5 head root %s", got, err, h5.Root)
	}
	if _, err := st.RootAt(9); err == nil {
		t.Fatal("RootAt beyond the log size did not error")
	}
	_ = st.Close()
}

func mustReadAll(t *testing.T, dir string) []Entry {
	t.Helper()
	e, err := ReadAll(dir, testKey())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustHead(t *testing.T, dir string) TreeHead {
	t.Helper()
	h, err := readStoredHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
