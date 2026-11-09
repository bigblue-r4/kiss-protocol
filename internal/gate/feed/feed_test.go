package feed

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteReadStringsOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gate.jsonl")
	w, err := Open(p, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write("breaker_trip", "WARN", map[string]string{"epoch": "18446744073709551615", "kind": "spoof"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write("bad kind!", "", nil); err == nil {
		t.Fatal("bad kind accepted")
	}
	if err := os.WriteFile(p+".x", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"kind":"torn`); err != nil { // crash mid-line
		t.Fatal(err)
	}
	f.Close()
	got, err := Read(p)
	if err != nil || len(got) != 1 {
		t.Fatalf("read %v %v", got, err)
	}
	if got[0]["kind"] != "breaker_trip" || got[0]["epoch"] != "18446744073709551615" || got[0]["level"] != "WARN" {
		t.Fatalf("record %v (kind must not be overridable by fields)", got[0])
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if m, _ := Read(filepath.Join(t.TempDir(), "none")); m != nil {
		t.Fatal("missing file should be an empty feed")
	}
}

func TestWriteFailureIsSticky(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gate.jsonl")
	w, _ := Open(p, nil)
	w.f.Close() // the disk went away
	if err := w.Write("gate_request", "", nil); !errors.Is(err, ErrBroken) {
		t.Fatalf("err %v", err)
	}
	if !errors.Is(w.Healthy(), ErrBroken) {
		t.Fatal("feed should report broken")
	}
}
