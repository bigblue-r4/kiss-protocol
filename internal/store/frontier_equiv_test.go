package store

import (
	"encoding/hex"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// TestAppendHeadMatchesFullRecompute: Append keeps the root incrementally
// (merkle.Frontier). After every append, across reopens and a crash-tail
// recovery, the stored head must equal a from-scratch merkle.Root over every
// record in the log, and the log must still verify.
func TestAppendHeadMatchesFullRecompute(t *testing.T) {
	s := newTestDevSigner(t)
	dir := t.TempDir()
	open := func() *Store {
		st, err := Open(dir, testKey(), s)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	check := func(when string) {
		t.Helper()
		es, err := ReadAll(dir, testKey())
		if err != nil {
			t.Fatal(err)
		}
		leaves := make([][32]byte, len(es))
		for i, e := range es {
			leaves[i] = leafHash(e)
		}
		root := merkle.Root(leaves)
		h, err := readStoredHead(dir)
		if err != nil {
			t.Fatal(err)
		}
		if h.Size != uint64(len(es)) || h.Root != hex.EncodeToString(root[:]) {
			t.Fatalf("%s: head size %d root %s, full recompute gives %d %x", when, h.Size, h.Root, len(es), root)
		}
		if err := verifyHeadSignature(h, root, pinsOf(s)); err != nil {
			t.Fatalf("%s: %v", when, err)
		}
	}
	st := open()
	for i := 0; i < 300; i++ {
		if err := st.Append("INFO", "e", "test", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
		check("append")
		if i%37 == 36 {
			_ = st.Close()
			st = open()
			if h := st.Head(); h.Size != uint64(i+1) {
				t.Fatalf("Head() after reopen: size %d, want %d", h.Size, i+1)
			}
		}
	}
	// A crash tail (one uncommitted record) is moved aside at the next open;
	// appending after that must continue from the committed records.
	_ = st.Close()
	appendRaw(t, dir, frameFor(t, Entry{Seq: 301, Level: "INFO", Event: "e", Source: "test"}))
	st = open()
	if st.Recovered().UncommittedRecords != 1 {
		t.Fatalf("crash tail not recovered: %+v", st.Recovered())
	}
	if err := st.Append("INFO", "after-crash", "test", nil); err != nil {
		t.Fatal(err)
	}
	check("append after crash-tail recovery")
	_ = st.Close()

	ro, err := OpenPinned(dir, testKey(), pinsOf(s))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if n, err := ro.VerifyIntegrity(); err != nil || n != 301 {
		t.Fatalf("verify after incremental appends: %d %v", n, err)
	}
	h := ro.Head()
	es, _ := ReadAll(dir, testKey())
	leaves := make([][32]byte, len(es))
	for i, e := range es {
		leaves[i] = leafHash(e)
	}
	if r := merkle.Root(leaves); h.Root != hex.EncodeToString(r[:]) {
		t.Fatal("read-only Head() differs from a full recompute")
	}
}
