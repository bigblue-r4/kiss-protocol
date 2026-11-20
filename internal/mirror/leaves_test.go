package mirror

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

type fakeLog struct{ leaves [][32]byte }

func (f *fakeLog) LeafCount() uint64 { return uint64(len(f.leaves)) }
func (f *fakeLog) LeafAt(i uint64) ([32]byte, bool) {
	if i >= uint64(len(f.leaves)) {
		return [32]byte{}, false
	}
	return f.leaves[i], true
}
func (f *fakeLog) LeavesFrom(from uint64) [][32]byte {
	if from >= uint64(len(f.leaves)) {
		return nil
	}
	return append([][32]byte(nil), f.leaves[from:]...)
}

func logOf(tag string, n int) *fakeLog {
	f := &fakeLog{}
	for i := 0; i < n; i++ {
		f.leaves = append(f.leaves, merkle.HashLeaf([]byte(tag+string(rune('a'+i%26))+string(rune(i)))))
	}
	return f
}

func feed(t *testing.T, dir string) [][32]byte {
	t.Helper()
	fh, err := os.Open(filepath.Join(dir, LeavesFilename))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	l, err := ReadLeaves(fh)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func backend(t *testing.T) (*fileBackend, string) {
	t.Helper()
	dir := t.TempDir()
	b, err := newFileBackend(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b, dir
}

func TestPublishLeavesAppendsAndIsIdempotent(t *testing.T) {
	b, dir := backend(t)
	src := logOf("x", 5)
	for i := 0; i < 2; i++ {
		if reset, err := b.PublishLeaves(src); err != nil || reset {
			t.Fatalf("publish: reset=%v err=%v", reset, err)
		}
	}
	src.leaves = append(src.leaves, logOf("y", 3).leaves...)
	if reset, err := b.PublishLeaves(src); err != nil || reset {
		t.Fatalf("append: reset=%v err=%v", reset, err)
	}
	got := feed(t, dir)
	if len(got) != 8 {
		t.Fatalf("feed has %d leaves, want 8", len(got))
	}
	for i := range got {
		if got[i] != src.leaves[i] {
			t.Fatalf("leaf %d differs", i)
		}
	}
}

// A slower concurrent push holding an older snapshot must not shrink the feed.
func TestPublishLeavesOlderSnapshotNeverShrinks(t *testing.T) {
	b, dir := backend(t)
	full := logOf("x", 10)
	if _, err := b.PublishLeaves(full); err != nil {
		t.Fatal(err)
	}
	older := &fakeLog{leaves: full.leaves[:6]}
	if reset, err := b.PublishLeaves(older); err != nil || reset {
		t.Fatalf("older snapshot: reset=%v err=%v", reset, err)
	}
	if n := len(feed(t, dir)); n != 10 {
		t.Fatalf("feed shrank to %d", n)
	}
}

func TestPublishLeavesConcurrent(t *testing.T) {
	b, dir := backend(t)
	full := logOf("x", 64)
	var wg sync.WaitGroup
	for n := 1; n <= 64; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := b.PublishLeaves(&fakeLog{leaves: full.leaves[:n]}); err != nil {
				t.Error(err)
			}
		}(n)
	}
	wg.Wait()
	got := feed(t, dir)
	if len(got) != 64 {
		t.Fatalf("feed has %d leaves, want 64", len(got))
	}
	for i := range got {
		if got[i] != full.leaves[i] {
			t.Fatalf("leaf %d differs after concurrent publishes", i)
		}
	}
}

// A re-initialised log (or a feed someone edited) is replaced, and reported.
func TestPublishLeavesResetsOnDisagreement(t *testing.T) {
	for name, damage := range map[string]func(dir string){
		"new log":   func(string) {},
		"torn feed": func(dir string) { appendBytes(t, dir, []byte{1, 2, 3}) },
	} {
		t.Run(name, func(t *testing.T) {
			b, dir := backend(t)
			if _, err := b.PublishLeaves(logOf("old", 20)); err != nil {
				t.Fatal(err)
			}
			damage(dir)
			fresh := logOf("new", 3)
			if name == "torn feed" {
				fresh = logOf("old", 20)
			}
			reset, err := b.PublishLeaves(fresh)
			if err != nil || !reset {
				t.Fatalf("want reset, got reset=%v err=%v", reset, err)
			}
			got := feed(t, dir)
			if len(got) != len(fresh.leaves) || got[0] != fresh.leaves[0] {
				t.Fatalf("feed not rewritten from the log: %d leaves", len(got))
			}
		})
	}
}

func appendBytes(t *testing.T, dir string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, LeavesFilename), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// Audit F1: root on the box rewrites an old record and publishes a correctly
// signed, LONGER head (and rewrites the feed to match). A size/same-root check
// accepts that. A verifier holding its own copy of the earlier leaves must not.
func TestVerifyLeafRootCatchesRewrittenHistory(t *testing.T) {
	honest := logOf("x", 40)
	held := append([][32]byte(nil), honest.leaves[:25]...) // what the LAB pulled earlier

	// Honest growth: held prefix + new leaves gives the new head's root.
	grown := append(append([][32]byte(nil), held...), honest.leaves[25:]...)
	if err := VerifyLeafRoot(grown, 40, merkle.Root(honest.leaves)); err != nil {
		t.Fatalf("honest growth rejected: %v", err)
	}

	// Rewrite: record 7 replaced, log extended, new root re-signed by the host.
	forged := append([][32]byte(nil), honest.leaves...)
	forged[7] = merkle.HashLeaf([]byte("rewritten record 7"))
	forged = append(forged, merkle.HashLeaf([]byte("cover-up")))
	forgedRoot := merkle.Root(forged)

	// The verifier appends only the NEW leaves from the (rewritten) feed to
	// its own copy, so leaf 7 is still the original.
	check := append(append([][32]byte(nil), held...), forged[25:]...)
	if err := VerifyLeafRoot(check, uint64(len(forged)), forgedRoot); err != ErrLeafRootMismatch {
		t.Fatalf("rewritten history accepted: err=%v", err)
	}
	// Taking the box's whole feed instead (no held copy) would accept it:
	// the check only works because the verifier keeps its earlier leaves.
	if err := VerifyLeafRoot(forged, uint64(len(forged)), forgedRoot); err != nil {
		t.Fatalf("sanity: forged feed should be self-consistent: %v", err)
	}
}

func TestVerifyLeafRootShortFeed(t *testing.T) {
	l := logOf("x", 3)
	if err := VerifyLeafRoot(l.leaves, 4, merkle.Root(l.leaves)); err == nil || err == ErrLeafRootMismatch {
		t.Fatalf("short feed: err=%v, want a distinct error", err)
	}
}

func TestReadLeavesRejectsPartial(t *testing.T) {
	if _, err := ReadLeaves(bytes.NewReader(make([]byte, 33))); err == nil {
		t.Fatal("33-byte feed accepted")
	}
}
