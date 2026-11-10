package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"
)

// dirState fingerprints everything in dir a reader could change: names,
// sizes, modes, mtimes, inodes and content hashes.
func dirState(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		var ino uint64
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = st.Ino
		}
		sum := ""
		if !d.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			sum = hex.EncodeToString(h[:])
		}
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, fmt.Sprintf("%s|%s|%d|%d|%d|%s", rel, fi.Mode(), fi.ModTime().UnixNano(), fi.Size(), ino, sum))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

// readAllSince walks the whole log in steps of ReadSince and returns every
// covered entry and the final offset.
func readAllSince(t *testing.T, dir string) (TreeHead, []Entry, int64) {
	t.Helper()
	head, es, off, err := ReadSince(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return head, es, off
}

func TestReadSinceIncrementalMatchesReadAll(t *testing.T) {
	s := newTestDevSigner(t)
	dir := t.TempDir()
	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var got []Entry
	var off int64
	for round := 0; round < 5; round++ {
		for i := 0; i <= round; i++ {
			if err := st.Append("INFO", "e", "test", map[string]int{"r": round, "i": i}); err != nil {
				t.Fatal(err)
			}
		}
		head, es, next, err := ReadSince(dir, testKey(), off, uint64(len(got)))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, es...)
		off = next
		if head.Size != uint64(len(got)) {
			t.Fatalf("round %d: head size %d, have %d records", round, head.Size, len(got))
		}
	}
	// Nothing new: no records, same offset.
	head, es, next, err := ReadSince(dir, testKey(), off, uint64(len(got)))
	if err != nil || len(es) != 0 || next != off || head.Size != uint64(len(got)) {
		t.Fatalf("idle read: %d records, off %d→%d, err %v", len(es), off, next, err)
	}
	all, err := ReadAll(dir, testKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(got) {
		t.Fatalf("incremental read %d records, ReadAll %d", len(got), len(all))
	}
	for i := range all {
		if LeafHash(all[i]) != LeafHash(got[i]) {
			t.Fatalf("record %d differs between incremental and full read", i)
		}
	}
	if fi, _ := os.Stat(logPath(dir)); fi.Size() != off {
		t.Fatalf("final offset %d, log is %d bytes", off, fi.Size())
	}
}

// TestReadSinceNeverMutates: with an uncovered record and a torn partial frame
// after the covered ones (what makes Open quarantine a crash tail), ReadSince
// changes nothing, returns only covered records, and still works with the
// directory and files made read-only.
func TestReadSinceNeverMutates(t *testing.T) {
	dir, _ := signedStore(t, 4)
	appendRaw(t, dir, frameFor(t, Entry{Seq: 5, Level: "INFO", Event: "e", Source: "test"}))
	torn := frameFor(t, Entry{Seq: 6, Level: "INFO", Event: "e", Source: "test"})
	appendRaw(t, dir, torn[:len(torn)/2])
	before := dirState(t, dir)

	head, es, off, err := ReadSince(dir, testKey(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if head.Size != 4 || len(es) != 4 {
		t.Fatalf("head %d, %d records; want only the 4 covered", head.Size, len(es))
	}
	if _, _, _, err := ReadSince(dir, testKey(), off, 4); err != nil {
		t.Fatal(err)
	}
	if after := dirState(t, dir); after != before {
		t.Fatalf("ReadSince changed the directory:\nbefore\n%s\nafter\n%s", before, after)
	}
	if q, _ := filepath.Glob(logPath(dir) + ".crash-tail-*"); len(q) != 0 {
		t.Fatalf("quarantine file written: %v", q)
	}

	// The fingerprint must see a change, or the comparison above proves nothing.
	data, _ := os.ReadFile(logPath(dir))
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(logPath(dir), data, 0600); err != nil {
		t.Fatal(err)
	}
	if dirState(t, dir) == before {
		t.Fatal("fingerprint did not notice a rewrite of the log")
	}

	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes; the read-only-directory half needs a normal user")
	}
	for _, p := range []string{logPath(dir), filepath.Join(dir, treeHeadFilename)} {
		if err := os.Chmod(p, 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if _, es, _, err := ReadSince(dir, testKey(), 0, 0); err != nil || len(es) != 4 {
		t.Fatalf("read-only directory: %d records, err %v", len(es), err)
	}
}

func TestReadSinceHeadBehindAndMissing(t *testing.T) {
	dir, _ := signedStore(t, 3)
	if _, _, _, err := ReadSince(dir, testKey(), 0, 5); !errors.Is(err, ErrHeadBehind) {
		t.Fatalf("head behind: err = %v", err)
	}
	if err := os.Remove(filepath.Join(dir, treeHeadFilename)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ReadSince(dir, testKey(), 0, 3); !errors.Is(err, ErrMissingTreeHead) {
		t.Fatalf("missing head with records already read: err = %v", err)
	}
	empty := t.TempDir()
	if h, es, _, err := ReadSince(empty, testKey(), 0, 0); err != nil || h.Size != 0 || len(es) != 0 {
		t.Fatalf("empty dir: %+v %d %v", h, len(es), err)
	}
}

// TestReadSinceBesideWriter: a reader polling while the daemon appends always
// gets complete, contiguous records and ends with exactly the full log.
func TestReadSinceBesideWriter(t *testing.T) {
	s := newTestDevSigner(t)
	dir := t.TempDir()
	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	const n = 300
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			_ = st.Append("INFO", "e", "test", map[string]int{"i": i})
		}
	}()
	var got []Entry
	var off int64
	deadline := time.Now().Add(20 * time.Second)
	for uint64(len(got)) < n && time.Now().Before(deadline) {
		_, es, next, err := ReadSince(dir, testKey(), off, uint64(len(got)))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if e.Seq != uint64(len(got))+1 {
				t.Fatalf("record seq %d after %d records: not contiguous", e.Seq, len(got))
			}
			got = append(got, e)
		}
		off = next
	}
	wg.Wait()
	_ = st.Close()
	if len(got) != n {
		t.Fatalf("read %d of %d records", len(got), n)
	}
}

func TestVerifyHeadSignature(t *testing.T) {
	dir, s := signedStore(t, 3)
	head, _, _ := readAllSince(t, dir)
	if err := VerifyHeadSignature(head, pinsOf(s)); err != nil {
		t.Fatalf("genuine head refused: %v", err)
	}
	if err := VerifyHeadSignature(head, pinsOf(newTestDevSigner(t))); !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("unpinned signer: err = %v", err)
	}
	h := head
	h.Size++
	if err := VerifyHeadSignature(h, pinsOf(s)); err == nil {
		t.Fatal("head with size edited after signing accepted")
	}
	h = head
	h.Signature = ""
	if err := VerifyHeadSignature(h, pinsOf(s)); !errors.Is(err, ErrHeadNotSigned) {
		t.Fatalf("unsigned head: err = %v", err)
	}
	if err := VerifyHeadSignature(head, nil); err == nil {
		t.Fatal("verified with no pins")
	}
}
