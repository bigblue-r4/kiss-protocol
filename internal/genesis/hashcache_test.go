package genesis

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A merged-/usr layout in miniature: bin -> usr/bin, plus a binary that is
// itself a symlink to another binary in the same directory.
func mergedUsr(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(usrBin, "tool"), []byte("tool v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(usrBin, "other"), []byte("other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tool", filepath.Join(usrBin, "tool-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(usrBin, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestHashOneFileStreamsTheContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	data := make([]byte, 3<<20) // larger than any io.Copy buffer
	for i := range data {
		data[i] = byte(i * 7)
	}
	if err := os.WriteFile(p, data, 0o640); err != nil {
		t.Fatal(err)
	}
	e := HashOneFile(p)
	sum := sha256.Sum256(data)
	if e == nil || e.SHA256 != hex.EncodeToString(sum[:]) || e.Size != int64(len(data)) || e.Mode != "0640" || e.Path != p {
		t.Fatalf("got %+v", e)
	}
	if HashOneFile(filepath.Join(t.TempDir(), "nope")) != nil {
		t.Fatal("missing file must give nil")
	}
	if HashOneFile(t.TempDir()) != nil {
		t.Fatal("a directory must give nil, as os.ReadFile did")
	}
}

// The cache must give exactly what HashOneFile gives for every path.
func TestHashCacheMatchesHashOneFile(t *testing.T) {
	root := mergedUsr(t)
	hc := NewHashCache()
	for _, rel := range []string{"usr/bin/tool", "bin/tool", "usr/bin/tool-alias", "bin/tool-alias",
		"usr/bin/other", "bin/other", "usr/bin/dangling", "bin/dangling", "bin/nope"} {
		p := filepath.Join(root, rel)
		got, want := hc.Hash(p), HashOneFile(p)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: cache %+v, direct %+v", rel, got, want)
		}
	}
}

// Each underlying file is hashed once per pass; entries keep their own paths.
func TestHashCacheSharesResolvedFiles(t *testing.T) {
	root := mergedUsr(t)
	hc := NewHashCache()
	a := hc.Hash(filepath.Join(root, "usr/bin/tool"))
	b := hc.Hash(filepath.Join(root, "bin/tool-alias"))
	if a == nil || b == nil || a.SHA256 != b.SHA256 || a.Path == b.Path || a == b {
		t.Fatalf("a=%+v b=%+v", a, b)
	}
	if n := len(hc.byReal); n != 1 {
		t.Fatalf("hashed %d underlying files, want 1", n)
	}
	b.SHA256 = "mutated" // callers own their entries
	if c := hc.Hash(filepath.Join(root, "bin/tool")); c.SHA256 != a.SHA256 {
		t.Fatal("a caller's change leaked into the cache")
	}
}

// A new pass sees a change made after the last one (the cache never outlives a pass).
func TestNewPassSeesChanges(t *testing.T) {
	root := mergedUsr(t)
	p := filepath.Join(root, "bin/tool")
	before := NewHashCache().Hash(p)
	if err := os.WriteFile(filepath.Join(root, "usr/bin/tool"), []byte("tool v2, tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	after := NewHashCache().Hash(p)
	if before.SHA256 == after.SHA256 {
		t.Fatal("a fresh cache must rehash")
	}
}

func TestHashPathsRecordsEveryPath(t *testing.T) {
	root := mergedUsr(t)
	got := hashPaths(nil, []string{filepath.Join(root, "usr/bin"), filepath.Join(root, "bin")})
	// tool, other, tool-alias in each dir; dangling is unreadable and skipped, as before.
	if len(got) != 6 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	for _, e := range got {
		if !reflect.DeepEqual(&e, HashOneFile(e.Path)) {
			t.Errorf("%s differs from HashOneFile", e.Path)
		}
	}
}
