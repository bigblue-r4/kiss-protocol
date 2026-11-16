package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatalf("got %q", b)
	}
	assertOnly(t, dir, "state.json")
}

// perm goes through the umask exactly as os.WriteFile's does.
func TestWriteFileAtomicPermMatchesWriteFile(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	for _, perm := range []os.FileMode{0o600, 0o644, 0o666} {
		a, b := filepath.Join(dir, "atomic"), filepath.Join(dir, "plain")
		_ = os.Remove(a)
		_ = os.Remove(b)
		if err := WriteFileAtomic(a, nil, perm); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, nil, perm); err != nil {
			t.Fatal(err)
		}
		ia, _ := os.Stat(a)
		ib, _ := os.Stat(b)
		if ia.Mode().Perm() != ib.Mode().Perm() {
			t.Errorf("perm %o: atomic %o, os.WriteFile %o", perm, ia.Mode().Perm(), ib.Mode().Perm())
		}
	}
}

// A failed write leaves the old file and no temporary file behind.
func TestWriteFileAtomicFailureLeavesOld(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Renaming a file over a non-empty directory fails.
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(sub, []byte("new"), 0o600); err == nil {
		t.Fatal("rename over a non-empty directory should fail")
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("got %q", b)
	}
	assertOnly(t, dir, "state.json", "sub")
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	if err := WriteFileAtomic(filepath.Join(t.TempDir(), "no", "such"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

// Concurrent writers never share a temporary file: every result is one
// writer's complete contents.
func TestWriteFileAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "head.json")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte(strings.Repeat(string(rune('a'+i)), 4096))
			if err := WriteFileAtomic(p, data, 0o600); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	b, _ := os.ReadFile(p)
	if len(b) != 4096 || strings.Count(string(b), string(b[0])) != 4096 {
		t.Fatalf("torn result: %d bytes", len(b))
	}
	assertOnly(t, dir, "head.json")
}

func assertOnly(t *testing.T, dir string, names ...string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Fatalf("dir holds %v, want %v", got, names)
	}
}
