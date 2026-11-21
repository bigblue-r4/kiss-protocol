package drift

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
)

func writeFile(t *testing.T, p, s string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
}

// fileChanges returns the file changes under dir, keyed by path.
func fileChanges(t *testing.T, snap *genesis.Snapshot, dir string) map[string]Change {
	t.Helper()
	changes, err := Measure(snap)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range changes {
		if c.Path != "" && strings.HasPrefix(c.Path, dir+"/") {
			if _, dup := got[c.Path]; dup {
				t.Errorf("%s reported twice", c.Path)
			}
			got[c.Path] = c
		}
	}
	return got
}

// A binary planted in a watched directory after genesis is reported once,
// with its hash; a new subdirectory is not entered.
func TestMeasureReportsFileAddedToWatchedDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "witness"), "v1", 0o755)
	snap, err := genesis.TakeWith("m", nil, genesis.Watch{Dirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if got := fileChanges(t, snap, dir); len(got) != 0 {
		t.Fatalf("clean dir reported %v", got)
	}

	planted := filepath.Join(dir, "sshd-helper")
	writeFile(t, planted, "implant", 0o755)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "sub", "deeper"), "x", 0o644)

	got := fileChanges(t, snap, dir)
	c, ok := got[planted]
	want := genesis.HashOneFile(planted).SHA256
	if !ok || c.Type != "file_added" || c.New != want {
		t.Fatalf("planted file: got %+v, want file_added with its hash %s (all: %v)", c, want, got)
	}
	if len(got) != 1 {
		t.Errorf("want only the planted file, got %v", got)
	}
}

// Through a symlinked alias (/bin -> /usr/bin) a new file is reported once.
func TestMeasureFileAddedAliasedDirReportedOnce(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "usr-bin")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "bin")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(real, "ls"), "ls", 0o755)
	snap, err := genesis.TakeWith("m", nil, genesis.Watch{Dirs: []string{real, alias}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(real, "new"), "new", 0o755)
	if got := fileChanges(t, snap, root); len(got) != 1 {
		t.Fatalf("want one report for the new file, got %v", got)
	}
}

// A file the witness cannot read is still reported as added; one that was
// already unreadable at genesis is not.
func TestMeasureFileAddedUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-0 files")
	}
	dir := t.TempDir()
	old := filepath.Join(dir, "old-secret")
	writeFile(t, old, "x", 0o000)
	snap, err := genesis.TakeWith("m", nil, genesis.Watch{Dirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	hidden := filepath.Join(dir, "hidden")
	writeFile(t, hidden, "implant", 0o000)
	got := fileChanges(t, snap, dir)
	if c := got[hidden]; c.Type != "file_added" || c.New != Unreadable {
		t.Fatalf("unreadable new file: got %+v, want file_added/%s", c, Unreadable)
	}
	if _, ok := got[old]; ok {
		t.Error("an entry unreadable at genesis was reported as added")
	}
}

// A genesis from before watched_dirs was recorded (the running log on a host
// upgraded in place) is scanned in the built-in dirs that hold its files,
// and keeps its hash.
func TestMeasureFileAddedLegacyGenesis(t *testing.T) {
	dir := t.TempDir()
	unwatched := t.TempDir()
	saved := genesis.WatchDirs
	genesis.WatchDirs = []string{dir, unwatched}
	t.Cleanup(func() { genesis.WatchDirs = saved })

	writeFile(t, filepath.Join(dir, "a"), "a", 0o755)
	snap, err := genesis.Take("m", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The old format: no watched_dirs and no unreadable list. (That its hash
	// is unchanged is tested in package genesis.)
	snap.WatchedDirs, snap.Unreadable = nil, nil
	raw, _ := json.Marshal(snap)
	reloaded, err := genesis.Load(raw)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(dir, "planted"), "p", 0o755)
	writeFile(t, filepath.Join(unwatched, "new"), "n", 0o755)
	got := fileChanges(t, reloaded, dir)
	if c := got[filepath.Join(dir, "planted")]; c.Type != "file_added" {
		t.Fatalf("legacy genesis: planted file not reported (%v)", got)
	}
	if g := fileChanges(t, reloaded, unwatched); len(g) != 0 {
		t.Errorf("a dir with no files at genesis was scanned for a legacy snapshot: %v", g)
	}
}
