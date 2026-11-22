package genesis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/hashutil"
)

func TestDefaultWatchDirsCoverLocalBinaries(t *testing.T) {
	want := map[string]bool{"/usr/local/bin": false, "/usr/local/sbin": false}
	for _, d := range WatchDirs {
		if _, ok := want[d]; ok {
			want[d] = true
		}
	}
	for d, ok := range want {
		if !ok {
			t.Errorf("WatchDirs is missing %s (the witness's own binary lives there)", d)
		}
	}
}

func TestTakeWithRecordsExtraPaths(t *testing.T) {
	root := t.TempDir()
	tool := filepath.Join(root, "toolchain")
	if err := os.MkdirAll(filepath.Join(tool, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(tool, "rustc"), "compiler")
	write(filepath.Join(tool, "nested", "deep.rlib"), "not watched: dirs are one level")
	single := filepath.Join(root, "wasmtime")
	write(single, "runtime")

	snap, err := TakeWith("m", nil, Watch{
		Files: []string{single, single, filepath.Join(root, "missing")},
		Dirs:  []string{tool},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Verify() {
		t.Fatal("snapshot hash does not cover the extra paths")
	}
	count := map[string]int{}
	for _, f := range snap.Files {
		count[f.Path]++
	}
	if count[single] != 1 {
		t.Errorf("extra file recorded %d times, want 1 (listed twice)", count[single])
	}
	if count[filepath.Join(tool, "rustc")] != 1 {
		t.Error("file in an extra dir not recorded")
	}
	if count[filepath.Join(tool, "nested", "deep.rlib")] != 0 {
		t.Error("extra dirs must be shallow, like the built-in ones")
	}
	if count[filepath.Join(root, "missing")] != 0 {
		t.Error("an unreadable path was recorded")
	}

	plain, _ := Take("m", nil)
	for _, f := range plain.Files {
		if f.Path == single {
			t.Error("Take without extras recorded an extra path")
		}
	}
}

// A genesis written by a binary that predates watched_dirs/unreadable must
// still verify: the new fields are omitted when empty, so the hashed JSON is
// byte-for-byte what the old binary hashed.
func TestOldFormatSnapshotKeepsItsHash(t *testing.T) {
	s, err := Take("m", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.WatchedDirs, s.Unreadable, s.ProcessIdentities = nil, nil, nil
	s.Hash = s.computeHash()
	raw, err := s.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	// The struct as the previous release defined it.
	type oldSnapshot struct {
		Version         int             `json:"version"`
		Timestamp       time.Time       `json:"timestamp"`
		MachineID       string          `json:"machine_id"`
		OS              OSInfo          `json:"os"`
		Files           []FileEntry     `json:"files"`
		Procs           []string        `json:"procs"`
		Nets            []string        `json:"nets"`
		Users           []string        `json:"users"`
		AgentsAtGenesis []AgentPresence `json:"agents_at_genesis"`
		Hash            string          `json:"hash"`
	}
	var old oldSnapshot
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	want := old.Hash
	old.Hash = ""
	b, _ := json.Marshal(old)
	if got := hashutil.SHA256Hex(b); got != want {
		t.Fatalf("old binary would compute %s, new one %s: existing genesis files would fail verification", got, want)
	}
	loaded, err := Load(raw)
	if err != nil || !loaded.Verify() {
		t.Fatalf("old-format snapshot does not verify after load: %v", err)
	}
	if _, legacy := loaded.ScanDirs(); !legacy {
		t.Error("old-format snapshot not treated as legacy")
	}
}

func TestTakeRecordsScannedDirsAndUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-0 files")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "locked"), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	s, err := TakeWith("m", nil, Watch{Dirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ProcessIdentities) == 0 || len(s.Procs) == 0 {
		t.Fatal("new genesis did not record process identities and legacy names")
	}
	if !s.Verify() {
		t.Fatal("captured process identities not included in valid snapshot")
	}
	dirs, legacy := s.ScanDirs()
	if legacy || dirs[len(dirs)-1] != dir {
		t.Fatalf("ScanDirs = %v (legacy %v), want the built-in dirs plus %s", dirs, legacy, dir)
	}
	if len(s.Unreadable) == 0 || s.Unreadable[len(s.Unreadable)-1] != filepath.Join(dir, "locked") {
		t.Fatalf("unreadable entry not recorded: %v", s.Unreadable)
	}
}
