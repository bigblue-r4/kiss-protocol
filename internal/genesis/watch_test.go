package genesis

import (
	"os"
	"path/filepath"
	"testing"
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
