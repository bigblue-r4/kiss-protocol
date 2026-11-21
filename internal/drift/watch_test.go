package drift

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
)

// A path added through the operator's watch list is checked like a built-in
// one: swapping the binary is reported, and so is removing it.
func TestMeasureReportsChangedExtraWatchedFile(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "split-brain-harness")
	gone := filepath.Join(dir, "wasmtime")
	for _, p := range []string{bin, gone} {
		if err := os.WriteFile(p, []byte("v1"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := genesis.TakeWith("m", nil, genesis.Watch{Dirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("v2 swapped"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	changes, err := Measure(snap)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range changes {
		if filepath.Dir(c.Path) == dir {
			got[c.Path] = c.Type
		}
	}
	if got[bin] != "file_changed" || got[gone] != "file_removed" {
		t.Fatalf("changes in the watched dir = %v, want %s changed and %s removed", got, bin, gone)
	}
}
