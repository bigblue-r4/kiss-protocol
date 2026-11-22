//go:build linux

package accept

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
)

func TestProcessPathHelper(t *testing.T) {
	if os.Getenv("KISS_PROCESS_PATH_TEST_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, "ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestMeasuredSameNameDifferentPathIsUnapprovedDrift(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, label := range []string{"approved", "other"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "pipelock")
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, path, "-test.run=^TestProcessPathHelper$")
		cmd.Env = append(os.Environ(), "KISS_PROCESS_PATH_TEST_HELPER=1")
		input, err := cmd.StdinPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = input.Close(); cancel(); _ = cmd.Wait() })
		ready, err := bufio.NewReader(output).ReadString('\n')
		if err != nil || ready != "ready\n" {
			t.Fatalf("%s process did not start: %q %v", label, ready, err)
		}
		paths = append(paths, path)
	}
	changes, err := drift.Measure(&genesis.Snapshot{WatchedDirs: []string{t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	var measured []drift.Change
	for _, c := range changes {
		if c.Type == "new_process" && c.Process == "pipelock" && (c.Path == paths[0] || c.Path == paths[1]) {
			measured = append(measured, c)
		}
	}
	if len(measured) != 2 {
		t.Fatalf("distinct same-name binaries not measured: %+v", measured)
	}
	op := newKey(t)
	set := NewSet()
	if _, err := set.Apply(signedAccept(t, op, drift.Change{Type: "new_process", Process: "pipelock", Path: paths[0]}), policy(op, nil)); err != nil {
		t.Fatal(err)
	}
	left, n := set.Filter(measured)
	if n != 1 || len(left) != 1 || left[0].Path != paths[1] {
		t.Fatalf("different binary hidden by approval: approved=%d drift=%+v", n, left)
	}
}
