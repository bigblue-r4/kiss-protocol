package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/death"
)

func TestVerifyDeathCLI(t *testing.T) {
	if os.Getenv("WITNESS_VERIFY_DEATH_TEST_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				return
			}
		}
		os.Exit(2)
	}
	dir := t.TempDir()
	for name, data := range map[string]string{"witness.log": "encrypted log", "genesis.enc": "baseline", "tree-head.json": `{"size":1}`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writer := death.New(dir, "test")
	if err := writer.Fire("first"); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "witness.log"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("append"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Fire("second"); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*"))
	before := map[string][]byte{}
	for _, path := range paths {
		before[path], _ = os.ReadFile(path)
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestVerifyDeathCLI$", "--", "verify-death"}, args...)...)
		cmd.Env = append(os.Environ(), "WITNESS_VERIFY_DEATH_TEST_HELPER=1")
		return cmd.CombinedOutput()
	}
	for _, args := range [][]string{{dir}, {"--log", filepath.Join(dir, "witness.log"), dir}} {
		output, err := run(args...)
		if err != nil || !bytes.Contains(output, []byte("OK death_")) {
			t.Fatalf("CLI: %v\n%s", err, output)
		}
	}
	after, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(after) != len(paths) {
		t.Fatal("CLI created files")
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("CLI changed %s", path)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "witness.log"), []byte("tamper"), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := run("--log", filepath.Join(dir, "witness.log"), dir); err == nil || !bytes.Contains(output, []byte("FAIL")) {
		t.Fatalf("CLI accepted tampering: %v\n%s", err, output)
	}
}
