package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
)

func TestSaveConfigIfMissingWritesFirstInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	if err := saveConfigIfMissing(config.DefaultConfig(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("written config does not load: %v", err)
	}
}

// The R5 layout: config.json root-owned and read-only to the witness. init
// used to fail at its last step ("save config: permission denied").
func TestSaveConfigIfMissingLeavesExistingReadOnlyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	orig := []byte("{\n  \"drift_interval_sec\": 30\n}\n")
	if err := os.WriteFile(path, orig, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil { // nor may it replace the file
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	t.Setenv("SBH_AUDIT_PATH", "/from/env")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveConfigIfMissing(cfg, path); err != nil {
		t.Fatalf("existing read-only config: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(orig) {
		t.Fatalf("existing config was rewritten:\n%s", got)
	}
}
