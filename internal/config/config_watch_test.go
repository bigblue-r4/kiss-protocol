package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWatchPathsLoadAndValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"watch_files":["/opt/x/bin/rustc"],"watch_dirs":["/opt/x/lib"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WatchFiles) != 1 || cfg.WatchFiles[0] != "/opt/x/bin/rustc" || len(cfg.WatchDirs) != 1 {
		t.Fatalf("watch paths not loaded: %+v %+v", cfg.WatchFiles, cfg.WatchDirs)
	}
	if err := cfg.ValidateWatch(); err != nil {
		t.Fatalf("valid paths rejected: %v", err)
	}
	for _, bad := range []string{"", "opt/x", "/opt/x/../y", "/opt/x/"} {
		c := &Config{WatchDirs: []string{bad}}
		if c.ValidateWatch() == nil {
			t.Errorf("watch_dirs %q accepted", bad)
		}
		c = &Config{WatchFiles: []string{bad}}
		if c.ValidateWatch() == nil {
			t.Errorf("watch_files %q accepted", bad)
		}
	}
}
