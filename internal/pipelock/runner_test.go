package pipelock

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWriteConfigSchema guards against issue #10: the generated config must use
// Pipelock v3 top-level keys and must not reintroduce the invented keys that
// Pipelock rejects at startup with unknown-field errors.
func TestWriteConfigSchema(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig(dir)
	if err := cfg.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	got := string(data)

	// Real Pipelock v3 top-level keys that must be present.
	for _, key := range []string{
		"version:", "mode: audit", "enforce: false",
		"fetch_proxy:", "forward_proxy:", "logging:",
		"mcp_input_scanning:", "mcp_tool_scanning:", "behavioral_baseline:",
	} {
		if !strings.Contains(got, key) {
			t.Errorf("generated config missing expected key %q\n%s", key, got)
		}
	}

	// Invented keys from the old template that Pipelock rejects. If any of
	// these come back, the network audit leg silently no-ops again.
	for _, bad := range []string{
		"\nproxy:", "\naudit:", "\npolicy:", "\nresponse_scan:", "\nbehavioral:", "\nmcp:",
	} {
		if strings.Contains(got, bad) {
			t.Errorf("generated config reintroduced rejected key %q", strings.TrimSpace(bad))
		}
	}

	// The tailer follows logging.file; it must be the configured audit log.
	if !strings.Contains(got, cfg.AuditLog) {
		t.Errorf("logging.file does not point at the audit log %q\n%s", cfg.AuditLog, got)
	}
}

// TestWriteConfigPassesPipelockCheck validates the generated config against the
// real Pipelock binary when it is installed. Skipped in environments without
// pipelock (e.g. CI without the tool), so it never blocks the build but proves
// the schema on any machine that has Pipelock.
func TestWriteConfigPassesPipelockCheck(t *testing.T) {
	bin, err := exec.LookPath("pipelock")
	if err != nil {
		t.Skip("pipelock binary not installed; skipping live schema check")
	}
	dir := t.TempDir()
	cfg := DefaultConfig(dir)
	if err := cfg.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	out, err := exec.Command(bin, "check", "--config", cfg.ConfigFile).CombinedOutput()
	if err != nil {
		t.Fatalf("pipelock check rejected generated config: %v\n%s", err, out)
	}
}
