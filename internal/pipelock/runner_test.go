package pipelock

import (
	"os"
	"os/exec"
	"path/filepath"
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

// TestWriteConfigSigningKey verifies the flight_recorder signing key is only
// emitted when configured, and that it passes pipelock check when present.
func TestWriteConfigSigningKey(t *testing.T) {
	dir := t.TempDir()

	// Explicitly keyless: signing_key_path is omitted (evidence leg disabled).
	cfg := DefaultConfig(dir)
	cfg.SigningKeyPath = ""
	if err := cfg.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, _ := os.ReadFile(cfg.ConfigFile)
	if strings.Contains(string(data), "signing_key_path: \"") {
		t.Errorf("signing_key_path should be absent when no key is configured\n%s", data)
	}
	if !strings.Contains(string(data), "flight_recorder:") {
		t.Errorf("flight_recorder block should always be present")
	}

	// With a key: signing_key_path is emitted and check still passes.
	keyPath := filepath.Join(dir, "signing.key")
	cfg.SigningKeyPath = keyPath
	if err := cfg.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig with key: %v", err)
	}
	data, _ = os.ReadFile(cfg.ConfigFile)
	if !strings.Contains(string(data), "signing_key_path: \""+keyPath+"\"") {
		t.Errorf("signing_key_path not emitted\n%s", data)
	}
	if bin, err := exec.LookPath("pipelock"); err == nil {
		out, err := exec.Command(bin, "check", "--config", cfg.ConfigFile).CombinedOutput()
		if err != nil {
			t.Fatalf("pipelock check rejected signed config: %v\n%s", err, out)
		}
	}
}

// TestWriteConfigProvisionsDefaultKey verifies that the default config emits a
// signing_key_path and that WriteConfig auto-generates the key file, so the
// evidence leg is active out of the box (guards issue #10 bug #3: no key meant
// Pipelock wrote no evidence at all).
func TestWriteConfigProvisionsDefaultKey(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig(dir)
	if cfg.SigningKeyPath == "" {
		t.Fatal("default config should provision a signing key path")
	}
	if err := cfg.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	if _, err := os.Stat(cfg.SigningKeyPath); err != nil {
		t.Fatalf("signing key not generated at %s: %v", cfg.SigningKeyPath, err)
	}
	data, _ := os.ReadFile(cfg.ConfigFile)
	if !strings.Contains(string(data), "signing_key_path: \""+cfg.SigningKeyPath+"\"") {
		t.Errorf("config missing default signing_key_path\n%s", data)
	}
	if bin, err := exec.LookPath("pipelock"); err == nil {
		out, err := exec.Command(bin, "check", "--config", cfg.ConfigFile).CombinedOutput()
		if err != nil {
			t.Fatalf("pipelock check rejected default signed config: %v\n%s", err, out)
		}
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
