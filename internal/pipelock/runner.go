// Package pipelock manages the Pipelock subprocess and its audit log.
//
// Witness starts Pipelock in the background using an audit-mode config,
// then tails Pipelock's NDJSON audit log and forwards every event into
// the witness encrypted log.  Pipelock runs as a transparent proxy; the
// agent is configured to route traffic through it via HTTPS_PROXY /
// HTTP_PROXY environment variables.
package pipelock

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

const configTemplate = `# SGAIL Labs Harborlight Firewall — generated Pipelock config (audit mode)
# Do not edit manually; regenerated on every 'witness init'.

proxy:
  listen: "127.0.0.1:{{.ProxyPort}}"
  mode: forward

audit:
  enabled: true
  format: json
  output: "{{.AuditLog}}"
  max_size_mb: 256
  max_backups: 4

policy:
  default: allow    # audit-only — witness handles alerting, not Pipelock

dlp:
  enabled: true

response_scan:
  enabled: true

behavioral:
  enabled: true

mcp:
  enabled: true
  scan_requests: true
  scan_responses: true
`

// Config holds runtime paths for a Pipelock instance.
type Config struct {
	ConfigFile string
	AuditLog   string
	ProxyPort  int
	BinPath    string
}

// DefaultConfig returns sensible defaults relative to primaryDir.
func DefaultConfig(primaryDir string) *Config {
	return &Config{
		ConfigFile: filepath.Join(primaryDir, "pipelock.yaml"),
		AuditLog:   filepath.Join(primaryDir, "pipelock-audit.log"),
		ProxyPort:  8889,
		BinPath:    "pipelock",
	}
}

// WriteConfig generates and writes the Pipelock YAML config.
func (c *Config) WriteConfig() error {
	if err := os.MkdirAll(filepath.Dir(c.ConfigFile), 0700); err != nil {
		return err
	}
	tmpl, err := template.New("cfg").Parse(configTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]interface{}{
		"ProxyPort": c.ProxyPort,
		"AuditLog":  c.AuditLog,
	}); err != nil {
		return err
	}
	return os.WriteFile(c.ConfigFile, buf.Bytes(), 0600)
}

// Runner manages a Pipelock subprocess.
type Runner struct {
	cfg  *Config
	cmd  *exec.Cmd
	done chan struct{}
}

// NewRunner creates a Runner for the given config.
func NewRunner(cfg *Config) *Runner {
	return &Runner{cfg: cfg, done: make(chan struct{})}
}

// Start launches Pipelock as a background subprocess.
// Returns an error if the binary is not found or fails to start.
func (r *Runner) Start() error {
	bin, err := resolveBin(r.cfg.BinPath)
	if err != nil {
		return fmt.Errorf("pipelock binary not found (%s): %w", r.cfg.BinPath, err)
	}

	// Touch the audit log so the tailer can open it before any events arrive.
	_ = os.MkdirAll(filepath.Dir(r.cfg.AuditLog), 0700)
	if f, err := os.OpenFile(r.cfg.AuditLog, os.O_CREATE|os.O_APPEND, 0600); err == nil {
		_ = f.Close()
	}

	r.cmd = exec.Command(bin, "run", "--config", r.cfg.ConfigFile)
	r.cmd.Stdout = nil
	r.cmd.Stderr = nil

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("start pipelock: %w", err)
	}

	go func() {
		_ = r.cmd.Wait()
		close(r.done)
	}()
	return nil
}

// Stop sends SIGTERM to Pipelock and waits for it to exit.
func (r *Runner) Stop() {
	if r.cmd != nil && r.cmd.Process != nil {
		_ = r.cmd.Process.Signal(os.Interrupt)
		<-r.done
	}
}

// ProxyAddr returns the HTTP proxy address for use in HTTPS_PROXY / HTTP_PROXY.
func (r *Runner) ProxyAddr() string {
	return fmt.Sprintf("http://127.0.0.1:%d", r.cfg.ProxyPort)
}

// AuditLogPath returns the path to Pipelock's audit log.
func (r *Runner) AuditLogPath() string {
	return r.cfg.AuditLog
}

// AuditLogPath returns the audit log path directly from Config.
func (c *Config) AuditLogPath() string {
	return c.AuditLog
}

func resolveBin(name string) (string, error) {
	// Accept absolute paths directly.
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err != nil {
			return "", err
		}
		return name, nil
	}
	// Check standard install locations.
	candidates := []string{
		"/usr/local/bin/" + name,
		"/usr/bin/" + name,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// Fall back to PATH.
	return exec.LookPath(strings.TrimPrefix(name, "./"))
}
