// Package pipelock manages the Pipelock subprocess and its audit log.
//
// Witness starts Pipelock in the background using an audit-mode config,
// then tails Pipelock's NDJSON audit log and forwards every event into
// the witness encrypted log.  Pipelock runs as a forward proxy; the
// agent is configured to route traffic through it via HTTPS_PROXY /
// HTTP_PROXY environment variables.
package pipelock

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"
)

// configTemplate is a Pipelock v3 audit-mode config.
//
// The schema is verified against github.com/luckyPipewrench/pipelock v3
// (see docs/configuration.md upstream). Earlier versions of this file used
// invented top-level keys (proxy/audit/policy/response_scan/behavioral/mcp)
// that Pipelock rejects at startup with unknown-field errors, which silently
// disabled the network audit leg — see issue #10, reported by the Pipelock
// author. Keep every key below in sync with the upstream config reference.
const configTemplate = `# SGAIL Labs Harborlight Firewall — generated Pipelock config (audit mode)
# Do not edit manually; regenerated on every 'witness init'.
# Schema: Pipelock v3 (github.com/luckyPipewrench/pipelock).
version: 1
mode: audit          # detect and log, never block — witness handles alerting
enforce: false       # belt-and-suspenders with mode: audit

fetch_proxy:
  listen: "127.0.0.1:{{.ProxyPort}}"

forward_proxy:
  enabled: true
  max_tunnel_seconds: 300
  idle_timeout_seconds: 120

logging:
  format: json
  output: file
  file: "{{.AuditLog}}"
  include_allowed: true
  include_blocked: true

dlp:
  scan_env: true

response_scanning:
  enabled: true
  action: warn

mcp_input_scanning:
  enabled: true
  action: warn
  on_parse_error: forward

mcp_tool_scanning:
  enabled: true
  action: warn

session_profiling:
  enabled: true

behavioral_baseline:
  enabled: true
  profile_dir: "{{.ProfileDir}}"
  deviation_action: warn

# Hash-chained, tamper-evident evidence log. The witness bridge tails this
# directory and folds every signed decision receipt into the witness Merkle log
# alongside the raw audit events. A signing key is required: Pipelock's recorder
# is inert without flight_recorder.signing_key_path and writes nothing, so
# witness provisions one by default (see EnsureSigningKey).
flight_recorder:
  enabled: true
  dir: "{{.EvidenceDir}}"
{{- if .SigningKeyPath}}
  signing_key_path: "{{.SigningKeyPath}}"
  sign_checkpoints: true
{{- end}}
`

// Config holds runtime paths for a Pipelock instance.
type Config struct {
	ConfigFile  string
	AuditLog    string
	ProxyPort   int
	BinPath     string
	ProfileDir  string
	EvidenceDir string
	// SigningKeyPath is the Ed25519 key Pipelock uses to sign flight_recorder
	// decision receipts. It is required for any evidence to be produced at all:
	// without it Pipelock's recorder is inert and writes nothing. WriteConfig
	// auto-generates a Pipelock-format key here if the file is absent, so leave
	// it set (DefaultConfig points it under primaryDir). Set it empty only to
	// deliberately disable the evidence leg.
	SigningKeyPath string
}

// DefaultConfig returns sensible defaults relative to primaryDir.
func DefaultConfig(primaryDir string) *Config {
	return &Config{
		ConfigFile:  filepath.Join(primaryDir, "pipelock.yaml"),
		AuditLog:    filepath.Join(primaryDir, "pipelock-audit.log"),
		ProxyPort:   8889,
		BinPath:     "pipelock",
		ProfileDir:  filepath.Join(primaryDir, "pipelock-profiles"),
		EvidenceDir: filepath.Join(primaryDir, "pipelock-evidence"),
		// A signing key is required for evidence to be emitted at all, so witness
		// provisions one by default under primaryDir (WriteConfig generates it if
		// missing). PIPELOCK_SIGNING_KEY overrides the location to reuse a key
		// provisioned elsewhere.
		SigningKeyPath: defaultSigningKeyPath(primaryDir),
	}
}

// defaultSigningKeyPath returns the PIPELOCK_SIGNING_KEY override if set,
// otherwise a witness-managed key path under primaryDir.
func defaultSigningKeyPath(primaryDir string) string {
	if p := os.Getenv("PIPELOCK_SIGNING_KEY"); p != "" {
		return p
	}
	return filepath.Join(primaryDir, "pipelock-keys", "id_ed25519")
}

// WriteConfig generates and writes the Pipelock YAML config.
func (c *Config) WriteConfig() error {
	if err := os.MkdirAll(filepath.Dir(c.ConfigFile), 0700); err != nil {
		return err
	}
	// Pipelock requires profile_dir / flight_recorder.dir to exist; create
	// them up front so the subprocess does not fail closed at startup.
	for _, dir := range []string{c.ProfileDir, c.EvidenceDir} {
		if dir != "" {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
		}
	}
	// Provision the flight_recorder signing key if it does not exist yet.
	// Without it Pipelock's recorder is inert and no evidence is written, so the
	// key must be in place before the config that references it is used.
	if _, err := EnsureSigningKey(c.SigningKeyPath); err != nil {
		return err
	}
	tmpl, err := template.New("cfg").Parse(configTemplate)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]interface{}{
		"ProxyPort":      c.ProxyPort,
		"AuditLog":       c.AuditLog,
		"ProfileDir":     c.ProfileDir,
		"EvidenceDir":    c.EvidenceDir,
		"SigningKeyPath": c.SigningKeyPath,
	}); err != nil {
		return err
	}
	return os.WriteFile(c.ConfigFile, buf.Bytes(), 0600)
}

// Runner manages a Pipelock subprocess.
type Runner struct {
	cfg    *Config
	cmd    *exec.Cmd
	done   chan struct{}
	stderr *lineSink
}

// NewRunner creates a Runner for the given config.
func NewRunner(cfg *Config) *Runner {
	return &Runner{cfg: cfg, done: make(chan struct{}), stderr: &lineSink{}}
}

// SetStderrSink registers a callback invoked once per line Pipelock writes to
// stderr. The bridge uses it to forward Pipelock's own diagnostics into the
// witness log, so a config failure is visible instead of silent.
func (r *Runner) SetStderrSink(fn func(line string)) { r.stderr.setSink(fn) }

// Start launches Pipelock as a background subprocess and waits until its proxy
// port is accepting connections. Returns an error if the binary is not found,
// the process fails to start, or the proxy does not come up (e.g. a rejected
// config) — in which case the subprocess is torn down before returning.
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
	r.cmd.Stderr = r.stderr

	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("start pipelock: %w", err)
	}

	go func() {
		_ = r.cmd.Wait()
		close(r.done)
	}()

	// A bad config makes Pipelock exit at startup, or the proxy port never
	// opens. Either way we must not report success while nothing is listening.
	if err := r.waitReady(3 * time.Second); err != nil {
		r.Stop()
		return err
	}
	return nil
}

// waitReady blocks until the proxy port accepts a connection, the subprocess
// exits, or timeout elapses. Returns nil only when the port is live.
func (r *Runner) waitReady(timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", r.cfg.ProxyPort)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-r.done:
			return fmt.Errorf("pipelock exited during startup (check config %s): %s",
				r.cfg.ConfigFile, r.stderr.tail())
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("pipelock proxy did not come up on %s within %s: %s",
		addr, timeout, r.stderr.tail())
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

const maxStderrLines = 20

// lineSink is an io.Writer that splits incoming bytes into lines, retains the
// last maxStderrLines for error reporting, and forwards each line to an
// optional sink. It is safe for concurrent use: the subprocess writes to it
// while Start reads its tail.
type lineSink struct {
	mu    sync.Mutex
	pend  []byte
	lines []string
	sink  func(string)
}

func (l *lineSink) setSink(fn func(string)) {
	l.mu.Lock()
	l.sink = fn
	l.mu.Unlock()
}

func (l *lineSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.pend = append(l.pend, p...)
	var emit []string
	for {
		i := bytes.IndexByte(l.pend, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(l.pend[:i]), "\r")
		l.pend = l.pend[i+1:]
		if line == "" {
			continue
		}
		l.lines = append(l.lines, line)
		if len(l.lines) > maxStderrLines {
			l.lines = l.lines[len(l.lines)-maxStderrLines:]
		}
		emit = append(emit, line)
	}
	sink := l.sink
	l.mu.Unlock()

	// Invoke the sink outside the lock so a slow consumer cannot stall the
	// subprocess's stderr pipe.
	if sink != nil {
		for _, line := range emit {
			sink(line)
		}
	}
	return len(p), nil
}

// tail returns the retained stderr lines joined for inclusion in an error.
func (l *lineSink) tail() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return "(no stderr output)"
	}
	return strings.Join(l.lines, " | ")
}
