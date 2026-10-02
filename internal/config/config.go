// Package config manages kiss-core configuration.
//
// v3 split: the core config covers only local witness concerns. All peer mesh
// and enforcement settings live in the enforcer's own config (~/.enforcer/).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Config is the kiss-core witness configuration.
// It intentionally has no network-facing fields — the core is network-silent
// except for transparency mirror pushes (operator opt-in).
type Config struct {
	PrimaryDir       string `json:"primary_dir"`
	DriftIntervalSec int    `json:"drift_interval_sec"`
	MirrorURL        string `json:"mirror_url,omitempty"` // transparency mirror endpoint
	// SBHAuditPath is the path to the split-brain-harness forge audit JSONL log.
	// When set (or overridden by SBH_AUDIT_PATH env var), witness tails the log
	// and records every forge run in the encrypted Merkle witness store.
	SBHAuditPath string `json:"sbh_audit_path,omitempty"`
	// SBHDecisionLogPath is split-brain-harness's per-decision log (SBH_DECISION_LOG):
	// one line per request `sbh serve` analysed. Witness records every verdict.
	SBHDecisionLogPath string `json:"sbh_decision_log_path,omitempty"`
	// SBHSessionLogPath is split-brain-harness's session escalation log (SBH_SESSION_LOG).
	SBHSessionLogPath string `json:"sbh_session_log_path,omitempty"`
	// FarmEventsPath is a farm-automation NDJSON feed (docs/farm-events.md):
	// readings, alarms, setting changes, access and health records.
	FarmEventsPath string `json:"farm_events_path,omitempty"`
	// FarmSilenceMinutes flags a farm source that stops reporting for this long
	// (0 = default of 10).
	FarmSilenceMinutes int `json:"farm_silence_minutes,omitempty"`
}

// FarmSilence is the configured silence threshold, defaulting to 10 minutes.
func (c *Config) FarmSilence() time.Duration {
	if c.FarmSilenceMinutes > 0 {
		return time.Duration(c.FarmSilenceMinutes) * time.Minute
	}
	return 10 * time.Minute
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		PrimaryDir:       filepath.Join(home, ".witness", "primary"),
		DriftIntervalSec: 30,
	}
}

// Load reads the config file at path. If the file does not exist, returns DefaultConfig.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	// Allow SBH audit path override via environment
	if p := os.Getenv("SBH_AUDIT_PATH"); p != "" {
		cfg.SBHAuditPath = p
	}
	if p := os.Getenv("SBH_DECISION_LOG"); p != "" {
		cfg.SBHDecisionLogPath = p
	}
	if p := os.Getenv("SBH_SESSION_LOG"); p != "" {
		cfg.SBHSessionLogPath = p
	}
	if p := os.Getenv("FARM_EVENTS_PATH"); p != "" {
		cfg.FarmEventsPath = p
	}
	return cfg, nil
}

// Save writes the config to path, creating parent directories as needed.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Path returns the default config file location.
func Path() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witness", "config.json")
}
