// Package config manages kiss-core configuration.
//
// v3 split: the core config covers only local witness concerns. All peer mesh
// and enforcement settings live in the enforcer's own config (~/.enforcer/).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config is the kiss-core witness configuration.
// It intentionally has no network-facing fields — the core is network-silent
// except for transparency mirror pushes (operator opt-in).
type Config struct {
	PrimaryDir       string `json:"primary_dir"`
	DriftIntervalSec int    `json:"drift_interval_sec"`
	MirrorURL        string `json:"mirror_url,omitempty"` // transparency mirror endpoint
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
