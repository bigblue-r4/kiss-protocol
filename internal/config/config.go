// Package config manages witness configuration.
// NOTE: Secondary and tertiary backup paths are intentionally NOT stored here.
// Secondary is fixed at a hidden system path.
// Tertiary is derived at runtime from machine identity — it never appears in any file.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config is the witness client configuration.
// SGAILToken may also be provided via the WITNESS_SGAIL_TOKEN environment variable.
type Config struct {
	PrimaryDir       string `json:"primary_dir"`
	SGAILEnabled     bool   `json:"sgail_enabled"`
	SGAILEndpoint    string `json:"sgail_endpoint,omitempty"`
	SGAILToken       string `json:"sgail_token,omitempty"`
	SyncIntervalSec  int    `json:"sync_interval_sec"`
	DriftIntervalSec int    `json:"drift_interval_sec"`
	GossipListenAddr string `json:"gossip_listen_addr,omitempty"` // UDP addr; default ":9273"
	MirrorURL        string `json:"mirror_url,omitempty"`         // transparency mirror endpoint
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		PrimaryDir:       filepath.Join(home, ".witness", "primary"),
		SGAILEnabled:     false,
		SyncIntervalSec:  300, // 5 minutes
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
	// Allow token override via environment
	if t := os.Getenv("WITNESS_SGAIL_TOKEN"); t != "" {
		cfg.SGAILToken = t
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
