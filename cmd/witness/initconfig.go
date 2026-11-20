package main

import (
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
)

// saveConfigIfMissing writes cfg only when no config file exists yet (a first
// install, where Load returned defaults). init never changes the config, so
// rewriting an existing one gains nothing and does harm: a hardened install
// keeps config.json root-owned and read-only to the witness (the daemon must
// not rewrite its own policy), and a rewrite would also bake environment
// overrides (SBH_*, FARM_EVENTS_PATH) into the file.
func saveConfigIfMissing(cfg *config.Config, path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return cfg.Save(path)
}
