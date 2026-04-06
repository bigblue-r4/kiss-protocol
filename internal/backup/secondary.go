// Package backup manages secondary and tertiary encrypted backup locations.
package backup

import (
	"os"
	"path/filepath"
)

// secondaryBase is the preferred secondary backup location.
// It is outside the normal user workspace so agents running in user-space
// cannot see or modify it. Falls back to a hidden home-dir location if
// the system path is not writable (e.g., non-root installation).
const secondaryBase = "/var/lib/.watcher_state"

// SecondaryDir returns the secondary backup directory, creating it if needed.
// Tries the system path first; falls back to ~/.witness/.secondary.
func SecondaryDir() string {
	if canWrite(secondaryBase) {
		return secondaryBase
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witness", ".secondary")
}

// WriteSecondary atomically writes data to filename in the secondary backup dir.
func WriteSecondary(filename string, data []byte) error {
	dir := SecondaryDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, filename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AppendSecondary appends data to filename in the secondary backup dir.
func AppendSecondary(filename string, data []byte) error {
	dir := SecondaryDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, filename), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func canWrite(path string) bool {
	if err := os.MkdirAll(path, 0700); err != nil {
		return false
	}
	probe := filepath.Join(path, ".probe")
	if err := os.WriteFile(probe, []byte{0}, 0600); err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}
