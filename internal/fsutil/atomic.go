// Package fsutil holds small file-system helpers shared across the witness.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data so that a reader sees either the old
// file or the complete new one, never a partial write, and the new contents
// survive a crash once it returns nil.
//
// It writes a uniquely named temporary file in the same directory
// (".<base>.<random>.tmp", created with perm under the process umask, exactly
// as os.WriteFile does), fsyncs it, renames it over path and fsyncs the
// directory. The unique name means concurrent writers never share a temporary
// file, and readers that look for "*.json" or a fixed name never see it.
//
// On an error before the rename, the temporary file is removed and path is
// unchanged. An error from the final directory fsync means path already holds
// the new contents but the rename may not yet be durable.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	tmp := filepath.Join(dir, "."+base+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}
