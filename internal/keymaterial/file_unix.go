//go:build linux || darwin

// Package keymaterial provides explicitly provisioned secret material for a
// future versioned log format. It does not change legacy log key derivation.
package keymaterial

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/unix"
)

const secretSize = 32

// Keys separates encryption and authentication uses of the same data secret.
// These keys must only be used with an explicitly versioned new format, not as
// a replacement for the machine-derived key when opening existing logs.
type Keys struct {
	Encryption [32]byte
	MAC        [32]byte
}

// CreateFile creates a random 256-bit secret without replacing an existing
// file (including a symlink). The parent must already exist and must be trusted
// and protected from untrusted writes. Success includes file and directory
// synchronization. An error can leave a newly created file; inspect it rather
// than retrying with overwrite semantics. This function never generates keys
// as a side effect of loading a missing or damaged file.
func CreateFile(path string) error {
	var secret [secretSize]byte
	defer clear(secret[:])
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate data secret: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create data secret: %w", err)
	}
	if _, err := f.Write(secret[:]); err != nil {
		_ = f.Close()
		return fmt.Errorf("write data secret: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync data secret: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close data secret: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open secret directory after creation: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync secret directory after creation: %w", err)
	}
	return nil
}

// LoadFile loads exactly 32 raw secret bytes from a regular, owner-only file
// owned by the effective user or root. The final path component cannot be a
// symlink; trusted parent directories remain a deployment requirement.
// No secret is created, repaired, or replaced, and there is no legacy fallback.
// A protected secret file does not resist root or process-memory compromise.
func LoadFile(path string) (Keys, error) {
	// Nonblocking open prevents a substituted FIFO from hanging verification.
	// Validate the opened descriptor, not a separate path-based stat result.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return Keys{}, fmt.Errorf("open data secret: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Keys{}, fmt.Errorf("stat data secret: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() != secretSize {
		return Keys{}, fmt.Errorf("data secret must be a regular file of exactly %d bytes", secretSize)
	}
	if st.Mode().Perm()&0077 != 0 {
		return Keys{}, fmt.Errorf("data secret must have owner-only permissions")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return Keys{}, fmt.Errorf("stat data secret owner: %w", err)
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return Keys{}, fmt.Errorf("data secret must be owned by the effective user or root")
	}
	var secret [secretSize]byte
	defer clear(secret[:])
	if _, err := io.ReadFull(f, secret[:]); err != nil {
		return Keys{}, fmt.Errorf("read data secret: %w", err)
	}
	var keys Keys
	if err := derive(secret[:], "witness-secret-v1/encryption", keys.Encryption[:]); err != nil {
		return Keys{}, err
	}
	if err := derive(secret[:], "witness-secret-v1/tree-head-mac", keys.MAC[:]); err != nil {
		return Keys{}, err
	}
	return keys, nil
}

func derive(secret []byte, purpose string, dst []byte) error {
	_, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(purpose)), dst)
	if err != nil {
		return fmt.Errorf("derive data key: %w", err)
	}
	return nil
}
