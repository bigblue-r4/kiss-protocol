package backup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// tertiarySecret is the HMAC key used to derive the tertiary backup path.
// This value is public (source is open). The path is still machine-specific
// because the machine ID is the HMAC input — an attacker needs the machine ID
// to compute the path, not just the source.
const tertiarySecret = "w1tn3ss-t3rt14ry-s3cr3t-2026"

// TertiaryDir derives the tertiary backup directory from the machine ID.
// The returned path is NEVER stored in any configuration file.
// Preferred location: /var/cache/.<derived> (root installs).
// Fallback: os.TempDir()/.<derived> (non-persistent but available).
func TertiaryDir(machineID string) string {
	digest := deriveHex(machineID)[:16]
	preferred := "/var/cache/." + digest
	if canWrite(preferred) {
		return preferred
	}
	return filepath.Join(os.TempDir(), "."+digest)
}

// WriteTertiary atomically writes data to filename in the tertiary backup dir.
func WriteTertiary(machineID, filename string, data []byte) error {
	dir := TertiaryDir(machineID)
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

// AppendTertiary appends data to filename in the tertiary backup dir.
func AppendTertiary(machineID, filename string, data []byte) error {
	dir := TertiaryDir(machineID)
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

func deriveHex(machineID string) string {
	mac := hmac.New(sha256.New, []byte(tertiarySecret))
	mac.Write([]byte(machineID))
	return hex.EncodeToString(mac.Sum(nil))
}
