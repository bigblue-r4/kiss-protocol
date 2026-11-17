// Package hashutil holds the one-shot hash helpers shared across the witness.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the lowercase hex SHA-256 of data: the same string as
// hex.EncodeToString of sha256.Sum256(data).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
