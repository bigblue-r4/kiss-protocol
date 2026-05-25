// Package migrate provides a one-shot importer from v1 backup tiers to the
// v2 Merkle log.
//
// The v1 log used a SHA-256 linear hash chain (each entry carried a prev_hash
// field). The v2 log uses a Merkle tree. These two integrity models are
// fundamentally different: there is no cryptographic continuity between v1 and
// v2 — only documentary continuity (all events are present, in order, with a
// clearly marked boundary).
//
// The importer reads the v1 log, strips the prev_hash field (ignored by v2
// decoders), and appends each entry into the new Merkle log. A boundary marker
// leaf is appended last so that the seam is visible in any audit.
package migrate

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// ImportResult summarises a completed import.
type ImportResult struct {
	Imported int    // entries successfully imported
	Skipped  int    // entries that could not be decoded
	LogPath  string // source log path
}

// FromV1Log imports all entries from a v1 witness.log at srcDir into dst.
// dst must already be initialised (store.Open must succeed).
// Returns an error if the source log cannot be read or if any write fails.
func FromV1Log(srcDir string, key []byte, dst *store.Store) (*ImportResult, error) {
	srcPath := filepath.Join(srcDir, "witness.log")
	f, err := os.Open(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("v1 log not found at %s", srcPath)
		}
		return nil, fmt.Errorf("open v1 log: %w", err)
	}
	defer f.Close()

	result := &ImportResult{LogPath: srcPath}
	var entries []v1Entry

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			break
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length == 0 || length > 64<<20 {
			break
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(f, sealed); err != nil {
			break
		}
		plain, err := encrypt.Open(sealed, key)
		if err != nil {
			result.Skipped++
			continue
		}
		var e v1Entry
		if err := json.Unmarshal(plain, &e); err != nil {
			result.Skipped++
			continue
		}
		entries = append(entries, e)
	}

	// Write each entry into the v2 store in original order.
	for _, e := range entries {
		data := e.Data
		if err := dst.Append(e.Level, e.Event, e.Source, json.RawMessage(data)); err != nil {
			return result, fmt.Errorf("write entry seq %d: %w", e.Seq, err)
		}
		result.Imported++
	}

	// Append the boundary marker.
	boundary := map[string]interface{}{
		"note":             "v1 import boundary — Merkle continuity begins here",
		"v1_log":           srcPath,
		"entries_imported": result.Imported,
		"entries_skipped":  result.Skipped,
		"imported_at":      time.Now().UTC().Format(time.RFC3339),
	}
	if err := dst.Append("SYSTEM", "v1_import_boundary", "migrate", boundary); err != nil {
		return result, fmt.Errorf("write boundary marker: %w", err)
	}

	return result, nil
}

// v1Entry is the v1 log entry format (with prev_hash, which is ignored in v2).
type v1Entry struct {
	Seq      uint64          `json:"seq"`
	Level    string          `json:"level"`
	Event    string          `json:"event"`
	Source   string          `json:"source"`
	PrevHash string          `json:"prev_hash"` // v1 only, not written to v2
	Data     json.RawMessage `json:"data,omitempty"`
}
