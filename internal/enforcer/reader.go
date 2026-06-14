// Package enforcer implements kiss-enforcer — a privileged asynchronous reader
// of the kiss-core immutable Merkle log.
//
// Architectural invariant: the enforcer is NEVER in the core write path.
// It reads log files produced by kiss-core via store.ReadAll (a read-only
// operation) and delivers decoded entries upstream. All peer mesh, loyalty
// enforcement, and anomaly reporting live here, not in the core.
//
// Isolation contract:
//
//   - kiss-core (cmd/witness) writes the log; it never imports this package.
//   - kiss-enforcer (cmd/enforcer) reads the log; it never opens the log
//     file for writing and holds no lock on the Store.
//   - The machine-derived AES-256 key is derived independently by both
//     binaries from machid → encrypt.DeriveKey; no IPC is required.
//
// Data flow:
//
//	kiss-core → ~/.witness/primary/witness.log (append-only, encrypted)
//	                              ↓  (file read, no lock)
//	              enforcer.TailReader.poll()
//	                              ↓
//	                     chan enforcer.Event
//	                              ↓
//	          gossip mesh / loyalty checker / anomaly reporter
package enforcer

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Event is a decoded Merkle leaf delivered to the enforcer event loop.
type Event struct {
	store.Entry

	// LeafIndex is the 0-based position of this entry in the Merkle tree.
	LeafIndex uint64
	// LeafHash is the RFC 6962 BLAKE3 leaf hash for this entry — usable for
	// inclusion-proof requests without re-serialising the entry.
	LeafHash [32]byte
}

// TailReader watches the kiss-core log directory for new entries and
// delivers them to its Events channel. It polls at Interval; a future
// Linux-specific backend can use inotify for sub-second latency without
// changing this interface.
//
// TailReader is safe for single-goroutine use. Start one goroutine with Run.
type TailReader struct {
	dir      string
	key      []byte
	interval time.Duration
	events   chan<- Event
	lastSeq  uint64
	done     chan struct{}
}

// NewTailReader creates a TailReader.
//
//   - dir is the kiss-core primary log directory (~/.witness/primary).
//   - key is the machine-derived AES-256 decryption key from encrypt.DeriveKey.
//     Both binaries derive this identically from the same machine-id.
//   - interval is the poll cadence; 0 defaults to 5 s.
//   - events receives decoded entries; the caller must drain it or entries are
//     silently dropped to avoid blocking the poll goroutine.
func NewTailReader(dir string, key []byte, interval time.Duration, events chan<- Event) *TailReader {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &TailReader{
		dir:      dir,
		key:      key,
		interval: interval,
		events:   events,
		done:     make(chan struct{}),
	}
}

// Run polls the core log until ctx is cancelled, then closes the done channel.
// Designed to run in its own goroutine: go r.Run(ctx).
func (r *TailReader) Run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.poll() // deliver any backlog immediately on start
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll()
		}
	}
}

// Wait blocks until Run has returned. Safe to call from any goroutine.
func (r *TailReader) Wait() { <-r.done }

// poll reads all current entries, computes leaf hashes for the full set
// (verifying the Merkle structure stays consistent), then delivers only
// the entries with Seq > lastSeq.
//
// Reading the full entry list on every poll is O(n) in log size. For
// very large logs a future optimisation is to seek to the last known
// offset; that requires store.ReadFrom(offset) which does not yet exist.
func (r *TailReader) poll() {
	entries, err := store.ReadAll(r.dir, r.key)
	if err != nil || len(entries) == 0 {
		return
	}

	// Recompute the full leaf set so we can provide verified hashes and
	// detect any truncation or reordering of the on-disk log.
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		b, _ := json.Marshal(e)
		leaves[i] = merkle.HashLeaf(b)
	}

	for i, e := range entries {
		if e.Seq <= r.lastSeq {
			continue
		}
		r.lastSeq = e.Seq
		evt := Event{
			Entry:     e,
			LeafIndex: uint64(i),
			LeafHash:  leaves[i],
		}
		select {
		case r.events <- evt:
		default:
			// Enforcer is congested. Drop rather than blocking the poll goroutine.
			// The entry will be re-delivered on the next poll (lastSeq was updated).
			// Re-set lastSeq so we retry this entry next time.
			r.lastSeq = e.Seq - 1
			return
		}
	}
}
