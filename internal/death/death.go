// Package death implements the death broadcast.
//
// When the witness daemon is terminated — by signal, storage anomaly, or
// watchdog detection of unexpected exit — it writes a timestamped snapshot
// of the log and genesis to the primary directory.
//
// v3 change: SGAIL remote push removed (package deleted). The enforcer
// (cmd/enforcer) handles cross-node death notification via the gossip mesh.
// The core witness never touches the network on death — only local disk.
package death

import (
	"os"
	"path/filepath"
	"time"
)

const broadcastDeadline = 8 * time.Second

// Broadcaster writes death snapshots to the primary log directory.
type Broadcaster struct {
	primaryDir string
	machineID  string
}

// New creates a Broadcaster.
func New(primaryDir, machineID string) *Broadcaster {
	return &Broadcaster{
		primaryDir: primaryDir,
		machineID:  machineID,
	}
}

// Fire writes timestamped death snapshots (log + genesis) to the primary
// directory. It blocks until both writes complete or broadcastDeadline elapses.
// Fire is intentionally local-only; cross-node notification is the enforcer's job.
func (b *Broadcaster) Fire(logData, genesisData []byte) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	logName := "death_" + ts + "_witness.log"
	genesisName := "death_" + ts + "_genesis.enc"

	done := make(chan struct{})
	go func() {
		defer close(done)
		writeFile(filepath.Join(b.primaryDir, logName), logData)
		writeFile(filepath.Join(b.primaryDir, genesisName), genesisData)
	}()

	select {
	case <-done:
	case <-time.After(broadcastDeadline):
	}
}

func writeFile(path string, data []byte) {
	if len(data) == 0 {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, data, 0600)
}
