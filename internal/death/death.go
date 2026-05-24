// Package death implements the death broadcast.
//
// When the witness daemon is terminated — by signal, storage anomaly, or
// watchdog detection of unexpected exit — it writes a timestamped snapshot
// of the log and genesis to the primary directory and, if configured, pushes
// to the remote SGAIL server. Both writes happen in parallel goroutines with
// a hard deadline.
//
// The three-tier replication model from v1 is removed. Tamper-evidence is now
// provided by the Merkle log and signed tree head rather than redundant copies.
// Peer gossip (Phase 4) will provide the distributed redundancy.
package death

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/sgail"
)

const broadcastDeadline = 8 * time.Second

// Broadcaster fires the log to all configured destinations on death.
type Broadcaster struct {
	primaryDir  string
	machineID   string
	sgailClient *sgail.Client // nil if SGAIL not configured
}

// New creates a Broadcaster.
// sgailClient may be nil if remote sync is not opted in.
func New(primaryDir, machineID string, sgailClient *sgail.Client) *Broadcaster {
	return &Broadcaster{
		primaryDir:  primaryDir,
		machineID:   machineID,
		sgailClient: sgailClient,
	}
}

// Fire writes timestamped death snapshots to the primary directory and,
// if configured, pushes to the remote SGAIL server.
// It blocks until all writes complete or broadcastDeadline is reached.
func (b *Broadcaster) Fire(logData, genesisData []byte) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	logName := "death_" + ts + "_witness.log"
	genesisName := "death_" + ts + "_genesis.enc"

	var wg sync.WaitGroup

	// 1. Write death snapshots to the primary directory.
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeFile(filepath.Join(b.primaryDir, logName), logData)
		writeFile(filepath.Join(b.primaryDir, genesisName), genesisData)
	}()

	// 2. Remote SGAIL push (if opted in).
	if b.sgailClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.sgailClient.Death(b.machineID, logData, broadcastDeadline-time.Second)
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
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
