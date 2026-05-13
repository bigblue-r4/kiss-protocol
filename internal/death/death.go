// Package death implements the death broadcast.
//
// When the witness process detects it is being terminated — signal, network cut,
// or storage anomaly — it fires the complete log simultaneously to all three
// backup locations and the remote SGAIL server. All four writes happen in
// parallel goroutines; we wait up to a hard deadline for completion.
package death

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/sgail"
)

const broadcastDeadline = 8 * time.Second

// Broadcaster fires the complete log to all destinations simultaneously.
type Broadcaster struct {
	primaryDir   string
	secondaryDir string
	tertiaryDir  string
	machineID    string
	sgailClient  *sgail.Client // nil if SGAIL not configured
}

// New creates a Broadcaster.
// sgailClient may be nil if remote sync is not opted in.
func New(primaryDir, secondaryDir, tertiaryDir, machineID string, sgailClient *sgail.Client) *Broadcaster {
	return &Broadcaster{
		primaryDir:   primaryDir,
		secondaryDir: secondaryDir,
		tertiaryDir:  tertiaryDir,
		machineID:    machineID,
		sgailClient:  sgailClient,
	}
}

// Fire sends logData and genesisData to all destinations simultaneously.
// It blocks until all writes complete or broadcastDeadline is reached.
func (b *Broadcaster) Fire(logData, genesisData []byte) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	logName := "death_" + ts + "_witness.log"
	genesisName := "death_" + ts + "_genesis.enc"

	var wg sync.WaitGroup

	// 1. Secondary backup
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeFile(filepath.Join(b.secondaryDir, logName), logData)
		writeFile(filepath.Join(b.secondaryDir, genesisName), genesisData)
	}()

	// 2. Tertiary backup
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeFile(filepath.Join(b.tertiaryDir, logName), logData)
		writeFile(filepath.Join(b.tertiaryDir, genesisName), genesisData)
	}()

	// 3. Primary backup (overwrite the live files so they're consistent)
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeFile(filepath.Join(b.primaryDir, logName), logData)
	}()

	// 4. Remote SGAIL (if opted in)
	if b.sgailClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.sgailClient.Death(b.machineID, logData, broadcastDeadline-1*time.Second)
		}()
	}

	// Wait with a hard deadline.
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
