package pipelock

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EvidenceTailer watches a Pipelock flight_recorder evidence directory and
// forwards every new JSONL entry from its evidence-*.jsonl files into a
// channel, so Pipelock's signed, hash-chained decision receipts can be folded
// into the witness Merkle log alongside the raw audit events.
//
// Pipelock rotates evidence by creating new files (evidence-<session>-<seq>.jsonl)
// rather than truncating in place, so the tailer discovers files by polling the
// directory. Files that already exist when the tailer starts are followed from
// their current end — historical evidence is not re-ingested on restart, which
// matches the single-file audit Tailer and avoids duplicate Merkle leaves.
// Files that appear afterwards are read from the beginning.
type EvidenceTailer struct {
	dir       string
	events    chan AuditEvent
	stop      chan struct{}
	pollEvery time.Duration

	mu       sync.Mutex
	followed map[string]struct{}
	wg       sync.WaitGroup
}

// NewEvidenceTailer creates a tailer for the given flight_recorder directory.
// events receives parsed evidence entries.
func NewEvidenceTailer(dir string, events chan AuditEvent) *EvidenceTailer {
	return &EvidenceTailer{
		dir:       dir,
		events:    events,
		stop:      make(chan struct{}),
		pollEvery: time.Second,
		followed:  make(map[string]struct{}),
	}
}

// Run discovers evidence files and follows each one. Blocks until Stop.
func (e *EvidenceTailer) Run() {
	firstScan := true
	for {
		matches, _ := filepath.Glob(filepath.Join(e.dir, "evidence-*.jsonl"))
		for _, path := range matches {
			e.mu.Lock()
			_, seen := e.followed[path]
			if !seen {
				e.followed[path] = struct{}{}
			}
			e.mu.Unlock()
			if seen {
				continue
			}
			// Files present at boot are followed from the end (skip history);
			// files that appear later are read in full from the start.
			fromStart := !firstScan
			e.wg.Add(1)
			go func(p string, fs bool) {
				defer e.wg.Done()
				e.follow(p, fs)
			}(path, fromStart)
		}
		firstScan = false

		select {
		case <-e.stop:
			e.wg.Wait()
			return
		case <-time.After(e.pollEvery):
		}
	}
}

// follow tails a single evidence file, buffering partial lines so an entry that
// is still being written is never parsed until its terminating newline arrives.
func (e *EvidenceTailer) follow(path string, fromStart bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if !fromStart {
		_, _ = f.Seek(0, io.SeekEnd)
	}
	reader := bufio.NewReaderSize(f, 64<<10)
	var pending []byte

	for {
		select {
		case <-e.stop:
			return
		default:
		}

		chunk, err := reader.ReadBytes('\n')
		pending = append(pending, chunk...)
		if len(pending) > 0 && pending[len(pending)-1] == '\n' {
			line := trimNewline(string(pending))
			pending = pending[:0]
			if line != "" {
				var evt AuditEvent
				if json.Unmarshal([]byte(line), &evt) == nil {
					select {
					case e.events <- evt:
					case <-e.stop:
						return
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				select {
				case <-e.stop:
					return
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			return
		}
	}
}

// Stop signals the tailer to exit and waits for its followers to drain.
func (e *EvidenceTailer) Stop() {
	close(e.stop)
	e.wg.Wait()
}
