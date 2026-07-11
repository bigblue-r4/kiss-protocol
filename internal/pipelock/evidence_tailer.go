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
	dir          string
	events       chan AuditEvent
	stop         chan struct{}
	pollEvery    time.Duration
	drainTimeout time.Duration

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
		// On Stop each follower reads to EOF so pipelock's final receipt (e.g.
		// the shutdown checkpoint) is captured. The deadline bounds that drain.
		drainTimeout: 2 * time.Second,
		followed:     make(map[string]struct{}),
	}
}

// Run discovers evidence files and follows each one. Blocks until Stop.
func (e *EvidenceTailer) Run() {
	firstScan := true
	for {
		// Files present at boot are followed from the end (skip history); files
		// that appear later are read in full from the start.
		e.scan(!firstScan)
		firstScan = false

		select {
		case <-e.stop:
			// Final scan: pick up any evidence file pipelock created just before
			// exiting that the poll loop hadn't discovered yet, and read it from
			// the start so its shutdown records are drained too.
			e.scan(true)
			e.wg.Wait()
			return
		case <-time.After(e.pollEvery):
		}
	}
}

// scan discovers not-yet-followed evidence files and launches a follower for
// each. fromStart controls whether a newly discovered file is read in full or
// only tailed from its current end.
func (e *EvidenceTailer) scan(fromStart bool) {
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
		e.wg.Add(1)
		go func(p string, fs bool) {
			defer e.wg.Done()
			e.follow(p, fs)
		}(path, fromStart)
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

	stopped := false
	var drainDeadline time.Time
	for {
		// Once Stop is signalled, keep reading what is already on disk until EOF
		// so the final receipts are drained rather than dropped mid-file.
		if !stopped {
			select {
			case <-e.stop:
				stopped = true
				drainDeadline = time.Now().Add(e.drainTimeout)
			default:
			}
		}

		chunk, err := reader.ReadBytes('\n')
		pending = append(pending, chunk...)
		if len(pending) > 0 && pending[len(pending)-1] == '\n' {
			line := trimNewline(string(pending))
			pending = pending[:0]
			if line != "" {
				var evt AuditEvent
				if json.Unmarshal([]byte(line), &evt) == nil {
					if stopped {
						// Draining: deliver to the still-alive consumer, bounded
						// by the drain deadline so a dead consumer can't hang us.
						select {
						case e.events <- evt:
						case <-time.After(time.Until(drainDeadline)):
							return
						}
					} else {
						select {
						case e.events <- evt:
						case <-e.stop:
							stopped = true
							drainDeadline = time.Now().Add(e.drainTimeout)
						}
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				if stopped {
					return // drained to EOF after stop
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return
		}

		if stopped && time.Now().After(drainDeadline) {
			return // safety bound — don't drain forever if writes keep coming
		}
	}
}

// Stop signals the tailer to exit and waits for its followers to drain.
func (e *EvidenceTailer) Stop() {
	close(e.stop)
	e.wg.Wait()
}
