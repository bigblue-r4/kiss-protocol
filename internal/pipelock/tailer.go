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

// AuditEvent is one raw event from Pipelock's NDJSON audit log.
// All fields are preserved; witness stores them as-is in the encrypted log.
type AuditEvent map[string]interface{}

// Level returns the zerolog level field, or "info" if absent.
func (e AuditEvent) Level() string {
	if v, ok := e["level"].(string); ok {
		return v
	}
	return "info"
}

// EventName returns the "event" field, or "pipelock_event" if absent.
func (e AuditEvent) EventName() string {
	if v, ok := e["event"].(string); ok {
		return v
	}
	return "pipelock_event"
}

// Tailer tails an NDJSON log (Pipelock's audit log, split-brain-harness's logs,
// any one-JSON-object-per-line feed) and sends parsed events to a channel. It
// polls the file with a short sleep — no inotify dependency, works everywhere.
//
// Without a state file (NewTailer) it starts at the end of an existing file and
// forwards only new lines, as it always has. With a state file (SetStateFile)
// it resumes where the last run left off, so lines written while the witness
// was stopped are still ingested: the gap a restart used to leave is closed.
//
// Delivery is at-least-once, never at-most-once. The saved position advances
// only past lines the consumer has Ack'ed — i.e. stored — so a crash re-reads
// rather than skips. A duplicate entry is visible in the evidence; a missing one
// is not.
type Tailer struct {
	path         string
	events       chan AuditEvent
	stop         chan struct{}
	done         chan struct{}
	drainTimeout time.Duration

	// Resume state (all zero when statePath is empty).
	statePath string
	onOpen    func(OpenInfo)

	mu        sync.Mutex
	pending   []pendingLine // emitted or skipped lines not yet committed, in file order
	committed int64         // end offset of the last line safely stored
	ident     fileIdent     // identity of the file `committed` refers to
	dirty     int           // acks since the last flush
	lastFlush time.Time
}

type pendingLine struct {
	end   int64
	acked bool
}

type fileIdent struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

// OpenInfo describes where the tailer started reading a file.
type OpenInfo struct {
	// Mode is "fresh" (no saved state: start at end), "resumed" (continued from
	// the saved position), "restarted" (file replaced or truncated since the
	// saved position: read from the beginning), or "rotated" (file replaced while
	// running: read the new file from the beginning).
	Mode     string
	From     int64 // byte offset reading starts at
	FileSize int64 // file size at open; FileSize-From bytes are being caught up
}

// tailState is the on-disk resume record.
type tailState struct {
	Path    string    `json:"path"`
	Ident   fileIdent `json:"ident"`
	Offset  int64     `json:"offset"`
	Updated time.Time `json:"updated"`
}

const (
	flushEvery     = time.Second
	flushEveryAcks = 64
)

// NewTailer creates a Tailer for the given log file path.
// events is the channel that receives parsed audit events.
func NewTailer(path string, events chan AuditEvent) *Tailer {
	return &Tailer{
		path:   path,
		events: events,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		// On Stop the tailer keeps reading until it reaches EOF so the final
		// records (e.g. pipelock's shutdown transcript_root) are not lost. The
		// deadline bounds that drain in case writes are somehow still ongoing.
		drainTimeout: 2 * time.Second,
	}
}

// SetStateFile enables resume: the read position is saved to path and restored
// on the next Run. Call before Run. The consumer must call Ack once per event it
// has stored, and Flush after it stops consuming.
func (t *Tailer) SetStateFile(path string) { t.statePath = path }

// OnOpen registers a callback invoked each time the tailer opens the file, so the
// caller can record how much was caught up after downtime. Call before Run.
func (t *Tailer) OnOpen(fn func(OpenInfo)) { t.onOpen = fn }

// Ack marks the oldest unacknowledged event as stored. Events are delivered in
// file order on one channel, so a single in-order consumer acks them in order.
func (t *Tailer) Ack() {
	if t.statePath == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.pending {
		if !t.pending[i].acked {
			t.pending[i].acked = true
			break
		}
	}
	t.advanceLocked()
	t.dirty++
	if t.dirty >= flushEveryAcks || time.Since(t.lastFlush) >= flushEvery {
		t.flushLocked()
	}
}

// Flush writes the committed position to the state file now.
func (t *Tailer) Flush() {
	if t.statePath == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.flushLocked()
}

// advanceLocked moves `committed` past the longest fully-acked prefix.
func (t *Tailer) advanceLocked() {
	n := 0
	for n < len(t.pending) && t.pending[n].acked {
		t.committed = t.pending[n].end
		n++
	}
	t.pending = t.pending[n:]
}

func (t *Tailer) flushLocked() {
	st := tailState{Path: t.path, Ident: t.ident, Offset: t.committed, Updated: time.Now().UTC()}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(t.statePath), 0700); err != nil {
		return
	}
	tmp := t.statePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return
	}
	if os.Rename(tmp, t.statePath) == nil {
		t.dirty = 0
		t.lastFlush = time.Now()
	}
}

func (t *Tailer) loadState() (tailState, bool) {
	data, err := os.ReadFile(t.statePath)
	if err != nil {
		return tailState{}, false
	}
	var st tailState
	if json.Unmarshal(data, &st) != nil || st.Path != t.path || st.Offset < 0 {
		return tailState{}, false
	}
	return st, true
}

// record notes a line that has been read: emitted lines wait for Ack, skipped
// ones (blank, not JSON) are committed as soon as everything before them is.
func (t *Tailer) record(end int64, emitted bool) {
	if t.statePath == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending = append(t.pending, pendingLine{end: end, acked: !emitted})
	t.advanceLocked()
}

// Run starts tailing the file. Blocks until Stop is called, then drains the
// remaining lines to EOF before returning so shutdown records are captured.
func (t *Tailer) Run() {
	defer close(t.done)

	var f *os.File
	var reader *bufio.Reader
	var pos int64 // logical position: end of the last complete line consumed
	firstOpen := true

	openFile := func() bool {
		var err error
		f, err = os.Open(t.path)
		if err != nil {
			return false
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return false
		}
		size, ident := fi.Size(), identOf(fi)
		info := OpenInfo{FileSize: size}
		switch {
		case !firstOpen:
			// Replaced or truncated while running: everything in it is new.
			info.Mode, info.From = "rotated", 0
		case t.statePath == "":
			info.Mode, info.From = "fresh", size // only tail new events
		default:
			st, ok := t.loadState()
			switch {
			case !ok:
				info.Mode, info.From = "fresh", size
			case st.Ident == ident && st.Offset <= size:
				info.Mode, info.From = "resumed", st.Offset
			default:
				// Replaced or truncated while the witness was down. The old
				// file's unread tail is gone; read the new content in full.
				info.Mode, info.From = "restarted", 0
			}
		}
		firstOpen = false
		if _, err := f.Seek(info.From, io.SeekStart); err != nil {
			_ = f.Close()
			return false
		}
		pos = info.From
		reader = bufio.NewReaderSize(f, 64<<10)
		if t.statePath != "" {
			t.mu.Lock()
			t.pending = nil
			t.committed, t.ident = info.From, ident
			t.mu.Unlock()
		}
		if t.onOpen != nil {
			t.onOpen(info)
		}
		return true
	}

	// Wait for file to appear.
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		if openFile() {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer f.Close()

	stopped := false
	var drainDeadline time.Time
	for {
		// Once Stop is signalled we stop polling for new data but keep reading
		// what is already on disk until EOF, so pipelock's final checkpoint is
		// not left unread.
		if !stopped {
			select {
			case <-t.stop:
				stopped = true
				drainDeadline = time.Now().Add(t.drainTimeout)
			default:
			}
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if line != "" {
					// A line still being written: rewind to its start and read it
					// again once it is complete, instead of dropping the fragment.
					if _, serr := f.Seek(pos, io.SeekStart); serr == nil {
						reader.Reset(f)
					}
				}
				// Check if file was rotated (replaced, or shrunk below our position).
				if fi, statErr := os.Stat(t.path); statErr == nil {
					cur, _ := f.Stat()
					if fi.Size() < pos || (cur != nil && !os.SameFile(fi, cur)) {
						_ = f.Close()
						if openFile() {
							continue
						}
					}
				}
				if stopped {
					return // drained to EOF after stop
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			// Real read error — try to reopen.
			_ = f.Close()
			if stopped {
				return
			}
			time.Sleep(500 * time.Millisecond)
			openFile()
			continue
		}

		pos += int64(len(line))
		line = trimNewline(line)
		var evt AuditEvent
		if line == "" || json.Unmarshal([]byte(line), &evt) != nil {
			t.record(pos, false)
		} else {
			t.record(pos, true)
			if stopped {
				// Draining: deliver to the still-alive consumer, bounded by
				// the drain deadline so a dead consumer can't hang us. An event
				// not delivered is not acked, so it is re-read on the next run.
				select {
				case t.events <- evt:
				case <-time.After(time.Until(drainDeadline)):
					return
				}
			} else {
				select {
				case t.events <- evt:
				case <-t.stop:
					stopped = true
					drainDeadline = time.Now().Add(t.drainTimeout)
				}
			}
		}

		if stopped && time.Now().After(drainDeadline) {
			return // safety bound — don't drain forever if writes keep coming
		}
	}
}

// Stop signals the tailer to drain to EOF and exit, then waits for it to finish.
func (t *Tailer) Stop() {
	close(t.stop)
	<-t.done
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
