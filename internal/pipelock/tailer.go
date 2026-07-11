package pipelock

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
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

// Tailer tails a Pipelock NDJSON audit log and sends parsed events to a channel.
// It polls the file with a short sleep — no inotify dependency, works everywhere.
type Tailer struct {
	path         string
	events       chan AuditEvent
	stop         chan struct{}
	done         chan struct{}
	drainTimeout time.Duration
}

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

// Run starts tailing the file. Blocks until Stop is called, then drains the
// remaining lines to EOF before returning so shutdown records are captured.
// Seeks to the end of the file on open so that only new events are forwarded.
func (t *Tailer) Run() {
	defer close(t.done)

	var f *os.File
	var reader *bufio.Reader
	var offset int64

	openFile := func() bool {
		var err error
		f, err = os.Open(t.path)
		if err != nil {
			return false
		}
		// Seek to end — only tail new events, not historical ones.
		offset, _ = f.Seek(0, io.SeekEnd)
		reader = bufio.NewReaderSize(f, 64<<10)
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
				// Check if file was rotated (inode changed / file shrunk).
				if fi, statErr := os.Stat(t.path); statErr == nil {
					if fi.Size() < offset {
						// Rotation detected — reopen.
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

		// Track our position for rotation detection.
		offset, _ = f.Seek(0, io.SeekCurrent)

		line = trimNewline(line)
		if line != "" {
			var evt AuditEvent
			if err := json.Unmarshal([]byte(line), &evt); err == nil {
				if stopped {
					// Draining: deliver to the still-alive consumer, bounded by
					// the drain deadline so a dead consumer can't hang us.
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
