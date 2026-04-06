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
	path   string
	events chan AuditEvent
	stop   chan struct{}
}

// NewTailer creates a Tailer for the given log file path.
// events is the channel that receives parsed audit events.
func NewTailer(path string, events chan AuditEvent) *Tailer {
	return &Tailer{
		path:   path,
		events: events,
		stop:   make(chan struct{}),
	}
}

// Run starts tailing the file. Blocks until Stop is called.
// Seeks to the end of the file on open so that only new events are forwarded.
func (t *Tailer) Run() {
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

	for {
		select {
		case <-t.stop:
			return
		default:
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
				time.Sleep(200 * time.Millisecond)
				continue
			}
			// Real read error — try to reopen.
			_ = f.Close()
			time.Sleep(500 * time.Millisecond)
			openFile()
			continue
		}

		// Track our position for rotation detection.
		offset, _ = f.Seek(0, io.SeekCurrent)

		line = trimNewline(line)
		if line == "" {
			continue
		}
		var evt AuditEvent
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue // skip malformed lines
		}
		select {
		case t.events <- evt:
		case <-t.stop:
			return
		}
	}
}

// Stop signals the tailer to exit.
func (t *Tailer) Stop() {
	close(t.stop)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
