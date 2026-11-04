// Package feed writes the gate's NDJSON event feed, the only file the gate
// writes besides its own state (gate-arch.md section 9). The witness records
// it as source "gate" through its event_feeds config.
//
// Every value is a string (C8): the witness re-marshals each line through
// map[string]interface{}, so numbers above 2^53 would lose precision. Every
// write is fsynced before it returns: a decision is not taken until it is on
// disk, and a write error means the gate must not issue (fail closed).
package feed

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

var kindRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// Writer appends lines to the feed file.
type Writer struct {
	mu   sync.Mutex
	f    *os.File
	path string
	now  func() time.Time
	err  error // sticky: once a write fails, every later write fails
}

// Open opens (creating, mode 0640) the feed for appending.
func Open(path string, now func() time.Time) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Writer{f: f, path: path, now: now}, nil
}

// ErrBroken is wrapped by every write after the first failure.
var ErrBroken = errors.New("gate feed unwritable")

// Write appends one record: kind, level ("" = INFO; WARN or CRITICAL raise
// it in the witness), gate_ts, and fields. A failure is sticky: a feed that
// lost one line can no longer prove the gate's history, so the gate stops
// issuing until it is restarted with a working feed.
func (w *Writer) Write(kind, level string, fields map[string]string) error {
	if !kindRE.MatchString(kind) {
		return fmt.Errorf("feed: bad kind %q", kind)
	}
	rec := make(map[string]string, len(fields)+3)
	for k, v := range fields {
		rec[k] = v
	}
	rec["kind"] = kind
	if level != "" {
		rec["level"] = level
	}
	rec["gate_ts"] = w.now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if _, err := w.f.Write(append(line, '\n')); err != nil {
		w.err = fmt.Errorf("%w: %v", ErrBroken, err)
		return w.err
	}
	if err := w.f.Sync(); err != nil {
		w.err = fmt.Errorf("%w: fsync: %v", ErrBroken, err)
		return w.err
	}
	return nil
}

// Healthy reports whether the feed is still writable.
func (w *Writer) Healthy() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// Close closes the file.
func (w *Writer) Close() error { return w.f.Close() }

// Read returns every well-formed line of the feed at path, oldest first,
// as string maps. A torn last line (crash mid-write) is skipped. A missing
// file is an empty feed.
func Read(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []map[string]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var m map[string]string
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}
