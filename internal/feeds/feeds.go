// Package feeds records any number of named NDJSON event feeds in the witness
// Merkle log: one feed per program that has something to put on the record
// (a dispatcher, an egress monitor, an integrity checker), each in its own file.
//
// The source each entry is stored under is the feed's configured name, never a
// field in the line: a program can only write as the feeds whose files it can
// write to, so file permissions decide who can speak for which source. The
// line's "kind" names the event and "level" may raise it to WARN or CRITICAL;
// the whole line is stored unchanged as the payload. See docs/event-feeds.md.
package feeds

import (
	"regexp"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

var kindRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// Classify maps one feed line to the witness level and event name. A missing
// or malformed kind is recorded as "feed_event", never dropped.
func Classify(evt pipelock.AuditEvent) (level, event string) {
	event = "feed_event"
	if k, ok := evt["kind"].(string); ok && kindRE.MatchString(k) {
		event = k
	}
	level = "INFO"
	if l, ok := evt["level"].(string); ok && (l == "WARN" || l == "CRITICAL") {
		level = l
	}
	return level, event
}

// Bridge tails one feed file and forwards each line to the witness store.
type Bridge struct {
	source      string
	tailer      *pipelock.Tailer
	events      chan pipelock.AuditEvent
	store       *store.Store
	stopForward chan struct{}
	done        chan struct{}
}

// New creates a Bridge recording the feed at path as source.
func New(path, source string, s *store.Store) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	return &Bridge{
		source:      source,
		tailer:      pipelock.NewTailer(path, ch),
		events:      ch,
		store:       s,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// ResumeFrom saves the read position to statePath so a restarted witness picks
// up lines written while it was down, and records each (re)open in the log.
// Call before Start.
func (b *Bridge) ResumeFrom(statePath string) {
	b.tailer.SetStateFile(statePath)
	b.tailer.OnOpen(func(i pipelock.OpenInfo) {
		level, event, data := pipelock.OpenEvent("feed_"+b.source, i)
		_ = b.store.Append(level, event, b.source, data)
	})
}

// Start begins tailing and forwarding.
func (b *Bridge) Start() {
	go b.tailer.Run()
	go b.forward()
}

// Stop halts forwarding. Safe to call even before Start.
func (b *Bridge) Stop() {
	b.tailer.Stop()
	close(b.stopForward)
	<-b.done
	b.tailer.Flush()
}

func (b *Bridge) forward() {
	defer close(b.done)
	for {
		select {
		case evt, ok := <-b.events:
			if !ok {
				return
			}
			level, event := Classify(evt)
			if b.store.Append(level, event, b.source, evt) == nil {
				b.tailer.Ack() // only a stored entry moves the resume position
			}
		case <-b.stopForward:
			return
		}
	}
}
