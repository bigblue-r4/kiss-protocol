// Package sbh bridges the split-brain-harness forge audit log to the witness
// Merkle log. Every forge run written to SBH_AUDIT_PATH (a JSONL file) is
// forwarded into the encrypted, hash-chained witness store as source "sbh".
//
// The bridge reuses the pipelock NDJSON tailer — the forge audit log is
// already NDJSON and the AuditEvent type is map[string]interface{}, which
// matches the forge audit entry schema exactly.
//
// Failed forge runs (succeeded=false) are stored at level WARN; successful
// runs at INFO. Event names are "forge_run:<capability>" for easy grep.
package sbh

import (
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Bridge tails the forge audit log and forwards events to the witness store.
type Bridge struct {
	tailer      *pipelock.Tailer
	events      chan pipelock.AuditEvent
	store       *store.Store
	stopForward chan struct{}
	done        chan struct{}
}

// New creates a Bridge for the given audit log path and witness store.
// Call Start to begin forwarding. path should equal SBH_AUDIT_PATH.
func New(path string, s *store.Store) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	return &Bridge{
		tailer:      pipelock.NewTailer(path, ch),
		events:      ch,
		store:       s,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start begins tailing the forge audit log and forwarding events.
func (b *Bridge) Start() {
	go b.tailer.Run()
	go b.forward()
}

// Stop halts forwarding. Safe to call even before Start.
func (b *Bridge) Stop() {
	b.tailer.Stop()
	close(b.stopForward)
	<-b.done
}

func (b *Bridge) forward() {
	defer close(b.done)
	for {
		select {
		case evt, ok := <-b.events:
			if !ok {
				return
			}
			level := "INFO"
			if succeeded, ok := evt["succeeded"].(bool); ok && !succeeded {
				level = "WARN"
			}
			eventName := "forge_run"
			if cap, ok := evt["capability"].(string); ok && cap != "" {
				eventName = "forge_run:" + cap
			}
			_ = b.store.Append(level, eventName, "sbh", evt)
		case <-b.stopForward:
			return
		}
	}
}
