// Package pipelock_bridge connects a Pipelock session to the witness Merkle log.
//
// The bridge manages the pipelock subprocess lifecycle (runner + tailer) and
// forwards every audit event into the store as a signed Merkle leaf. All
// pipelock wiring is contained here; callers only need Start/Stop.
//
// Migration note: when github.com/luckyPipewrench/pipelock exposes a stable
// Go library API, only this package needs to change. The bridge interface
// presented to cmd/witness stays the same.
package pipelock_bridge

import (
	"strings"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Bridge connects a pipelock session to the witness Merkle log.
type Bridge struct {
	runner      *pipelock.Runner
	tailer      *pipelock.Tailer
	events      chan pipelock.AuditEvent
	store       *store.Store
	stopForward chan struct{}
	done        chan struct{}
	enabled     bool
}

// New creates a Bridge for the given pipelock config and witness store.
// Call Start to begin forwarding events.
func New(cfg *pipelock.Config, s *store.Store) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	return &Bridge{
		runner:      pipelock.NewRunner(cfg),
		tailer:      pipelock.NewTailer(cfg.AuditLogPath(), ch),
		events:      ch,
		store:       s,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start launches the pipelock subprocess and begins forwarding audit events
// into the witness Merkle log. Returns an error if the pipelock binary is
// not found or fails to start; in that case the bridge is disabled and Stop
// is a safe no-op.
func (b *Bridge) Start() error {
	if err := b.runner.Start(); err != nil {
		return err
	}
	b.enabled = true
	go b.tailer.Run()
	go b.forward()
	return nil
}

// Stop halts event forwarding and shuts down the pipelock subprocess.
// Safe to call even if Start returned an error.
func (b *Bridge) Stop() {
	if !b.enabled {
		return
	}
	b.tailer.Stop()
	b.runner.Stop()
	close(b.stopForward)
	<-b.done
}

// ProxyAddr returns the HTTP proxy address agents should use (HTTPS_PROXY / HTTP_PROXY).
func (b *Bridge) ProxyAddr() string { return b.runner.ProxyAddr() }

// Enabled reports whether pipelock started successfully and is forwarding events.
func (b *Bridge) Enabled() bool { return b.enabled }

func (b *Bridge) forward() {
	defer close(b.done)
	for {
		select {
		case evt, ok := <-b.events:
			if !ok {
				return
			}
			level := strings.ToUpper(evt.Level())
			if level == "DEBUG" || level == "TRACE" {
				level = "INFO"
			}
			_ = b.store.Append(level, evt.EventName(), "pipelock", evt)
		case <-b.stopForward:
			return
		}
	}
}
