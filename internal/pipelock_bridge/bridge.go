// Package pipelock_bridge connects a Pipelock session to the witness Merkle log.
//
// The bridge manages the pipelock subprocess lifecycle (runner + tailers) and
// forwards every audit event and flight_recorder decision receipt into the
// store as a signed Merkle leaf. All pipelock wiring is contained here; callers
// only need Start/Stop.
//
// Two event streams are folded into the witness log:
//   - the NDJSON audit log (source "pipelock", raw request/response events)
//   - the flight_recorder evidence directory (source "pipelock", signed,
//     hash-chained decision receipts), when flight_recorder is configured
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
	evidence    *pipelock.EvidenceTailer
	evEvents    chan pipelock.AuditEvent
	store       *store.Store
	stopForward chan struct{}
	done        chan struct{}
	enabled     bool
}

// New creates a Bridge for the given pipelock config and witness store.
// Call Start to begin forwarding events.
func New(cfg *pipelock.Config, s *store.Store) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	evCh := make(chan pipelock.AuditEvent, 256)
	runner := pipelock.NewRunner(cfg)
	// Forward pipelock's own stderr (startup errors, config rejections, panics)
	// into the witness log so a misconfiguration is recorded, not silent.
	runner.SetStderrSink(func(line string) {
		_ = s.Append("WARN", "pipelock_stderr", "pipelock",
			map[string]interface{}{"message": line})
	})
	b := &Bridge{
		runner:      runner,
		tailer:      pipelock.NewTailer(cfg.AuditLogPath(), ch),
		events:      ch,
		evEvents:    evCh,
		store:       s,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
	// flight_recorder writes signed, hash-chained receipts to a directory; tail
	// them so they land in the witness log next to the raw audit events.
	if cfg.EvidenceDir != "" {
		b.evidence = pipelock.NewEvidenceTailer(cfg.EvidenceDir, evCh)
	}
	return b
}

// Start launches the pipelock subprocess and begins forwarding audit events
// and flight_recorder receipts into the witness Merkle log. Returns an error if
// the pipelock binary is not found or fails to start; in that case the bridge
// is disabled and Stop is a safe no-op.
func (b *Bridge) Start() error {
	if err := b.runner.Start(); err != nil {
		return err
	}
	b.enabled = true
	go b.tailer.Run()
	if b.evidence != nil {
		go b.evidence.Run()
	}
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
	if b.evidence != nil {
		b.evidence.Stop()
	}
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
	events := b.events
	evEvents := b.evEvents
	for {
		select {
		case evt, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			_ = b.store.Append(normalizeLevel(evt.Level()), evt.EventName(), "pipelock", evt)
		case evt, ok := <-evEvents:
			if !ok {
				evEvents = nil
				continue
			}
			level, event := classifyReceipt(evt)
			_ = b.store.Append(level, event, "pipelock", evt)
		case <-b.stopForward:
			return
		}
	}
}

// normalizeLevel maps pipelock log levels onto the witness levels, collapsing
// DEBUG/TRACE/unset to INFO.
func normalizeLevel(level string) string {
	level = strings.ToUpper(level)
	if level == "DEBUG" || level == "TRACE" || level == "" {
		return "INFO"
	}
	return level
}

// classifyReceipt derives a (level, event) label for a flight_recorder entry.
// The receipt schema varies across pipelock versions, so the whole entry is
// always forwarded as data and only well-known fields are read for labelling.
func classifyReceipt(evt pipelock.AuditEvent) (string, string) {
	event := "pipelock_receipt"
	for _, k := range []string{"type", "kind", "decision", "action", "event"} {
		if v, ok := evt[k].(string); ok && v != "" {
			event = "pipelock_receipt:" + v
			break
		}
	}
	return normalizeLevel(evt.Level()), event
}
