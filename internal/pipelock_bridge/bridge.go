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
//
// Order matters: pipelock is stopped first so it flushes its final
// transcript_root and shutdown checkpoint to the audit log and evidence dir.
// Only then are the tailers stopped — each drains to EOF before exiting, so the
// clean-shutdown records are read into the witness log instead of being lost.
// The forwarder is torn down last and drains any buffered events on its way out.
func (b *Bridge) Stop() {
	if !b.enabled {
		return
	}
	b.runner.Stop()
	b.tailer.Stop()
	if b.evidence != nil {
		b.evidence.Stop()
	}
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
			// Tailers have already drained to EOF and exited by the time
			// stopForward is closed, so anything left is sitting in the channel
			// buffers. Flush it before exiting so no receipt is dropped.
			b.drainRemaining()
			return
		}
	}
}

// drainRemaining appends any events still buffered in the channels after the
// tailers have stopped, then returns once both are empty.
func (b *Bridge) drainRemaining() {
	for {
		select {
		case evt := <-b.events:
			_ = b.store.Append(normalizeLevel(evt.Level()), evt.EventName(), "pipelock", evt)
		case evt := <-b.evEvents:
			level, event := classifyReceipt(evt)
			_ = b.store.Append(level, event, "pipelock", evt)
		default:
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
//
// Field precedence follows Pipelock's flight_recorder envelope (most specific
// first), so the read/write classification of a real action receipt isn't lost
// behind its generic top-level type:
//   - lifecycle/control receipts carry detail.action_record.session_control.kind
//     (session_open, heartbeat, session_close)
//   - action receipts (top-level type "action_receipt") carry the canonical
//     top-level event_kind (e.g. read, write)
//   - older rows without event_kind fall back to detail.action_record.action_type
//   - failing all of those, the top-level type is used as-is
func classifyReceipt(evt pipelock.AuditEvent) (string, string) {
	m := map[string]interface{}(evt)
	kind := firstNonEmpty(
		nestedString(m, "detail", "action_record", "session_control", "kind"),
		nestedString(m, "event_kind"),
		nestedString(m, "detail", "action_record", "action_type"),
		nestedString(m, "type"),
	)
	event := "pipelock_receipt"
	if kind != "" {
		event = "pipelock_receipt:" + kind
	}

	// Start from the row's own log level, then elevate on a blocking or warning
	// verdict so denials stand out in the witness log even if the row logs INFO.
	level := normalizeLevel(evt.Level())
	verdict := firstNonEmpty(
		nestedString(m, "detail", "action_record", "verdict"),
		nestedString(m, "verdict"),
	)
	level = elevateForVerdict(level, verdict)
	return level, event
}

// nestedString walks evt down the given keys and returns the string leaf, or ""
// if any hop is missing or not a string / nested object.
func nestedString(evt map[string]interface{}, keys ...string) string {
	var cur interface{} = evt
	for i, k := range keys {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = m[k]
		if i == len(keys)-1 {
			s, _ := cur.(string)
			return s
		}
	}
	return ""
}

// firstNonEmpty returns the first non-empty string in vals.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// elevateForVerdict raises an INFO row to WARN when Pipelock blocked or warned
// on the action, leaving already-elevated levels untouched.
func elevateForVerdict(level, verdict string) string {
	switch strings.ToLower(verdict) {
	case "block", "blocked", "deny", "denied", "warn", "warning":
		if level == "INFO" {
			return "WARN"
		}
	}
	return level
}
