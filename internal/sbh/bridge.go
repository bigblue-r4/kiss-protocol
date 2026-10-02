// Package sbh bridges split-brain-harness logs into the witness Merkle log.
//
// Three SBH logs are tailed, each with its own classifier, all stored as source "sbh":
//
//   - the forge audit log (SBH_AUDIT_PATH): one line per tool-generation run.
//     Event "forge_run:<capability>"; WARN when the run failed.
//   - the per-decision log (SBH_DECISION_LOG): one line per request `sbh serve`
//     analysed. Event "sbh_decision:stop_and_ask" or "sbh_decision:pass"; WARN when
//     the gate demanded stop_and_ask, the risk was high, or the turn escalated.
//   - the session escalation log (SBH_SESSION_LOG): one line per multi-turn
//     slow-boil escalation. Event "sbh_escalation"; always WARN.
//
// The bridges reuse the pipelock NDJSON tailer: every SBH log is already one JSON
// object per line, and AuditEvent is a map, so the full SBH entry is stored as the
// payload unchanged. None of these logs carries raw user input (SBH writes an
// input fingerprint), so neither does the witness record.
package sbh

import (
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Classifier maps one SBH log entry to the witness level and event name.
type Classifier func(evt pipelock.AuditEvent) (level, event string)

// Bridge tails one SBH log and forwards each entry to the witness store.
type Bridge struct {
	tailer      *pipelock.Tailer
	events      chan pipelock.AuditEvent
	store       *store.Store
	classify    Classifier
	stopForward chan struct{}
	done        chan struct{}
}

func newBridge(path string, s *store.Store, c Classifier) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	return &Bridge{
		tailer:      pipelock.NewTailer(path, ch),
		events:      ch,
		store:       s,
		classify:    c,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// New creates a Bridge for the forge audit log. path should equal SBH_AUDIT_PATH.
func New(path string, s *store.Store) *Bridge { return newBridge(path, s, ClassifyForge) }

// NewDecisionLog creates a Bridge for the per-decision log (SBH_DECISION_LOG).
func NewDecisionLog(path string, s *store.Store) *Bridge {
	return newBridge(path, s, ClassifyDecision)
}

// NewSessionLog creates a Bridge for the session escalation log (SBH_SESSION_LOG).
func NewSessionLog(path string, s *store.Store) *Bridge {
	return newBridge(path, s, ClassifyEscalation)
}

// ResumeFrom saves the read position to statePath so a restarted witness picks
// up lines written while it was down, and records each (re)open in the witness
// log. Call before Start.
func (b *Bridge) ResumeFrom(statePath, feed string) {
	b.tailer.SetStateFile(statePath)
	b.tailer.OnOpen(func(i pipelock.OpenInfo) {
		level, event, data := pipelock.OpenEvent(feed, i)
		_ = b.store.Append(level, event, "sbh", data)
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
			level, event := b.classify(evt)
			if b.store.Append(level, event, "sbh", evt) == nil {
				b.tailer.Ack() // only a stored entry moves the resume position
			}
		case <-b.stopForward:
			return
		}
	}
}

// ClassifyForge: "forge_run:<capability>", WARN when the run failed.
func ClassifyForge(evt pipelock.AuditEvent) (string, string) {
	level := "INFO"
	if succeeded, ok := evt["succeeded"].(bool); ok && !succeeded {
		level = "WARN"
	}
	event := "forge_run"
	if c, ok := evt["capability"].(string); ok && c != "" {
		event = "forge_run:" + c
	}
	return level, event
}

// ClassifyDecision: "sbh_decision:stop_and_ask" or "sbh_decision:pass".
// WARN when the gate stopped, the manipulation risk was high, or the turn escalated:
// those are the decisions an operator reviewing the record needs to find first.
func ClassifyDecision(evt pipelock.AuditEvent) (string, string) {
	stopped, _ := evt["stop_and_ask"].(bool)
	escalated, _ := evt["escalation"].(bool)
	risk, _ := evt["manipulation_risk"].(string)

	event := "sbh_decision:pass"
	if stopped {
		event = "sbh_decision:stop_and_ask"
	}
	level := "INFO"
	if stopped || escalated || risk == "high" {
		level = "WARN"
	}
	return level, event
}

// ClassifyEscalation: every escalation line is a WARN "sbh_escalation".
func ClassifyEscalation(pipelock.AuditEvent) (string, string) {
	return "WARN", "sbh_escalation"
}
