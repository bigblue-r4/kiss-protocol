// Package lifecycle turns the witness's own interruptions into log events:
// time it was not running, and a mirror it cannot reach.
//
// A gap in the record is evidence too. An explained stop (a signal, recorded
// as it happened) is routine; an unexplained one (a crash, kill -9, power
// loss, or someone stopping the witness without it noticing) is exactly the
// window in which something could have happened unrecorded, so it is CRITICAL.
package lifecycle

import (
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Event is one record to append: level, event name, data.
type Event struct {
	Level string
	Name  string
	Data  map[string]interface{}
}

// CleanStopEvent is the record the daemon writes when it is stopped by a
// signal (see fireDeath in cmd/witness). A log ending in it was stopped on purpose.
const CleanStopEvent = "signal_received"

// GenesisEvent is the first record `witness init` writes. A log ending in it
// has never been run: the first start is not an unexplained gap.
const GenesisEvent = "genesis"

// Downtime describes the gap between the newest record and now, written at
// daemon start. ok is false for an empty log (a first start has no gap).
//
//   - no stop recorded (crash, kill -9, power loss): CRITICAL, whatever its length
//   - stop recorded, gap longer than alertAfter: WARN
//   - stop recorded, short gap: INFO
func Downtime(last store.Entry, hasLast bool, now time.Time, alertAfter time.Duration) (Event, bool) {
	if !hasLast {
		return Event{}, false
	}
	gap := now.Sub(last.Timestamp)
	if gap < 0 {
		gap = 0 // clock went backwards; recorded as zero, the timestamps tell the rest
	}
	afterInit := last.Event == GenesisEvent && last.Seq == 1
	clean := (last.Level == "DEATH" && last.Event == CleanStopEvent) || afterInit
	level := "INFO"
	switch {
	case !clean:
		level = "CRITICAL"
	case gap > alertAfter:
		level = "WARN"
	}
	return Event{Level: level, Name: "witness_downtime", Data: map[string]interface{}{
		"gap_seconds":   int64(gap.Round(time.Second) / time.Second),
		"clean_stop":    clean,
		"after_init":    afterInit,
		"last_seq":      last.Seq,
		"last_event":    last.Event,
		"last_ts":       last.Timestamp.UTC().Format(time.RFC3339),
		"alert_after_s": int64(alertAfter / time.Second),
	}}, true
}

// MirrorHealth tracks consecutive mirror push results and says what to record:
// the first failure (WARN), the point it counts as unreachable (CRITICAL), and
// the recovery (INFO). Failures in between are not recorded again, so a mirror
// that is down for hours does not flood the log. Safe for concurrent use.
type MirrorHealth struct {
	mu            sync.Mutex
	failures      int
	escalateAfter int
}

// NewMirrorHealth escalates to CRITICAL after escalateAfter consecutive failures (minimum 1).
func NewMirrorHealth(escalateAfter int) *MirrorHealth {
	if escalateAfter < 1 {
		escalateAfter = 1
	}
	return &MirrorHealth{escalateAfter: escalateAfter}
}

// Result records one push outcome and returns the event to append, if any.
func (m *MirrorHealth) Result(err error) (Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		if m.failures == 0 {
			return Event{}, false
		}
		n := m.failures
		m.failures = 0
		return Event{Level: "INFO", Name: "mirror_push_recovered", Data: map[string]interface{}{"after_failures": n}}, true
	}
	m.failures++
	switch m.failures {
	case 1:
		return Event{Level: "WARN", Name: "mirror_push_failed", Data: map[string]interface{}{"error": err.Error(), "consecutive": 1}}, true
	case m.escalateAfter:
		return Event{Level: "CRITICAL", Name: "mirror_unreachable", Data: map[string]interface{}{"error": err.Error(), "consecutive": m.failures}}, true
	}
	return Event{}, false
}

// MirrorConfig describes the mirror setup at start: missing or broken is
// CRITICAL in production (heads are then anchored nowhere but this machine)
// and WARN in dev mode. ok is false when a mirror is configured and opened.
func MirrorConfig(url string, openErr error, devMode bool) (Event, bool) {
	level := "CRITICAL"
	if devMode {
		level = "WARN"
	}
	switch {
	case url == "":
		return Event{Level: level, Name: "mirror_not_configured", Data: map[string]interface{}{
			"meaning": "signed heads are kept only on this machine; a rewrite of the log by someone with full control of it cannot be detected"}}, true
	case openErr != nil:
		return Event{Level: level, Name: "mirror_misconfigured", Data: map[string]interface{}{"error": openErr.Error()}}, true
	}
	return Event{}, false
}
