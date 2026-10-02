// Package farm ingests a farm-automation event feed into the witness Merkle log
// and watches every source in it for silence.
//
// The feed is NDJSON, one event per line, in the format documented in
// docs/farm-events.md: {"ts", "source", "kind", ...}. Kinds are reading, alarm,
// setting_change, access, health and heartbeat; anything else is still recorded
// (as farm_event), never dropped. Entries are stored as source "farm" with the
// original event as the payload.
//
// The silence monitor is the "frozen house" check: a source that has reported
// before and then goes quiet for longer than the threshold gets one WARN
// farm_source_silent, and an INFO farm_source_resumed when it reports again.
// It detects and records; it cannot keep the house running.
package farm

import (
	"sort"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Classify maps one farm event to the witness level and event name.
func Classify(evt pipelock.AuditEvent) (level, event string) {
	kind, _ := evt["kind"].(string)
	sub := func(field string) string {
		if v, ok := evt[field].(string); ok && v != "" {
			return ":" + v
		}
		return ""
	}
	switch kind {
	case "alarm":
		return "WARN", "farm_alarm" + sub("alarm")
	case "setting_change":
		return "INFO", "farm_setting_change" + sub("setting")
	case "reading":
		return "INFO", "farm_reading" + sub("metric")
	case "access":
		return "INFO", "farm_access" + sub("door")
	case "health":
		return "INFO", "farm_health" + sub("record")
	case "heartbeat":
		return "INFO", "farm_heartbeat"
	default:
		return "INFO", "farm_event"
	}
}

// eventTime is when the event happened according to its source; arrival time if
// the source sent none or an unparseable one. Using the source's time means a
// burst of old events caught up after a witness restart cannot mask a source
// that really did go quiet.
func eventTime(evt pipelock.AuditEvent, arrived time.Time) time.Time {
	if s, ok := evt["ts"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return arrived
}

// Monitor tracks when each source last reported and flags the silent ones.
type Monitor struct {
	threshold time.Duration
	mu        sync.Mutex
	lastSeen  map[string]time.Time
	silent    map[string]bool
}

// NewMonitor returns a Monitor that flags a source after threshold of silence.
func NewMonitor(threshold time.Duration) *Monitor {
	return &Monitor{threshold: threshold, lastSeen: map[string]time.Time{}, silent: map[string]bool{}}
}

// Transition is a change in a source's state for the witness log.
type Transition struct {
	Level, Event string
	Data         map[string]interface{}
}

// Seen records a report from source at t. It returns a "resumed" transition if
// the source had been flagged silent.
func (m *Monitor) Seen(source string, t time.Time) *Transition {
	if source == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, known := m.lastSeen[source]
	if !known || t.After(prev) {
		m.lastSeen[source] = t
	}
	if m.silent[source] {
		delete(m.silent, source)
		return &Transition{"INFO", "farm_source_resumed", map[string]interface{}{
			"source": source, "last_seen_before": prev.UTC().Format(time.RFC3339),
			"silent_for_seconds": int64(t.Sub(prev).Seconds()),
		}}
	}
	return nil
}

// Check returns a "silent" transition for every source quiet longer than the
// threshold at now, each flagged once until it reports again. Sorted by source
// so the log order is deterministic.
func (m *Monitor) Check(now time.Time) []Transition {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Transition
	for src, seen := range m.lastSeen {
		if m.silent[src] || now.Sub(seen) <= m.threshold {
			continue
		}
		m.silent[src] = true
		out = append(out, Transition{"WARN", "farm_source_silent", map[string]interface{}{
			"source": src, "last_seen": seen.UTC().Format(time.RFC3339),
			"silent_for_seconds": int64(now.Sub(seen).Seconds()),
			"threshold_seconds":  int64(m.threshold.Seconds()),
		}})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Data["source"].(string) < out[j].Data["source"].(string) })
	return out
}

// Bridge tails the farm feed into the store and runs the silence monitor.
type Bridge struct {
	tailer      *pipelock.Tailer
	events      chan pipelock.AuditEvent
	store       *store.Store
	monitor     *Monitor
	checkEvery  time.Duration
	now         func() time.Time
	stopForward chan struct{}
	done        chan struct{}
}

// New creates a Bridge for the farm event feed at path. Sources silent longer
// than threshold are flagged.
func New(path string, s *store.Store, threshold time.Duration) *Bridge {
	ch := make(chan pipelock.AuditEvent, 256)
	return &Bridge{
		tailer:      pipelock.NewTailer(path, ch),
		events:      ch,
		store:       s,
		monitor:     NewMonitor(threshold),
		checkEvery:  30 * time.Second,
		now:         time.Now,
		stopForward: make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// ResumeFrom saves the read position so a restarted witness ingests what the
// farm logged while it was down, and records each (re)open. Call before Start.
func (b *Bridge) ResumeFrom(statePath string) {
	b.tailer.SetStateFile(statePath)
	b.tailer.OnOpen(func(i pipelock.OpenInfo) {
		level, event, data := pipelock.OpenEvent("farm_events", i)
		_ = b.store.Append(level, event, "farm", data)
	})
}

// Start begins tailing, forwarding and silence checks.
func (b *Bridge) Start() {
	go b.tailer.Run()
	go b.forward()
}

// Stop halts forwarding and saves the read position.
func (b *Bridge) Stop() {
	b.tailer.Stop()
	close(b.stopForward)
	<-b.done
	b.tailer.Flush()
}

func (b *Bridge) forward() {
	defer close(b.done)
	tick := time.NewTicker(b.checkEvery)
	defer tick.Stop()
	for {
		select {
		case evt, ok := <-b.events:
			if !ok {
				return
			}
			b.ingest(evt)
		case <-tick.C:
			b.checkSilence()
		case <-b.stopForward:
			return
		}
	}
}

func (b *Bridge) ingest(evt pipelock.AuditEvent) {
	level, event := Classify(evt)
	if b.store.Append(level, event, "farm", evt) != nil {
		return // not stored: not acked, re-read on the next run
	}
	b.tailer.Ack()
	src, _ := evt["source"].(string)
	if tr := b.monitor.Seen(src, eventTime(evt, b.now())); tr != nil {
		_ = b.store.Append(tr.Level, tr.Event, "farm", tr.Data)
	}
}

func (b *Bridge) checkSilence() {
	for _, tr := range b.monitor.Check(b.now()) {
		_ = b.store.Append(tr.Level, tr.Event, "farm", tr.Data)
	}
}
