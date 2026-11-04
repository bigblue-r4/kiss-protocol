package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/breaker"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/core"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// state is the gate's own file (StateDir/state.json, 0600). It holds what
// the gate needs across restarts that the verified log cannot give it
// cheaply: retained witness heads (append-only checks against heads seen in
// earlier runs) and known edges. It is never trusted to loosen the breaker;
// that comes only from the verified log.
type state struct {
	Priors []store.TreeHead `json:"priors"`
	Edges  []string         `json:"edges"`
}

func (d *Daemon) statePath() string { return filepath.Join(d.cfg.StateDir, "state.json") }

func (d *Daemon) loadState() state {
	var st state
	b, err := os.ReadFile(d.statePath())
	if err == nil {
		if err := json.Unmarshal(b, &st); err != nil {
			// A corrupt state file loses priors and edges: both only make
			// the gate stricter (first-seen edges escalate again).
			d.logf("state.json unreadable (%v); starting without priors or edges", err)
			st = state{}
		}
	}
	return st
}

// saveState writes atomically (temp file + rename) when something changed.
func (d *Daemon) saveState(v *evidence.View, c *core.Core) {
	edges := c.Edges()
	priors := v.Priors()
	var top uint64
	if n := len(priors); n > 0 {
		top = priors[n-1].Size
	}
	d.mu.Lock()
	if len(edges) == d.edgesSeen && top == d.priorTop && len(priors) == d.priorN {
		d.mu.Unlock()
		return
	}
	d.edgesSeen, d.priorTop, d.priorN = len(edges), top, len(priors)
	d.mu.Unlock()
	sort.Strings(edges)
	b, err := json.Marshal(state{Priors: priors, Edges: edges})
	if err != nil {
		return
	}
	tmp := d.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		d.logf("saving state: %v", err)
		return
	}
	if err := os.Rename(tmp, d.statePath()); err != nil {
		d.logf("saving state: %v", err)
	}
}

// encodeEvent renders a breaker event as feed fields, all strings (C8).
func encodeEvent(e breaker.Event) map[string]string {
	f := map[string]string{
		"scope_kind": e.Scope.Kind, "scope_value": e.Scope.Value, "scope": e.Scope.String(),
		"epoch": strconv.FormatUint(e.Epoch, 10), "trigger": e.Trigger, "reason": e.Reason,
		"event_ts": proto.FormatTime(e.TS),
	}
	if e.Bundle != nil {
		if raw, err := proto.Canonical(*e.Bundle); err == nil {
			f["bundle"] = string(raw)
		}
		f["nonce"] = e.Bundle.Reset.Nonce
	}
	if len(e.Approvers) > 0 {
		b, _ := json.Marshal(e.Approvers)
		f["approvers"] = string(b)
	}
	return f
}

// decodeEvent is the inverse, for restore. Lines that are not breaker events
// or do not parse are skipped (false).
func decodeEvent(f map[string]string) (breaker.Event, bool) {
	var e breaker.Event
	switch f["kind"] {
	case breaker.EventTrip, breaker.EventReset:
		e.Type = f["kind"]
	default:
		return e, false
	}
	e.Scope = proto.Scope{Kind: f["scope_kind"], Value: f["scope_value"]}
	if e.Scope.Validate() != nil {
		return e, false
	}
	n, err := strconv.ParseUint(f["epoch"], 10, 64)
	if err != nil {
		return e, false
	}
	e.Epoch, e.Trigger, e.Reason = n, f["trigger"], f["reason"]
	if t, err := proto.ParseTime(f["event_ts"], "event_ts"); err == nil {
		e.TS = t
	}
	if raw := f["bundle"]; raw != "" {
		if b, err := proto.DecodeResetBundle([]byte(raw)); err == nil {
			e.Bundle = &b
		}
	}
	return e, true
}
