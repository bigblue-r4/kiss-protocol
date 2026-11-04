package evidence

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Kind classifies a log record the gate may act on. Classification is
// deterministic and by exact event names (docs/gate-arch.md section 2,
// "Confirmed"). What a kind leads to (deny, escalate, trip) is policy, decided
// in internal/gate/core and breaker, never here. Every kind except Gate can
// only tighten.
type Kind string

const (
	KindDaemonStart         Kind = "daemon_start"          // witness started
	KindDeath               Kind = "death"                 // any DEATH record (signal_received, storage_anomaly...)
	KindDowntime            Kind = "witness_downtime"      // gap at start; Critical when the stop was unrecorded
	KindMirrorUnreachable   Kind = "mirror_unreachable"    // CRITICAL after N failed pushes
	KindMirrorNotConfigured Kind = "mirror_not_configured" // CRITICAL in production, WARN in --dev
	KindMirrorMisconfigured Kind = "mirror_misconfigured"
	KindTreeHeadUnsigned    Kind = "tree_head_unsigned"
	KindIntegrityBreach     Kind = "integrity_breach"
	KindDrift               Kind = "drift_detected"
	KindSBHStop             Kind = "sbh_stop_and_ask"
	KindSBHEscalation       Kind = "sbh_escalation"
	KindPipelockBlock       Kind = "pipelock_block"
	KindGate                Kind = "gate"  // the gate's own feed records
	KindFeed                Kind = "feed"  // any other named feed (edges, custom signals)
	KindOther               Kind = "other" // a CRITICAL record of no kind above
)

// Signal is one classified log record. Fields come from the verified log;
// TS is the witness's timestamp inside the record (covered by the Merkle
// root), not the gate's clock.
type Signal struct {
	Seq      uint64
	TS       time.Time
	Level    string
	Source   string
	Event    string
	Kind     Kind
	Critical bool // level CRITICAL, or DEATH
	Data     json.RawMessage
}

// builtinSources are written by the witness and its bridges; records from any
// other source come from a named event feed.
var builtinSources = map[string]bool{
	"witness": true, "witness-init": true, "sbh": true, "farm": true, "pipelock": true,
	"drift": true, "migrate": true, "pd": true, "pd-system": true, "mirror": true,
	"enforcer": true, "anomaly": true, "operator": true,
}

// classify returns the record's kind, or false for a record the gate does not
// keep (routine built-in records: drift_clean, pipelock allow receipts, farm
// readings...). Records from named feeds are always kept: edges and custom
// tightening rules read them.
func classify(e store.Entry) (Kind, bool) {
	critical := e.Level == "CRITICAL" || e.Level == "DEATH"
	switch {
	case e.Source == "gate":
		return KindGate, true
	case e.Level == "DEATH":
		return KindDeath, true
	case e.Source == "witness" && e.Event == "daemon_start":
		return KindDaemonStart, true
	case e.Source == "witness" && e.Event == "witness_downtime":
		return KindDowntime, true
	case e.Source == "witness" && e.Event == "mirror_unreachable":
		return KindMirrorUnreachable, true
	case e.Source == "witness" && e.Event == "mirror_not_configured":
		return KindMirrorNotConfigured, true
	case e.Source == "witness" && e.Event == "mirror_misconfigured":
		return KindMirrorMisconfigured, true
	case e.Event == "tree_head_unsigned":
		return KindTreeHeadUnsigned, true
	case e.Event == "integrity_breach":
		return KindIntegrityBreach, true
	case e.Source == "drift" && e.Event == "drift_detected":
		return KindDrift, true
	case e.Source == "sbh" && e.Event == "sbh_decision:stop_and_ask":
		return KindSBHStop, true
	case e.Source == "sbh" && e.Event == "sbh_escalation":
		return KindSBHEscalation, true
	case e.Source == "pipelock" && pipelockBlocked(e.Data):
		return KindPipelockBlock, true
	case !builtinSources[e.Source]:
		return KindFeed, true
	case critical:
		return KindOther, true
	}
	return "", false
}

// pipelockBlocked reports a blocking verdict in a pipelock record, read with
// the bridge's precedence (internal/pipelock_bridge): the v1 action receipt,
// then the v2 evidence payload, then the older paths. The bridge raises both
// "block" and "warn" verdicts to WARN, so the level alone cannot tell them
// apart; only a block counts here.
func pipelockBlocked(data json.RawMessage) bool {
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	for _, path := range [][]string{
		{"detail", "action_record", "verdict"},
		{"detail", "payload", "verdict"},
		{"detail", "verdict"},
		{"verdict"},
	} {
		if v := nested(m, path); v != "" {
			switch strings.ToLower(v) {
			case "block", "blocked", "deny", "denied":
				return true
			}
			return false
		}
	}
	return false
}

func nested(m map[string]any, path []string) string {
	var cur any = m
	for _, k := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	s, _ := cur.(string)
	return s
}
