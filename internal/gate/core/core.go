// Package core is the gate's decision logic (gate-arch.md section 6): roots,
// evidence health, tightening signals, edges, in-flight caps, atomic budget
// reservations and reason codes. It is deterministic and does no I/O; the
// daemon (cmd/gate) owns the socket, the feed, signing and commit-wait.
//
// No input from a feed can produce an Allow. Feeds reach this package only
// as evidence.Signals, and every path they take ends in deny, escalate or a
// breaker tick.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/breaker"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// Outcome of a decision.
type Outcome string

const (
	Allow    Outcome = "allow"
	Deny     Outcome = "deny"
	Escalate Outcome = "escalate" // valid operator approvals would change the answer
)

// Reason is a stable reason code.
type Reason string

// Reason codes. The first eighteen are the brief's; the last three are added
// by gate-arch.md C19–C21.
const (
	GateNotSynced      Reason = "GATE_NOT_SYNCED"
	BreakerOpen        Reason = "BREAKER_OPEN"
	NoRoot             Reason = "NO_ROOT"
	ApprovalInvalid    Reason = "APPROVAL_INVALID"
	ApprovalExpired    Reason = "APPROVAL_EXPIRED"
	OutsideEnvelope    Reason = "OUTSIDE_ENVELOPE"
	EvidenceUnhealthy  Reason = "EVIDENCE_UNHEALTHY"
	ChainUnverified    Reason = "CHAIN_UNVERIFIED"
	AnchorStale        Reason = "ANCHOR_STALE"
	DriftOnHost        Reason = "DRIFT_ON_HOST"
	AdvisoryDeny       Reason = "ADVISORY_DENY"
	FirstSeenEdge      Reason = "FIRST_SEEN_EDGE"
	VelocityExceeded   Reason = "VELOCITY_EXCEEDED"
	CommitWaitTimeout  Reason = "COMMIT_WAIT_TIMEOUT"
	FeedWriteFailed    Reason = "FEED_WRITE_FAILED"
	PolicyInvalid      Reason = "POLICY_INVALID"
	InflightLimit      Reason = "INFLIGHT_LIMIT"
	RevalidationFailed Reason = "REVALIDATION_FAILED"
	RequestInvalid     Reason = "REQUEST_INVALID"  // C19: malformed, or ts outside request_max_skew
	RequestReplayed    Reason = "REQUEST_REPLAYED" // C20: this action_hash already holds or used a token
	BreakerEscalate    Reason = "BREAKER_ESCALATE" // C21: a covering scope's ticks reached escalate_at
)

// Evidence is the read side of evidence.View the core uses.
type Evidence interface {
	Status() evidence.Status
	Signals(since time.Time, kinds ...evidence.Kind) []evidence.Signal
}

// Config wires a Core.
type Config struct {
	Policy    *policy.Loaded // nil = deny-all (POLICY_INVALID)
	Operators []proto.Operator
	Breaker   *breaker.Breaker
	Evidence  Evidence
	Now       func() time.Time
}

// Decision is the result of Decide or Revalidate.
type Decision struct {
	Outcome    Outcome
	Reasons    []Reason
	Detail     string
	ActionHash string
	Approvers  []string
	Warnings   []Reason        // fail-open (low tier) health failures that were let through
	Learned    []string        // edges learned in learn mode (to be logged)
	Events     []breaker.Event // trips this decision caused; the daemon records them
	Class      policy.Class
	Res        *Reservation // non-nil only on Allow: held until Release
}

// Reservation is an admitted request holding budget and an in-flight slot.
type Reservation struct {
	id         uint64
	Req        proto.ActionRequest
	ActionHash string
	PolicyHash string
	approved   bool
	buckets    []string
	inflight   []string
	done       bool
}

// Core is safe for concurrent use; every decision runs under one lock, which
// is what makes budget reservation atomic (addendum 1).
type Core struct {
	mu  sync.Mutex
	pol *policy.Loaded
	ops []proto.Operator
	br  *breaker.Breaker
	ev  Evidence
	now func() time.Time

	synced     bool
	haveCursor bool
	cursorSeq  uint64
	cursorTS   time.Time

	driftAt   time.Time
	sbhAt     map[string]time.Time // by principal; "" = not attributed (host-wide)
	pipeAt    map[string]time.Time
	healthAt  time.Time
	healthWhy string
	anchorAt  time.Time
	anchor    string
	deathAt   time.Time
	deathHit  bool

	edges    map[string]bool
	buckets  map[string]*bucket
	inflight map[string]int
	used     map[string]time.Time // action_hash -> forget after
	nextID   uint64
	pending  map[uint64]*Reservation
}

// New returns a Core. It reports GATE_NOT_SYNCED until Sync has run with a
// synced evidence view and a restored breaker.
func New(cfg Config) *Core {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	c := &Core{pol: cfg.Policy, ops: cfg.Operators, br: cfg.Breaker, ev: cfg.Evidence, now: now,
		sbhAt: map[string]time.Time{}, pipeAt: map[string]time.Time{}, edges: map[string]bool{},
		buckets: map[string]*bucket{}, inflight: map[string]int{}, used: map[string]time.Time{},
		pending: map[uint64]*Reservation{}}
	if cfg.Policy != nil {
		cfg.Breaker.SetConfig(BreakerConfig(cfg.Policy.Policy))
	}
	return c
}

// BreakerConfig derives the breaker's tick model from a policy.
func BreakerConfig(p *policy.Policy) breaker.Config {
	b := p.Breaker
	return breaker.Config{Window: b.Window.Duration, WarnAt: b.WarnAt, EscalateAt: b.EscalateAt,
		HaltAt: b.HaltAt, Weights: b.Triggers, Quorum: p.Global.ResetQuorum}
}

// SetPolicy swaps the policy (a verified SIGHUP reload) or, with nil, drops
// to deny-all. Admitted reservations keep the policy hash they were decided
// under.
func (c *Core) SetPolicy(l *policy.Loaded) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pol = l
	if l != nil {
		c.br.SetConfig(BreakerConfig(l.Policy))
	}
}

// LearnEdges seeds known edges (the daemon restores them from its records).
func (c *Core) LearnEdges(keys ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		c.edges[k] = true
	}
}

func edgeKeys(r proto.ActionRequest) []string {
	return []string{"origin_host:" + r.OriginHost + "->" + r.Target, "principal:" + r.Principal + "->" + r.Target}
}

func (c *Core) global() proto.Scope { return proto.Scope{Kind: proto.ScopeGlobal} }

// tick records a trigger on a scope and collects any trip.
func (c *Core) tick(evs []breaker.Event, trigger string, s proto.Scope, now time.Time) []breaker.Event {
	if _, ev, err := c.br.Tick(trigger, s, now); err == nil && ev != nil {
		evs = append(evs, *ev)
	}
	return evs
}

// tickClasses ticks trigger on every class: host-level evidence (one witness
// = one host, C7) concerns every class this gate decides for.
func (c *Core) tickClasses(evs []breaker.Event, trigger string, at, now time.Time) []breaker.Event {
	if c.pol == nil {
		return evs
	}
	for _, name := range c.pol.Policy.ClassNames() {
		s := proto.Scope{Kind: proto.ScopeClass, Value: name}
		if !at.After(c.br.AckedAt(s)) {
			continue
		}
		evs = c.tick(evs, trigger, s, now)
	}
	return evs
}

// syncSlack re-reads signals this far behind the cursor's timestamp, so a
// witness clock step backwards cannot hide a record; Seq dedupes.
const syncSlack = time.Hour

// Sync pulls new signals from the evidence view into the core's indexes and
// the breaker, and trips Global on a chain failure. The daemon calls it after
// every evidence poll and records the returned trips.
func (c *Core) Sync() []breaker.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var evs []breaker.Event
	st := c.ev.Status()
	if st.Failure != nil {
		if ev, err := c.br.Trip("chain_unverified", c.global(), st.Failure.Error(), now); err == nil && ev != nil {
			evs = append(evs, *ev)
		}
		return evs
	}
	if !st.Synced {
		return evs
	}
	since := time.Time{}
	if c.haveCursor {
		since = c.cursorTS.Add(-syncSlack)
	}
	for _, s := range c.ev.Signals(since) {
		if c.haveCursor && s.Seq <= c.cursorSeq {
			continue
		}
		c.haveCursor, c.cursorSeq = true, s.Seq
		if s.TS.After(c.cursorTS) {
			c.cursorTS = s.TS
		}
		evs = c.observe(s, now, evs)
	}
	if c.pol != nil && !c.deathAt.IsZero() && !c.deathHit && now.Sub(c.deathAt) > c.pol.Policy.Global.HeadMaxAge.Duration {
		c.deathHit = true
		evs = c.tickClasses(evs, "witness_death", c.deathAt, now)
	}
	for h, until := range c.used {
		if now.After(until) {
			delete(c.used, h)
		}
	}
	c.synced = true
	return evs
}

func later(t *time.Time, u time.Time) bool {
	if u.After(*t) {
		*t = u
		return true
	}
	return false
}

func (c *Core) observe(s evidence.Signal, now time.Time, evs []breaker.Event) []breaker.Event {
	// A signal older than the breaker window still counts for health and
	// tightening (their own windows), but never ticks: replaying a day of log
	// at restart must not re-trip scopes that were already handled.
	fresh := c.pol != nil && now.Sub(s.TS) <= c.pol.Policy.Breaker.Window.Duration
	tickAll := func(trigger string) {
		if fresh {
			evs = c.tickClasses(evs, trigger, s.TS, now)
		}
	}
	switch s.Kind {
	case evidence.KindDrift:
		later(&c.driftAt, s.TS)
		tickAll("drift_detected")
	case evidence.KindSBHStop:
		t := c.sbhAt[principalOf(s)]
		if later(&t, s.TS) {
			c.sbhAt[principalOf(s)] = t
		}
	case evidence.KindSBHEscalation:
		p := principalOf(s)
		t := c.sbhAt[p]
		if later(&t, s.TS) {
			c.sbhAt[p] = t
		}
		if sc := (proto.Scope{Kind: proto.ScopePrincipal, Value: p}); fresh && p != "" && s.TS.After(c.br.AckedAt(sc)) {
			evs = c.tick(evs, "sbh_escalation", sc, now)
		}
	case evidence.KindPipelockBlock:
		p := principalOf(s)
		t := c.pipeAt[p]
		if later(&t, s.TS) {
			c.pipeAt[p] = t
		}
	case evidence.KindDowntime:
		if s.Critical {
			if later(&c.healthAt, s.TS) {
				c.healthWhy = "witness_downtime (unclean stop)"
			}
			tickAll("witness_downtime")
		}
	case evidence.KindMirrorUnreachable:
		if later(&c.anchorAt, s.TS) {
			c.anchor = "mirror_unreachable"
		}
		tickAll("mirror_unreachable")
	case evidence.KindMirrorNotConfigured, evidence.KindMirrorMisconfigured:
		if s.Critical || c.pol != nil && c.pol.Policy.Global.Production {
			if later(&c.anchorAt, s.TS) {
				c.anchor = string(s.Kind)
			}
		}
	case evidence.KindTreeHeadUnsigned:
		// Every head the view accepts is signed by a pinned key, so signing
		// is established; an unsigned head after that is a regression.
		if later(&c.healthAt, s.TS) {
			c.healthWhy = "tree_head_unsigned"
		}
		tickAll("tree_head_unsigned")
	case evidence.KindIntegrityBreach, evidence.KindOther:
		if s.Critical && later(&c.healthAt, s.TS) {
			c.healthWhy = s.Source + " " + s.Event
		}
	case evidence.KindDeath:
		if later(&c.deathAt, s.TS) {
			c.deathHit = false
		}
	case evidence.KindDaemonStart:
		if !c.deathAt.IsZero() && !s.TS.Before(c.deathAt) {
			c.deathAt, c.deathHit = time.Time{}, false
		}
	}
	return evs
}

// principalOf reads the principal an advisory record is about: "principal"
// or "agent" at the top of its data or under "detail". "" means the record
// names nobody, and then it applies to every principal on the host.
func principalOf(s evidence.Signal) string {
	var m map[string]any
	if json.Unmarshal(s.Data, &m) != nil {
		return ""
	}
	for _, obj := range []any{m, m["detail"]} {
		o, ok := obj.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"principal", "agent"} {
			if v, ok := o[k].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

func deny(d *Decision, r Reason, format string, a ...any) Decision {
	d.Outcome = Deny
	d.Reasons = append(d.Reasons, r)
	if format != "" {
		d.Detail = fmt.Sprintf(format, a...)
	}
	return *d
}

// Decide runs steps 1–6. On Allow it returns a Reservation holding budget
// and an in-flight slot; the caller must Release it exactly once (or let
// Revalidate / CommitWaitTimeout do so).
func (c *Core) Decide(req proto.ActionRequest, approvals []proto.Approval) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	d := Decision{Outcome: Deny}
	if c.pol == nil {
		return deny(&d, PolicyInvalid, "no valid signed policy is loaded: deny-all")
	}
	p := c.pol.Policy
	if err := req.Validate(); err != nil {
		return deny(&d, RequestInvalid, "%v", err)
	}
	d.ActionHash, _ = proto.ActionHashHex(req)
	ts, _ := proto.ParseTime(req.TS, "ts")
	if skew := p.Global.RequestMaxSkew.Duration; ts.Before(now.Add(-skew)) || ts.After(now.Add(skew)) {
		return deny(&d, RequestInvalid, "request ts %s is more than %s from the gate clock", req.TS, skew)
	}

	if c.state(&d, req, now) {
		return d
	}
	if _, ok := c.used[d.ActionHash]; ok {
		c.denyTick(&d, req, now)
		return deny(&d, RequestReplayed, "this action_hash already holds or used a token; send a new request_nonce")
	}

	// Step 3: root and envelope.
	cl, ok := p.Classes[req.Class]
	if !ok {
		return deny(&d, OutsideEnvelope, "class %q is not in the policy", req.Class)
	}
	d.Class = cl
	units, ref, err := c.envelope(cl, req)
	if err != nil {
		c.denyTick(&d, req, now)
		return deny(&d, OutsideEnvelope, "%v", err)
	}
	var escalate []Reason
	approved := false
	if len(approvals) > 0 || cl.Root == policy.RootApproval {
		labels, err := proto.VerifyApprovals(approvals, d.ActionHash, c.ops, cl.ApprovalsRequired, now)
		switch {
		case err == nil:
			approved, d.Approvers = true, labels
		case errors.Is(err, proto.ErrTooFewApprovals):
			if cl.Root == policy.RootApproval {
				escalate = append(escalate, NoRoot)
				d.Detail = err.Error()
			}
		case errors.Is(err, proto.ErrApprovalExpired):
			c.denyTick(&d, req, now)
			return deny(&d, ApprovalExpired, "%v", err)
		default:
			c.denyTick(&d, req, now)
			return deny(&d, ApprovalInvalid, "%v", err)
		}
	}

	// Steps 4 and 5.
	if c.health(&d, cl, req, now) {
		return d
	}
	esc, stop := c.tighten(&d, cl, req, now)
	if stop {
		return d
	}
	escalate = append(escalate, esc...)
	// Step 6a: in-flight caps. Checked before answering Escalate, so a
	// flooding caller keeps ticking toward a trip even once its tick level
	// makes every answer an escalation (acceptance 22).
	inf := []struct {
		key string
		cap int
		s   proto.Scope
	}{
		{"class/" + req.Class, cl.Inflight.Class, proto.Scope{Kind: proto.ScopeClass, Value: req.Class}},
		{"principal/" + req.Principal, cl.Inflight.Principal, proto.Scope{Kind: proto.ScopePrincipal, Value: req.Principal}},
		{"origin_host/" + req.OriginHost, cl.Inflight.OriginHost, proto.Scope{Kind: proto.ScopeOriginHost, Value: req.OriginHost}},
	}
	for _, f := range inf {
		if c.inflight[f.key] >= f.cap {
			// Ticks go to the caller, never the class: one flooding
			// principal must not freeze the class for everyone (acceptance 22).
			d.Events = c.tick(d.Events, "inflight_limit", proto.Scope{Kind: proto.ScopePrincipal, Value: req.Principal}, now)
			d.Events = c.tick(d.Events, "inflight_limit", proto.Scope{Kind: proto.ScopeOriginHost, Value: req.OriginHost}, now)
			return deny(&d, InflightLimit, "%s has %d pending (cap %d)", f.key, c.inflight[f.key], f.cap)
		}
	}
	if len(escalate) > 0 && !approved {
		d.Outcome, d.Reasons = Escalate, append(d.Reasons, escalate...)
		return d
	}

	// Step 6b: the atomic reservation.
	keys, failed, err := c.reserve(p, cl, req, units, ref, now)
	if err != nil {
		d.Events = c.tick(d.Events, "velocity_exceeded", failed, now)
		return deny(&d, VelocityExceeded, "%v", err)
	}
	c.nextID++
	res := &Reservation{id: c.nextID, Req: req, ActionHash: d.ActionHash, PolicyHash: c.pol.Hash,
		approved: approved, buckets: keys}
	for _, f := range inf {
		c.inflight[f.key]++
		res.inflight = append(res.inflight, f.key)
	}
	c.pending[res.id] = res
	c.used[d.ActionHash] = ts.Add(p.Global.RequestMaxSkew.Duration)
	d.Outcome, d.Res = Allow, res
	return d
}

// state is steps 1 and 2. It reports true when it decided (deny).
func (c *Core) state(d *Decision, req proto.ActionRequest, now time.Time) bool {
	st := c.ev.Status()
	if st.Failure != nil {
		deny(d, ChainUnverified, "%v", st.Failure)
		return true
	}
	if !st.Synced || !c.synced || !c.br.Restored() {
		deny(d, GateNotSynced, "evidence synced=%v core synced=%v breaker restored=%v", st.Synced, c.synced, c.br.Restored())
		return true
	}
	if s, open := c.br.Open(req); open {
		deny(d, BreakerOpen, "scope %s is open; reset needs operator quorum", s)
		return true
	}
	return false
}

func (c *Core) envelope(cl policy.Class, req proto.ActionRequest) (units, ref *big.Rat, err error) {
	if !contains(cl.Targets, req.Target) {
		return nil, nil, fmt.Errorf("target %q is not allowed for class %s", req.Target, req.Class)
	}
	if req.Asset != "" && !contains(cl.Assets, req.Asset) {
		return nil, nil, fmt.Errorf("asset %q is not allowed for class %s", req.Asset, req.Class)
	}
	if !cl.AllowsDestination(req.Destination) {
		return nil, nil, fmt.Errorf("destination %q is not in class %s's envelope", req.Destination, req.Class)
	}
	units, ref, err = c.pol.Policy.Value(req.Asset, req.Amount)
	if err != nil {
		return nil, nil, err
	}
	if m := cl.MaxValueRat(); m != nil && ref.Cmp(m) > 0 {
		return nil, nil, fmt.Errorf("value %s exceeds class %s max_value %s", ref.FloatString(2), req.Class, cl.MaxValue)
	}
	return units, ref, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (c *Core) denyTick(d *Decision, req proto.ActionRequest, now time.Time) {
	d.Events = c.tick(d.Events, "deny", proto.Scope{Kind: proto.ScopePrincipal, Value: req.Principal}, now)
	d.Events = c.tick(d.Events, "deny", proto.Scope{Kind: proto.ScopeOriginHost, Value: req.OriginHost}, now)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// health is step 4. A low-tier fail-open class records the failure as a
// warning and continues; a chain failure is never fail-open (state()).
func (c *Core) health(d *Decision, cl policy.Class, req proto.ActionRequest, now time.Time) bool {
	g := c.pol.Policy.Global
	since := maxTime(now.Add(-g.CriticalWindow.Duration), c.br.AckTime(req))
	var r Reason
	var why string
	switch age := c.ev.Status().HeadAge; {
	case age > g.HeadMaxAge.Duration:
		r, why = EvidenceUnhealthy, fmt.Sprintf("no new verified witness head for %s (head_max_age %s)", age.Round(time.Second), g.HeadMaxAge.Duration)
	case c.healthAt.After(since):
		r, why = EvidenceUnhealthy, "unacknowledged CRITICAL: "+c.healthWhy
	case c.anchorAt.After(since):
		r, why = AnchorStale, "unacknowledged "+c.anchor
	default:
		return false
	}
	if cl.FailMode == policy.FailOpen {
		d.Warnings = append(d.Warnings, r)
		return false
	}
	deny(d, r, "%s", why)
	return true
}

// tighten is step 5. It returns the escalation reasons, or stop=true after a
// deny. The breaker's escalate level is a tightening signal too.
func (c *Core) tighten(d *Decision, cl policy.Class, req proto.ActionRequest, now time.Time) (esc []Reason, stop bool) {
	t := cl.Tighten
	since := maxTime(now.Add(-t.Lookback.Duration), c.br.AckTime(req))
	apply := func(action string, r Reason, why string) bool {
		switch action {
		case policy.ActionDeny:
			c.denyTick(d, req, now)
			deny(d, r, "%s", why)
			return true
		case policy.ActionEscal:
			esc = append(esc, r)
		}
		return false
	}
	if c.driftAt.After(since) && apply(t.Drift, DriftOnHost, "drift_detected on the gate host") {
		return nil, true
	}
	for _, k := range []string{req.Principal, ""} {
		if c.sbhAt[k].After(since) && apply(t.SBH, AdvisoryDeny, "sbh stop_and_ask/escalation") {
			return nil, true
		}
		if c.pipeAt[k].After(since) && apply(t.Pipelock, AdvisoryDeny, "pipelock block verdict") {
			return nil, true
		}
	}
	if t.FirstSeenEdge != policy.ActionOff {
		var unseen []string
		for _, k := range edgeKeys(req) {
			if !c.edges[k] {
				unseen = append(unseen, k)
			}
		}
		if len(unseen) > 0 {
			if t.EdgeMode == policy.EdgeLearn {
				for _, k := range unseen {
					c.edges[k] = true
				}
				d.Learned = unseen
			} else if apply(t.FirstSeenEdge, FirstSeenEdge, fmt.Sprintf("first-seen edge %v", unseen)) {
				return nil, true
			}
		}
	}
	if c.br.Level(req, now) == breaker.LevelEscalate {
		esc = append(esc, BreakerEscalate)
	}
	return esc, false
}

// Revalidate is addendum 2: after commit-wait, immediately before signing,
// re-run steps 1, 2, 4 and 5 against the current view. On any change the
// reservation is refunded and released, and the decision is a deny with
// REVALIDATION_FAILED plus the reason. The wait doubles as a detection
// window, on purpose.
func (c *Core) Revalidate(res *Reservation) Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	d := Decision{Outcome: Allow, ActionHash: res.ActionHash, Res: res}
	if res.done {
		return deny(&d, RevalidationFailed, "reservation already released")
	}
	fail := func() Decision {
		c.release(res, false)
		d.Res = nil
		d.Reasons = append([]Reason{RevalidationFailed}, d.Reasons...)
		return d
	}
	if c.pol == nil {
		deny(&d, PolicyInvalid, "policy dropped during the wait")
		return fail()
	}
	if c.state(&d, res.Req, now) {
		return fail()
	}
	cl, ok := c.pol.Policy.Classes[res.Req.Class]
	if !ok {
		deny(&d, OutsideEnvelope, "class %q left the policy during the wait", res.Req.Class)
		return fail()
	}
	d.Class = cl
	if c.health(&d, cl, res.Req, now) {
		return fail()
	}
	esc, stop := c.tighten(&d, cl, res.Req, now)
	if stop {
		return fail()
	}
	if len(esc) > 0 && !res.approved {
		deny(&d, esc[0], "a tightening signal arrived during the wait")
		d.Reasons = esc
		return fail()
	}
	d.Outcome = Allow
	return d
}

// Release ends a reservation. issued=true: the token went out, so the
// budget stays spent and the request's edges become known. issued=false
// (deny, feed write failure, cancel): the budget is refunded and the
// action_hash may be decided again. Releasing twice is a no-op.
func (c *Core) Release(res *Reservation, issued bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.release(res, issued)
}

func (c *Core) release(res *Reservation, issued bool) {
	if res == nil || res.done {
		return
	}
	res.done = true
	delete(c.pending, res.id)
	for _, k := range res.inflight {
		if c.inflight[k]--; c.inflight[k] <= 0 {
			delete(c.inflight, k)
		}
	}
	if issued {
		for _, k := range edgeKeys(res.Req) {
			c.edges[k] = true
		}
		return
	}
	for _, k := range res.buckets {
		if b := c.buckets[k]; b != nil {
			b.refund(res.id)
		}
	}
	delete(c.used, res.ActionHash)
}

// CommitWaitTimeout refunds and releases res and ticks commit_wait_timeout
// on its class (addendum 4).
func (c *Core) CommitWaitTimeout(res *Reservation) []breaker.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if res == nil || res.done {
		return nil
	}
	c.release(res, false)
	return c.tick(nil, "commit_wait_timeout", proto.Scope{Kind: proto.ScopeClass, Value: res.Req.Class}, c.now())
}

// Pending returns the number of admitted, unreleased reservations.
func (c *Core) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Edges returns the known edges (for the daemon to persist).
func (c *Core) Edges() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.edges))
	for k := range c.edges {
		out = append(out, k)
	}
	return out
}
