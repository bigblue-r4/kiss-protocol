package core

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/breaker"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func signer(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(append(make([]byte, 31), seed))}
}

type fakeEv struct {
	mu   sync.Mutex
	st   evidence.Status
	sigs []evidence.Signal
	seq  uint64
}

func (f *fakeEv) Status() evidence.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}

func (f *fakeEv) Signals(since time.Time, kinds ...evidence.Kind) []evidence.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []evidence.Signal
	for _, s := range f.sigs {
		if !s.TS.Before(since) {
			out = append(out, s)
		}
	}
	return out
}

func (f *fakeEv) add(kind evidence.Kind, ts time.Time, critical bool, data any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	raw, _ := json.Marshal(data)
	f.sigs = append(f.sigs, evidence.Signal{Seq: f.seq, TS: ts, Kind: kind, Critical: critical, Data: raw})
}

func (f *fakeEv) set(mod func(*evidence.Status)) {
	f.mu.Lock()
	mod(&f.st)
	f.mu.Unlock()
}

const testPolicy = `
version = 1
[global]
witness_keys = ["1111111111111111111111111111111111111111111111111111111111111111"]
witness_drift_interval_sec = 30
reset_quorum = 2
budget = { window = "1h", max_value = "100000" }
%s
[classes.manual]
tier = "high"
root = "approval"
approvals_required = 2
targets = ["wallet-svc"]
assets = [%s]
destinations = ["*"]
tighten = { first_seen_edge = "off", sbh = "deny" }

[classes.hot]
tier = "high"
root = "automated_envelope"
approvals_required = 2
targets = ["wallet-svc"]
assets = [%s]
destinations = ["cold"]
max_value = "5000"
budget = { window = "1h", max_value = "1000000" }
inflight = { class = 1000, principal = 1000, origin_host = 1000 }
tighten = { first_seen_edge = "off" }

[classes.low]
tier = "low"
root = "automated_envelope"
targets = ["export-svc"]
destinations = ["bucket"]
fail_mode = "open"
tighten = { first_seen_edge = "off" }

[classes.edgy]
tier = "high"
root = "automated_envelope"
approvals_required = 1
targets = ["svc"]
destinations = ["d"]

[classes.learner]
tier = "low"
root = "automated_envelope"
targets = ["svc"]
destinations = ["d"]
tighten = { edge_mode = "learn" }
`

func policyText(extra string) string {
	var assets, names []string
	for i := 0; i < 10; i++ {
		assets = append(assets, fmt.Sprintf("[assets.A%d]\ndecimals = 2\nref_value = \"1\"", i))
		names = append(names, fmt.Sprintf("%q", fmt.Sprintf("A%d", i)))
	}
	n := strings.Join(names, ", ")
	return fmt.Sprintf(testPolicy, strings.Join(assets, "\n"), n, n) + extra
}

type harness struct {
	t   *testing.T
	c   *Core
	ev  *fakeEv
	br  *breaker.Breaker
	now time.Time
	ops []proto.Operator
	sig []keySigner
	n   int
	mu  sync.Mutex
}

func newHarness(t *testing.T, extra string) *harness {
	t.Helper()
	h := &harness{t: t, now: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), ev: &fakeEv{}}
	for i := byte(1); i <= 3; i++ {
		s := signer(i)
		h.sig = append(h.sig, s)
		h.ops = append(h.ops, proto.Operator{Label: fmt.Sprintf("op%d", i), Key: s.PublicKey()})
	}
	data := []byte(policyText(extra))
	sig, _ := policy.Sign(data, h.sig[0])
	l, err := policy.LoadBytes(data, sig, h.ops)
	if err != nil {
		t.Fatal(err)
	}
	h.ev.st = evidence.Status{Synced: true, HeadAge: time.Second}
	h.br = breaker.New(breaker.Config{})
	h.c = New(Config{Policy: l, Operators: h.ops, Breaker: h.br, Evidence: h.ev, Now: h.clock})
	h.br.Restore(nil, nil, h.ops)
	h.c.Sync()
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *harness) req(class string, mod ...func(*proto.ActionRequest)) proto.ActionRequest {
	h.mu.Lock()
	h.n++
	n := h.n
	h.mu.Unlock()
	r := proto.ActionRequest{V: 1, Class: class, Target: "wallet-svc", Asset: "A0", Amount: "100",
		Destination: "cold", RequestNonce: fmt.Sprintf("%032x", n), Principal: "alice", OriginHost: "h1",
		TS: proto.FormatTime(h.clock())}
	switch class {
	case "low":
		r.Target, r.Asset, r.Amount, r.Destination = "export-svc", "", "0", "bucket"
	case "edgy", "learner":
		r.Target, r.Asset, r.Amount, r.Destination = "svc", "", "0", "d"
	}
	for _, m := range mod {
		m(&r)
	}
	return r
}

func (h *harness) approve(r proto.ActionRequest, who ...int) []proto.Approval {
	hash, _ := proto.ActionHashHex(r)
	var out []proto.Approval
	for _, i := range who {
		a, err := proto.SignApproval(proto.Approval{V: 1, ActionHash: hash, ApproverLabel: h.ops[i].Label,
			ExpiresAt: proto.FormatTime(h.clock().Add(5 * time.Minute))}, h.sig[i])
		if err != nil {
			h.t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func want(t *testing.T, d Decision, o Outcome, r ...Reason) {
	t.Helper()
	if d.Outcome != o {
		t.Fatalf("outcome %s %v (%s), want %s %v", d.Outcome, d.Reasons, d.Detail, o, r)
	}
	for i, x := range r {
		if i >= len(d.Reasons) || d.Reasons[i] != x {
			t.Fatalf("reasons %v (%s), want %v", d.Reasons, d.Detail, r)
		}
	}
	if (o == Allow) != (d.Res != nil) {
		t.Fatalf("reservation %v on %s", d.Res, o)
	}
}

func scopeOf(evs []breaker.Event) []string {
	var s []string
	for _, e := range evs {
		s = append(s, e.Scope.String())
	}
	return s
}

func TestNotSyncedAndDenyAll(t *testing.T) {
	h := newHarness(t, "")
	ev := &fakeEv{st: evidence.Status{Synced: true}}
	br := breaker.New(breaker.Config{})
	c := New(Config{Policy: nil, Breaker: br, Evidence: ev, Now: h.clock})
	// Acceptance 11: no valid signed policy -> deny-all, even when synced.
	want(t, c.Decide(h.req("hot"), nil), Deny, PolicyInvalid)

	c2 := New(Config{Policy: h.c.pol, Operators: h.ops, Breaker: br, Evidence: ev, Now: h.clock})
	want(t, c2.Decide(h.req("hot"), nil), Deny, GateNotSynced) // Sync not run
	c2.Sync()
	want(t, c2.Decide(h.req("hot"), nil), Deny, GateNotSynced) // breaker not restored
	br.Restore(nil, nil, h.ops)
	want(t, c2.Decide(h.req("hot"), nil), Allow)
	ev.set(func(s *evidence.Status) { s.Synced = false })
	want(t, c2.Decide(h.req("hot"), nil), Deny, GateNotSynced)

	h.c.SetPolicy(nil)
	want(t, h.c.Decide(h.req("hot"), nil), Deny, PolicyInvalid)
}

// Acceptance 1 and 4.
func TestManualClassRoots(t *testing.T) {
	h := newHarness(t, "")
	r := h.req("manual")
	want(t, h.c.Decide(r, nil), Escalate, NoRoot)
	want(t, h.c.Decide(r, h.approve(r, 0)), Escalate, NoRoot) // 1 of 2
	want(t, h.c.Decide(r, append(h.approve(r, 0), h.approve(r, 0)...)), Escalate, NoRoot)

	// Forged: right label, wrong key.
	forged := h.approve(r, 0)
	forged[0], _ = proto.SignApproval(proto.Approval{V: 1, ActionHash: forged[0].ActionHash, ApproverLabel: "op2",
		ExpiresAt: forged[0].ExpiresAt}, signer(99))
	want(t, h.c.Decide(r, append(h.approve(r, 0), forged...)), Deny, ApprovalInvalid)
	// Approvals for a different request (amount changed after signing).
	other := r
	other.Amount = "4999"
	want(t, h.c.Decide(other, h.approve(r, 0, 1)), Deny, ApprovalInvalid)
	// Expired.
	old := h.approve(r, 0, 1)
	h.advance(6 * time.Minute) // approvals last 5m; ts skew is checked first, so widen it
	h.c.mu.Lock()
	h.c.pol.Policy.Global.RequestMaxSkew.Duration = 10 * time.Minute
	h.c.mu.Unlock()
	want(t, h.c.Decide(r, old), Deny, ApprovalExpired)

	r3 := h.req("manual")
	d := h.c.Decide(r3, h.approve(r3, 0, 2))
	want(t, d, Allow)
	if len(d.Approvers) != 2 || d.Res.PolicyHash != h.c.pol.Hash {
		t.Fatalf("approvers %v", d.Approvers)
	}
}

func TestEnvelope(t *testing.T) {
	h := newHarness(t, "")
	for name, m := range map[string]func(*proto.ActionRequest){
		"target":      func(r *proto.ActionRequest) { r.Target = "other-svc" },
		"destination": func(r *proto.ActionRequest) { r.Destination = "attacker" },
		"over max":    func(r *proto.ActionRequest) { r.Amount = "5000.01" },
		"asset":       func(r *proto.ActionRequest) { r.Asset = "DOGE" },
		"class":       func(r *proto.ActionRequest) { r.Class = "nope" },
		"precision":   func(r *proto.ActionRequest) { r.Amount = "1.001" },
	} {
		d := h.c.Decide(h.req("hot", m), nil)
		if d.Outcome != Deny || d.Reasons[0] != OutsideEnvelope {
			t.Errorf("%s: %s %v", name, d.Outcome, d.Reasons)
		}
	}
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Amount = "5000" }), nil), Allow)
}

// Acceptance 2: an in-envelope burst across 10 assets is capped by the
// global value budget, the class trips, and every later request is
// BREAKER_OPEN.
func TestBurstCappedByGlobalBudget(t *testing.T) {
	h := newHarness(t, "")
	released := new(big.Rat)
	var trips []breaker.Event
	for i := 0; i < 100; i++ {
		r := h.req("hot", func(r *proto.ActionRequest) {
			r.Asset, r.Amount, r.Principal = fmt.Sprintf("A%d", i%10), "5000", fmt.Sprintf("p%d", i)
		})
		d := h.c.Decide(r, nil)
		trips = append(trips, d.Events...)
		if d.Outcome == Allow {
			released.Add(released, big.NewRat(5000, 1))
			h.c.Release(d.Res, true)
		}
		h.advance(10 * time.Millisecond)
	}
	if released.Cmp(big.NewRat(100000, 1)) > 0 {
		t.Fatalf("released %s > global budget 100000", released.FloatString(0))
	}
	if released.Cmp(big.NewRat(100000, 1)) != 0 {
		t.Fatalf("released %s; the budget should be usable up to its cap", released.FloatString(0))
	}
	// All-or-none: the class bucket was checked before the global one
	// failed, and must not have been debited by the refused requests.
	h.c.mu.Lock()
	classTotal := new(big.Rat).Set(h.c.buckets["class/hot"].total)
	h.c.mu.Unlock()
	if classTotal.Cmp(released) != 0 {
		t.Fatalf("class bucket %s != released %s: a refused request debited it", classTotal.FloatString(0), released.FloatString(0))
	}
	if len(trips) != 1 || trips[0].Scope.String() != "class:hot" || trips[0].Trigger != "velocity_exceeded" {
		t.Fatalf("trips %v", scopeOf(trips))
	}
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Amount = "1" }), nil), Deny, BreakerOpen)
	// Other classes still work: the trip is the class, not Global.
	want(t, h.c.Decide(h.req("low"), nil), Allow)
}

// Acceptance 3: drift on the gate (= signer) host trips its classes before
// any further token.
func TestDriftTripsHostClasses(t *testing.T) {
	h := newHarness(t, "")
	h.ev.add(evidence.KindDrift, h.clock(), false, nil)
	evs := h.c.Sync()
	if len(evs) != 5 {
		t.Fatalf("drift should trip every class, got %v", scopeOf(evs))
	}
	for _, c := range []string{"hot", "manual", "low", "edgy", "learner"} {
		d := h.c.Decide(h.req(c), nil)
		want(t, d, Deny, BreakerOpen)
	}
	// With the trigger disabled, drift still tightens (deny by default).
	h2 := newHarness(t, "[breaker.triggers]\ndrift_detected = 0\n")
	h2.ev.add(evidence.KindDrift, h2.clock(), false, nil)
	if evs := h2.c.Sync(); len(evs) != 0 {
		t.Fatalf("disabled trigger tripped %v", scopeOf(evs))
	}
	want(t, h2.c.Decide(h2.req("hot"), nil), Deny, DriftOnHost)
	h2.advance(61 * time.Minute)
	want(t, h2.c.Decide(h2.req("hot"), nil), Allow) // outside the 1h lookback
}

// Acceptance 8.
func TestHeadStale(t *testing.T) {
	h := newHarness(t, "")
	h.ev.set(func(s *evidence.Status) { s.HeadAge = 61 * time.Second })
	want(t, h.c.Decide(h.req("hot"), nil), Deny, EvidenceUnhealthy)
	d := h.c.Decide(h.req("low"), nil)
	want(t, d, Allow)
	if len(d.Warnings) != 1 || d.Warnings[0] != EvidenceUnhealthy {
		t.Fatalf("fail-open low tier must carry the warning: %v", d.Warnings)
	}
}

// Acceptance 9.
func TestCriticalEvidence(t *testing.T) {
	h := newHarness(t, "[breaker.triggers]\nwitness_downtime = 0\nmirror_unreachable = 0\n")
	h.ev.add(evidence.KindDowntime, h.clock(), false, nil) // clean stop: not critical
	h.c.Sync()
	want(t, h.c.Decide(h.req("hot"), nil), Allow)
	h.ev.add(evidence.KindDowntime, h.clock(), true, nil)
	h.c.Sync()
	want(t, h.c.Decide(h.req("hot"), nil), Deny, EvidenceUnhealthy)

	h2 := newHarness(t, "[breaker.triggers]\nmirror_unreachable = 0\n")
	h2.ev.add(evidence.KindMirrorUnreachable, h2.clock(), true, nil)
	h2.c.Sync()
	want(t, h2.c.Decide(h2.req("hot"), nil), Deny, AnchorStale)

	// Default weights: the configured trip.
	h3 := newHarness(t, "")
	h3.ev.add(evidence.KindDowntime, h3.clock(), true, nil)
	if evs := h3.c.Sync(); len(evs) != 5 {
		t.Fatalf("downtime trips %v", scopeOf(evs))
	}
	want(t, h3.c.Decide(h3.req("hot"), nil), Deny, BreakerOpen)
}

// Acceptance 10: advisory signals tighten; nothing advisory can allow.
func TestAdvisorySignals(t *testing.T) {
	h := newHarness(t, "")
	h.ev.add(evidence.KindSBHStop, h.clock(), false, map[string]any{"detail": map[string]any{"agent": "alice"}})
	// An advisory "allow" from a feed record: classified as a plain feed
	// record and ignored by the decision.
	h.ev.add(evidence.KindFeed, h.clock(), false, map[string]any{"decision": "allow", "principal": "alice"})
	h.c.Sync()
	r := h.req("hot")
	want(t, h.c.Decide(r, nil), Escalate, AdvisoryDeny) // hot: sbh = escalate (default)
	want(t, h.c.Decide(r, h.approve(r, 1, 2)), Allow)   // two operators satisfy the escalation
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Principal = "bob" }), nil), Allow)
	m := h.req("manual")
	want(t, h.c.Decide(m, h.approve(m, 0, 1)), Deny, AdvisoryDeny) // manual: sbh = deny

	// Unattributed records apply to every principal on the host.
	h.ev.add(evidence.KindPipelockBlock, h.clock(), false, map[string]any{"verdict": "block"})
	h.c.Sync()
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Principal = "bob" }), nil), Escalate, AdvisoryDeny)
}

func TestChainFailureTripsGlobal(t *testing.T) {
	h := newHarness(t, "")
	h.ev.set(func(s *evidence.Status) {
		s.Failure = &evidence.ChainError{Reason: "head signed by an unpinned key"}
		s.Synced = false
	})
	evs := h.c.Sync()
	if len(evs) != 1 || evs[0].Scope.Kind != proto.ScopeGlobal {
		t.Fatalf("trips %v", scopeOf(evs))
	}
	want(t, h.c.Decide(h.req("low"), nil), Deny, ChainUnverified)
	if !h.br.IsOpen(proto.Scope{Kind: proto.ScopeGlobal}) {
		t.Fatal("global must be open")
	}
}

func TestReplayAndSkew(t *testing.T) {
	h := newHarness(t, "")
	r := h.req("hot")
	d := h.c.Decide(r, nil)
	want(t, d, Allow)
	want(t, h.c.Decide(r, nil), Deny, RequestReplayed) // pending
	h.c.Release(d.Res, false)
	d = h.c.Decide(r, nil) // refunded: may be decided again
	want(t, d, Allow)
	h.c.Release(d.Res, true)
	want(t, h.c.Decide(r, nil), Deny, RequestReplayed) // issued
	h.c.Release(d.Res, true)                           // double release is a no-op

	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) {
		r.TS = proto.FormatTime(h.clock().Add(-6 * time.Minute))
	}), nil), Deny, RequestInvalid)
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.V = 2 }), nil), Deny, RequestInvalid)
}

// Acceptance 18: 200 concurrent in-envelope requests never reserve more than
// the budget. Run with -race.
func TestConcurrentReservationsNeverExceedBudget(t *testing.T) {
	h := newHarness(t, "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := new(big.Rat)
	allowed := 0
	for i := 0; i < 200; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := h.req("hot", func(r *proto.ActionRequest) {
				r.Asset, r.Amount, r.Principal = fmt.Sprintf("A%d", i%10), "1000", fmt.Sprintf("p%d", i%7)
			})
			d := h.c.Decide(r, nil)
			if d.Outcome != Allow {
				return
			}
			mu.Lock()
			total.Add(total, big.NewRat(1000, 1))
			allowed++
			mu.Unlock()
			if i%3 == 0 {
				h.c.Release(d.Res, false) // refunds race with reservations
				mu.Lock()
				total.Sub(total, big.NewRat(1000, 1))
				mu.Unlock()
			} else {
				h.c.Release(d.Res, true)
			}
		}()
	}
	wg.Wait()
	if total.Cmp(big.NewRat(100000, 1)) > 0 {
		t.Fatalf("issued %s > 100000", total.FloatString(0))
	}
	h.c.mu.Lock()
	g := h.c.buckets["global"].total
	h.c.mu.Unlock()
	if g.Cmp(total) != 0 {
		t.Fatalf("global bucket %s != issued %s: a refund or debit was lost", g.FloatString(0), total.FloatString(0))
	}
	if h.c.Pending() != 0 {
		t.Fatalf("%d reservations leaked", h.c.Pending())
	}
}

// Acceptance 19: the breaker trips during a pending commit-wait; the request
// is denied at re-validation and its budget refunded.
func TestRevalidation(t *testing.T) {
	h := newHarness(t, "")
	ok := h.c.Decide(h.req("hot"), nil)
	want(t, ok, Allow)
	if d := h.c.Revalidate(ok.Res); d.Outcome != Allow {
		t.Fatalf("unchanged view must revalidate: %v", d.Reasons)
	}
	h.c.Release(ok.Res, true)

	d := h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Amount = "4000" }), nil)
	want(t, d, Allow)
	h.ev.add(evidence.KindDrift, h.clock(), false, nil) // arrives during the wait
	h.c.Sync()
	rv := h.c.Revalidate(d.Res)
	want(t, rv, Deny, RevalidationFailed, BreakerOpen)
	h.c.mu.Lock()
	g := h.c.buckets["global"].total.FloatString(0)
	h.c.mu.Unlock()
	if g != "100" {
		t.Fatalf("global bucket %s after refund, want only the first request's 100", g)
	}
	if h.c.Pending() != 0 {
		t.Fatal("reservation not released")
	}
	h.c.Release(d.Res, true) // a late release after revalidation must not resurrect it
	if again := h.c.Revalidate(d.Res); again.Outcome != Deny {
		t.Fatal("revalidating a released reservation must deny")
	}
}

// Acceptance 22: a pending-queue flood gets INFLIGHT_LIMIT for the excess,
// the flooding principal trips, and other principals are unaffected.
func TestInflightFlood(t *testing.T) {
	h := newHarness(t, "")
	h.c.mu.Lock()
	cl := h.c.pol.Policy.Classes["hot"]
	cl.Inflight = policy.Inflight{Class: 100, Principal: 2, OriginHost: 50}
	h.c.pol.Policy.Classes["hot"] = cl
	h.c.mu.Unlock()
	allowed, limited := 0, 0
	var trips []breaker.Event
	var last Decision
	for i := 0; i < 20; i++ {
		last = h.c.Decide(h.req("hot", func(r *proto.ActionRequest) {
			r.Principal, r.OriginHost, r.Amount = "mallory", "evil", "1"
		}), nil)
		trips = append(trips, last.Events...)
		switch {
		case last.Outcome == Allow:
			allowed++ // left pending: the flood never completes
		case last.Reasons[0] == InflightLimit:
			limited++
		}
	}
	if allowed != 2 || limited == 0 {
		t.Fatalf("allowed %d limited %d, want the cap (2) then INFLIGHT_LIMIT", allowed, limited)
	}
	if len(trips) == 0 || trips[0].Scope.String() != "principal:mallory" {
		t.Fatalf("flooding principal should trip first, got %v", scopeOf(trips))
	}
	for _, e := range trips {
		if e.Scope.Kind == proto.ScopeClass || e.Scope.Kind == proto.ScopeGlobal {
			t.Fatalf("a flood must not trip %s", e.Scope)
		}
	}
	want(t, last, Deny, BreakerOpen)
	want(t, h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Principal, r.OriginHost = "bob", "h2" }), nil), Allow)
}

func TestCommitWaitTimeouts(t *testing.T) {
	h := newHarness(t, "")
	var evs []breaker.Event
	for i := 0; i < 3; i++ {
		// After two timeouts (weight 8 >= escalate_at 6) the class needs
		// approvals: the breaker's escalate level is a tightening signal.
		r := h.req("hot")
		d := h.c.Decide(r, h.approve(r, 0, 1))
		want(t, d, Allow)
		evs = append(evs, h.c.CommitWaitTimeout(d.Res)...)
		if h.c.CommitWaitTimeout(d.Res) != nil {
			t.Fatal("second timeout on one reservation must be a no-op")
		}
	}
	if len(evs) != 1 || evs[0].Scope.String() != "class:hot" || evs[0].Trigger != "commit_wait_timeout" {
		t.Fatalf("3 timeouts x weight 4 should trip the class once: %v", scopeOf(evs))
	}
	h.c.mu.Lock()
	g := h.c.buckets["global"].total.Sign()
	h.c.mu.Unlock()
	if g != 0 {
		t.Fatal("timeouts must refund")
	}
}

func TestFirstSeenEdge(t *testing.T) {
	h := newHarness(t, "")
	r := h.req("edgy")
	want(t, h.c.Decide(r, nil), Escalate, FirstSeenEdge)
	d := h.c.Decide(r, h.approve(r, 2))
	want(t, d, Allow)
	h.c.Release(d.Res, false)
	want(t, h.c.Decide(h.req("edgy"), nil), Escalate, FirstSeenEdge) // refunded: not learned
	d = h.c.Decide(r, h.approve(r, 2))
	h.c.Release(d.Res, true)
	want(t, h.c.Decide(h.req("edgy"), nil), Allow) // learned from the issued token
	want(t, h.c.Decide(h.req("edgy", func(r *proto.ActionRequest) { r.OriginHost = "laptop" }), nil), Escalate, FirstSeenEdge)

	l := h.c.Decide(h.req("learner", func(r *proto.ActionRequest) { r.Principal = "zed" }), nil)
	want(t, l, Allow)
	if len(l.Learned) != 1 || l.Learned[0] != "principal:zed->svc" {
		t.Fatalf("learn mode must report what it learned: %v", l.Learned)
	}
}

func TestBreakerEscalateLevelAndDenyTicks(t *testing.T) {
	h := newHarness(t, "")
	bad := func() Decision {
		return h.c.Decide(h.req("hot", func(r *proto.ActionRequest) { r.Destination = "attacker" }), nil)
	}
	for i := 0; i < 6; i++ {
		want(t, bad(), Deny, OutsideEnvelope)
	}
	r := h.req("hot")
	want(t, h.c.Decide(r, nil), Escalate, BreakerEscalate)
	want(t, h.c.Decide(r, h.approve(r, 0, 1)), Allow)
	var trips []breaker.Event
	for i := 0; i < 4; i++ {
		trips = append(trips, bad().Events...)
	}
	if got := scopeOf(trips); len(got) != 2 || got[0] != "principal:alice" || got[1] != "origin_host:h1" {
		t.Fatalf("10 denies should trip principal and origin host: %v", got)
	}
}

// A restart replays up to a day of signals: old ones must not tick, and ones
// a quorum already reset must not re-trip.
func TestReplayedSignalsDoNotRetrip(t *testing.T) {
	h := newHarness(t, "")
	h.ev.add(evidence.KindDrift, h.clock().Add(-2*time.Hour), false, nil)
	if evs := h.c.Sync(); len(evs) != 0 {
		t.Fatalf("a 2h-old drift must not trip: %v", scopeOf(evs))
	}
	want(t, h.c.Decide(h.req("hot"), nil), Allow)

	h = newHarness(t, "")
	drift := h.clock().Add(-30 * time.Minute)
	r := proto.Reset{V: 1, Scope: proto.Scope{Kind: proto.ScopeClass, Value: "hot"}, NewEpoch: 2, Reason: "reviewed drift",
		Nonce: strings.Repeat("ab", 16), TS: proto.FormatTime(drift)}
	b := proto.ResetBundle{Reset: r}
	for i := 0; i < 2; i++ {
		p, _ := proto.SignReset(r, h.ops[i].Label, h.sig[i])
		b.Partials = append(b.Partials, p)
	}
	h.br.Restore([]breaker.Event{
		{Type: breaker.EventTrip, Scope: r.Scope, Epoch: 1, TS: drift},
		{Type: breaker.EventReset, Scope: r.Scope, Epoch: 2, Bundle: &b, TS: drift.Add(10 * time.Minute)},
	}, nil, h.ops)
	h.ev.add(evidence.KindDrift, drift, false, nil)
	evs := h.c.Sync()
	for _, e := range evs {
		if e.Scope.Value == "hot" {
			t.Fatal("a drift the quorum already reset must not re-trip hot")
		}
	}
	if len(evs) != 4 {
		t.Fatalf("the other classes never saw a reset and should trip: %v", scopeOf(evs))
	}
	want(t, h.c.Decide(h.req("hot"), nil), Allow) // acknowledged, so no DRIFT_ON_HOST either
}

func TestWitnessDeathWithoutRestart(t *testing.T) {
	h := newHarness(t, "")
	h.ev.add(evidence.KindDeath, h.clock(), true, nil)
	if evs := h.c.Sync(); len(evs) != 0 {
		t.Fatal("death trips only after the restart grace")
	}
	h.advance(61 * time.Second)
	if evs := h.c.Sync(); len(evs) != 5 {
		t.Fatalf("death without restart: %v", scopeOf(evs))
	}

	h = newHarness(t, "")
	h.ev.add(evidence.KindDeath, h.clock(), true, nil)
	h.ev.add(evidence.KindDaemonStart, h.clock().Add(5*time.Second), false, nil)
	h.advance(2 * time.Minute)
	if evs := h.c.Sync(); len(evs) != 0 {
		t.Fatalf("a restarted witness must not trip: %v", scopeOf(evs))
	}
}

func TestSignalsBehindCursorStillSeen(t *testing.T) {
	h := newHarness(t, "[breaker.triggers]\ndrift_detected = 0\n")
	h.ev.add(evidence.KindDaemonStart, h.clock(), false, nil)
	h.c.Sync()
	// The witness clock stepped back 5 minutes: same Seq order, earlier TS.
	h.ev.add(evidence.KindDrift, h.clock().Add(-5*time.Minute), false, nil)
	h.c.Sync()
	want(t, h.c.Decide(h.req("hot"), nil), Deny, DriftOnHost)
}

func TestReasonCodesStable(t *testing.T) {
	all := []Reason{GateNotSynced, BreakerOpen, NoRoot, ApprovalInvalid, ApprovalExpired, OutsideEnvelope,
		EvidenceUnhealthy, ChainUnverified, AnchorStale, DriftOnHost, AdvisoryDeny, FirstSeenEdge,
		VelocityExceeded, CommitWaitTimeout, FeedWriteFailed, PolicyInvalid, InflightLimit, RevalidationFailed,
		RequestInvalid, RequestReplayed, BreakerEscalate}
	seen := map[Reason]bool{}
	for _, r := range all {
		if seen[r] || strings.ToUpper(string(r)) != string(r) {
			t.Fatalf("reason %s duplicated or not upper case", r)
		}
		seen[r] = true
	}
	if len(all) != 21 {
		t.Fatal("update the enum documentation in gate-arch.md section 6")
	}
}
