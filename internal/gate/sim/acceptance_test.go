package sim

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/daemon"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/feed"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce"
)

func running(t testing.TB, commit bool, edit func(string) string) *Env {
	t.Helper()
	e := New(t, commit, edit)
	e.Start()
	if s := e.Status(); s.DenyAllReason != "" {
		t.Fatalf("startup: %+v", s)
	}
	return e
}
func refused(t testing.TB, d daemon.Decision, outcome, reason string) {
	t.Helper()
	if d.Outcome != outcome || len(d.Token) != 0 || !contains(d.Reasons, reason) {
		t.Fatalf("want %s/%s, zero tokens: %+v", outcome, reason, d)
	}
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func allowed(t testing.TB, d daemon.Decision) {
	t.Helper()
	if d.Outcome != "allow" || len(d.Token) == 0 {
		t.Fatalf("want token: %+v", d)
	}
}
func noIssued(t testing.TB, e *Env) {
	t.Helper()
	lines, err := feed.Read(e.Path("state/gate.jsonl"))
	e.must(err)
	for _, l := range lines {
		if l["kind"] == "gate_issued" {
			t.Fatal("unexpected issuance", l)
		}
	}
}
func refusalCode(t testing.TB, err error, code string) {
	t.Helper()
	var r *gateenforce.Refusal
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func drift(e *Env) { e.Append("DRIFT", "drift_detected", "drift", nil); e.Gate.Poll() }

func TestAcceptance01ManualWithdrawal(t *testing.T) {
	e := running(t, false, nil)
	refused(t, e.Decide(e.Request("manual", "1")), "escalate", "NO_ROOT")
	noIssued(t, e)
}
func TestAcceptance02TenAssetBurst(t *testing.T) {
	e := running(t, false, nil)
	total := 0
	for i := 0; i < 10; i++ {
		r := e.Request("hot", "10")
		r.Asset = fmt.Sprintf("A%d", i)
		allowed(t, e.Decide(r))
		total += 10
	}
	if total != 100 {
		t.Fatal(total)
	}
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "VELOCITY_EXCEEDED")
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "BREAKER_OPEN")
}
func TestAcceptance03DriftBeforeTokens(t *testing.T) {
	e := running(t, false, nil)
	drift(e)
	s := e.Status()
	for _, c := range []string{"class:hot", "class:manual"} {
		if !contains(s.OpenScopes, c) {
			t.Fatalf("missing %s: %+v", c, s)
		}
	}
	for _, c := range []string{"hot", "manual"} {
		refused(t, e.Decide(e.Request(c, "1")), "deny", "BREAKER_OPEN")
	}
	noIssued(t, e)
}
func TestAcceptance04BadApprovals(t *testing.T) {
	for _, kind := range []string{"forged", "tampered", "expired"} {
		t.Run(kind, func(t *testing.T) {
			e := running(t, false, nil)
			r := e.Request("manual", "1")
			apps := e.Approve(r, 0, 1)
			reason := "APPROVAL_INVALID"
			switch kind {
			case "forged":
				a, err := proto.SignApproval(apps[0], key(99))
				e.must(err)
				apps[0] = a
			case "tampered":
				apps[0].ActionHash = strings.Repeat("a", 64)
			case "expired":
				apps[0].ExpiresAt = proto.FormatTime(e.Now().Add(-time.Minute))
				a, err := proto.SignApproval(apps[0], e.Ops[0])
				e.must(err)
				apps[0] = a
				reason = "APPROVAL_EXPIRED"
			}
			refused(t, e.Decide(r, apps...), "deny", reason)
			noIssued(t, e)
		})
	}
}
func TestAcceptance05ReplayAndDifferentAmount(t *testing.T) {
	e := running(t, false, nil)
	r := e.Request("hot", "1")
	d := e.Decide(r)
	allowed(t, d)
	v := e.Verifier(e.Now)
	other := r
	other.Amount = "2"
	_, err := v.Check(other, d.Token, gateenforce.Options{HighTier: true})
	refusalCode(t, err, gateenforce.ActionMismatch)
	_, err = v.Check(r, d.Token, gateenforce.Options{HighTier: true})
	e.must(err)
	_, err = v.Check(r, d.Token, gateenforce.Options{HighTier: true})
	refusalCode(t, err, gateenforce.TokenReplayed)
}
func TestAcceptance08StaleHead(t *testing.T) {
	e := running(t, false, nil)
	e.Advance(61 * time.Second)
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "EVIDENCE_UNHEALTHY")
	noIssued(t, e)
}
func TestAcceptance09CriticalDowntime(t *testing.T) {
	e := running(t, false, func(p string) string { return p + "\n[breaker.triggers]\nwitness_downtime = 0\n" })
	e.Append("CRITICAL", "witness_downtime", "witness", map[string]any{"clean_stop": false})
	e.Gate.Poll()
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "EVIDENCE_UNHEALTHY")
	noIssued(t, e)
}
func TestAcceptance10SBHStopAndAsk(t *testing.T) {
	e := running(t, false, nil)
	e.Append("WARN", "sbh_decision:stop_and_ask", "sbh", map[string]string{"principal": "payouts"})
	e.Gate.Poll()
	refused(t, e.Decide(e.Request("hot", "1")), "escalate", "ADVISORY_DENY")
	noIssued(t, e)
}
func TestAcceptance11UnsignedPolicy(t *testing.T) {
	e := New(t, false, nil)
	e.must(os.Remove(e.Path("policy.sig")))
	e.Start()
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "POLICY_INVALID")
	noIssued(t, e)
}
func TestAcceptance12QuorumReset(t *testing.T) {
	e := running(t, false, nil)
	drift(e)
	e.Advance(time.Second) // reset follows the witnessed signal, including on the injected clock
	reset := proto.Reset{V: 1, Scope: proto.Scope{Kind: proto.ScopeClass, Value: "hot"}, NewEpoch: e.Status().Epoch + 1, Nonce: strings.Repeat("1", 32), TS: proto.FormatTime(e.Now()), Reason: "reviewed"}
	bundle := func(who ...int) proto.ResetBundle {
		b := proto.ResetBundle{Reset: reset}
		for _, i := range who {
			p, err := proto.SignReset(reset, fmt.Sprintf("op%d", i+1), e.Ops[i])
			e.must(err)
			b.Partials = append(b.Partials, p)
		}
		return b
	}
	for i, c := range []struct {
		b      proto.ResetBundle
		status int
	}{{bundle(0), 409}, {bundle(0, 2), 200}, {bundle(0, 2), 409}} {
		if got := e.Call("POST", "/v1/reset", c.b, nil); got != c.status {
			t.Fatalf("reset %d HTTP %d want %d", i, got, c.status)
		}
	}
	s := e.Status()
	if contains(s.OpenScopes, "class:hot") || !contains(s.OpenScopes, "class:manual") {
		t.Fatalf("reset scopes %+v", s)
	}
	allowed(t, e.Decide(e.Request("hot", "1")))
}
func TestAcceptance13StaleOrForgedEpoch(t *testing.T) {
	e := running(t, false, nil)
	r := e.Request("hot", "1")
	d := e.Decide(r)
	allowed(t, d)
	v := e.Verifier(e.Now)
	e.Advance(13 * time.Second)
	_, err := v.Check(r, d.Token, gateenforce.Options{HighTier: true})
	refusalCode(t, err, gateenforce.EpochStale)
	e.Gate.Poll()
	raw := e.Epoch()
	ep, err := proto.DecodeEpoch(raw)
	e.must(err)
	ep, err = proto.SignEpoch(ep, key(99))
	e.must(err)
	forged, err := proto.Canonical(ep)
	e.must(err)
	if err := v.UpdateEpoch(forged); err == nil {
		t.Fatal("forged epoch accepted")
	}
	old := raw
	drift(e)
	e.must(v.UpdateEpoch(e.Epoch()))
	if err := v.UpdateEpoch(old); err == nil {
		t.Fatal("older epoch accepted")
	}
}
func TestAcceptance14RestartStaysTripped(t *testing.T) {
	e := running(t, false, nil)
	// Stop delivery so the budget trip exists only in the local gate feed.
	// A fresh daemon cannot infer this trip again from witness signals.
	e.bridge.Stop()
	e.bridge = nil
	allowed(t, e.Decide(e.Request("hot", "100")))
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "VELOCITY_EXCEEDED")
	epoch := e.Status().Epoch
	e.Stop()
	e.Start()
	s := e.Status()
	if len(s.OpenScopes) != 1 || !contains(s.OpenScopes, "class:hot") || s.Epoch < epoch {
		t.Fatalf("restart %+v", s)
	}
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "BREAKER_OPEN")
}
func TestAcceptance15UnwritableFeed(t *testing.T) {
	e := New(t, false, nil)
	e.bridge.Stop()
	e.bridge = nil
	e.must(os.Remove(e.Path("state/gate.jsonl")))
	e.must(os.Mkdir(e.Path("state/gate.jsonl"), 0700))
	e.Start()
	r := e.Request("manual", "1")
	refused(t, e.Decide(r, e.Approve(r, 0, 1)...), "deny", "FEED_WRITE_FAILED")
}

// complete drives exactly one poll after the real bridge has committed the
// request. No daemon background polling can change the ordering.
func complete(e *Env, r proto.ActionRequest, beforePoll func()) daemon.Decision {
	done := make(chan daemon.Decision, 1)
	go func() { done <- e.Decide(r) }()
	e.Wait("request witnessed", func() bool { return e.Witnessed(r) })
	if beforePoll != nil {
		beforePoll()
	}
	e.Gate.Poll()
	select {
	case d := <-done:
		return d
	case <-time.After(15 * time.Second):
		e.T.Fatal("decision blocked")
		return daemon.Decision{}
	}
}
func TestAcceptance16CommitProofAndForgedHead(t *testing.T) {
	e := running(t, true, nil)
	r := e.Request("hot", "1")
	d := complete(e, r, nil)
	allowed(t, d)
	v := e.Verifier(e.Now)
	tok, err := v.Check(r, d.Token, gateenforce.Options{HighTier: true, CommitWait: true})
	e.must(err)
	if tok.Witnessed == nil {
		t.Fatal("missing proof")
	}
	tok.Witnessed.Head.Root = strings.Repeat("0", 64)
	tok, err = proto.SignToken(tok, e.GateKey)
	e.must(err)
	raw, err := proto.Canonical(tok)
	e.must(err)
	_, err = e.Verifier(e.Now).Check(r, raw, gateenforce.Options{HighTier: true, CommitWait: true})
	refusalCode(t, err, gateenforce.CommitWaitInvalid)
}
func TestAcceptance18ConcurrentBudget(t *testing.T) {
	e := running(t, false, nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	out := make(chan daemon.Decision, 200)
	for i := 0; i < 200; i++ {
		r := e.Request("hot", "1")
		r.Principal = fmt.Sprintf("p%d", i)
		r.OriginHost = fmt.Sprintf("h%d", i)
		wg.Add(1)
		go func() { defer wg.Done(); <-start; out <- e.Decide(r) }()
	}
	close(start)
	wg.Wait()
	close(out)
	n := 0
	for d := range out {
		if d.Outcome == "allow" {
			allowed(t, d)
			n++
		} else {
			refused(t, d, "deny", d.Reasons[0])
			if !contains(d.Reasons, "VELOCITY_EXCEEDED") && !contains(d.Reasons, "BREAKER_OPEN") && !contains(d.Reasons, "REVALIDATION_FAILED") {
				t.Fatalf("unexpected %+v", d)
			}
		}
	}
	if n == 0 || n > 100 {
		t.Fatalf("issued %d against budget 100", n)
	}
	t.Logf("issued %d of 200, budget 100", n)
}
func TestAcceptance19TripDuringCommitWait(t *testing.T) {
	e := running(t, true, nil)
	r := e.Request("hot", "1")
	d := complete(e, r, func() { e.Append("DRIFT", "drift_detected", "drift", nil) })
	refused(t, d, "deny", "REVALIDATION_FAILED")
	if !contains(d.Reasons, "BREAKER_OPEN") {
		t.Fatalf("missing trip: %+v", d)
	}
	noIssued(t, e)
}
func TestAcceptance22InflightFlood(t *testing.T) {
	e := running(t, true, func(p string) string {
		return strings.Replace(p, "principal = 512, origin_host = 512", "principal = 2, origin_host = 2", 1)
	})
	done := make(chan daemon.Decision, 2)
	for i := 0; i < 2; i++ {
		r := e.Request("hot", "1")
		go func() { done <- e.Decide(r) }()
		e.Wait("pending request witnessed", func() bool { return e.Witnessed(r) })
	}
	for i := 0; i < 5; i++ {
		refused(t, e.Decide(e.Request("hot", "1")), "deny", "INFLIGHT_LIMIT")
	}
	s := e.Status()
	if !contains(s.OpenScopes, "principal:payouts") || contains(s.OpenScopes, "class:hot") {
		t.Fatalf("flood trip %+v", s)
	}
	refused(t, e.Decide(e.Request("hot", "1")), "deny", "BREAKER_OPEN")
	e.Gate.Poll()
	for i := 0; i < 2; i++ {
		select {
		case d := <-done:
			refused(t, d, "deny", "REVALIDATION_FAILED")
		case <-time.After(15 * time.Second):
			t.Fatal("pending flood blocked")
		}
	}
	r := e.Request("hot", "1")
	r.Principal = "innocent"
	r.OriginHost = "other"
	allowed(t, complete(e, r, nil))
}
