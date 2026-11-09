package breaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func operators() ([]proto.Operator, []keySigner) {
	var o []proto.Operator
	var s []keySigner
	for i := 1; i <= 3; i++ {
		k := keySigner{ed25519.NewKeyFromSeed(append(make([]byte, 31), byte(i)))}
		s = append(s, k)
		o = append(o, proto.Operator{Label: "op" + string(rune('0'+i)), Key: k.PublicKey()})
	}
	return o, s
}

func cfg() Config {
	return Config{Window: time.Hour, WarnAt: 3, EscalateAt: 6, HaltAt: 10, Quorum: 2,
		Weights: map[string]int{"deny": 1, "inflight_limit": 2, "chain_unverified": 10, "velocity_exceeded": 10, "self_check": 10}}
}

var (
	class = proto.Scope{Kind: proto.ScopeClass, Value: "withdrawal_hot"}
	alice = proto.Scope{Kind: proto.ScopePrincipal, Value: "alice"}
	glob  = proto.Scope{Kind: proto.ScopeGlobal}
)

func req() proto.ActionRequest {
	return proto.ActionRequest{V: 1, Class: "withdrawal_hot", Target: "wallet-svc", Asset: "BTC", Amount: "1",
		Destination: "addr", Principal: "alice", OriginHost: "h1"}
}

func bundle(t *testing.T, s proto.Scope, epoch uint64, nonce byte, signers []keySigner, labels []string) proto.ResetBundle {
	t.Helper()
	r := proto.Reset{V: 1, Scope: s, NewEpoch: epoch, Reason: "reviewed", Nonce: strings.Repeat("0", 30) + string("0123456789abcdef"[nonce%16]) + "0", TS: proto.FormatTime(t0)}
	b := proto.ResetBundle{Reset: r}
	for i, k := range signers {
		p, err := proto.SignReset(r, labels[i], k)
		if err != nil {
			t.Fatal(err)
		}
		b.Partials = append(b.Partials, p)
	}
	return b
}

func TestTicksLevelsAndHalt(t *testing.T) {
	b := New(cfg())
	r := req()
	var lvl string
	for i := 1; i <= 9; i++ {
		var ev *Event
		var err error
		lvl, ev, err = b.Tick("deny", alice, t0)
		if err != nil || ev != nil {
			t.Fatalf("tick %d: %v %v", i, ev, err)
		}
		want := LevelNone
		if i >= 6 {
			want = LevelEscalate
		} else if i >= 3 {
			want = LevelWarn
		}
		if lvl != want || b.Level(r, t0) != want {
			t.Fatalf("after %d ticks level %q/%q, want %q", i, lvl, b.Level(r, t0), want)
		}
	}
	if _, open := b.Open(r); open {
		t.Fatal("open below halt")
	}
	_, ev, _ := b.Tick("deny", alice, t0)
	if ev == nil || ev.Type != EventTrip || ev.Epoch != 1 || ev.Scope != alice {
		t.Fatalf("10th tick: %+v", ev)
	}
	if s, open := b.Open(r); !open || s != alice {
		t.Fatal("principal scope should be open")
	}
	other := r
	other.Principal = "bob"
	if _, open := b.Open(other); open {
		t.Fatal("a principal trip must not cover another principal")
	}
	if _, ev, _ := b.Tick("deny", alice, t0); ev != nil || b.EpochNum() != 1 {
		t.Fatal("ticks on an open scope must not bump the epoch")
	}
}

func TestTicksExpire(t *testing.T) {
	b := New(cfg())
	for i := 0; i < 9; i++ {
		if _, _, err := b.Tick("deny", alice, t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, ev, _ := b.Tick("deny", alice, t0.Add(time.Hour+time.Second)); ev != nil {
		t.Fatal("ticks older than the window must not count")
	}
	if b.Level(req(), t0.Add(time.Hour+time.Second)) != LevelNone {
		t.Fatal("one fresh tick is below warn")
	}
}

func TestUnknownOrZeroWeightIgnored(t *testing.T) {
	b := New(cfg())
	for i := 0; i < 50; i++ {
		if _, ev, _ := b.Tick("not_configured", alice, t0); ev != nil {
			t.Fatal("zero-weight trigger tripped")
		}
	}
}

func TestGlobalIsReserved(t *testing.T) {
	b := New(cfg())
	if _, _, err := b.Tick("velocity_exceeded", glob, t0); !errors.Is(err, ErrNotGlobal) {
		t.Fatalf("velocity on global: %v", err)
	}
	if _, err := b.Trip("drift_detected", glob, "x", t0); !errors.Is(err, ErrNotGlobal) {
		t.Fatalf("drift trip on global: %v", err)
	}
	_, ev, err := b.Tick("chain_unverified", glob, t0)
	if err != nil || ev == nil {
		t.Fatalf("chain_unverified must trip global at once: %v %v", ev, err)
	}
	r := req()
	r.Class, r.Principal = "anything", "anyone"
	if s, open := b.Open(r); !open || s != glob {
		t.Fatal("global must cover every request")
	}
	if _, _, err := b.Tick("deny", proto.Scope{Kind: "bogus"}, t0); err == nil {
		t.Fatal("invalid scope accepted")
	}
}

func TestUnknownScopeKindFailsClosed(t *testing.T) {
	b := New(cfg())
	b.mu.Lock()
	b.open["future:x"] = openScope{scope: proto.Scope{Kind: "future", Value: "x"}}
	b.mu.Unlock()
	if _, open := b.Open(req()); !open {
		t.Fatal("an open scope of unknown kind must cover everything")
	}
}

// Acceptance 12: reset 1-of-3 rejected, 2-of-3 accepted with the epoch
// bumped, replayed reset rejected.
func TestResetQuorum(t *testing.T) {
	o, s := operators()
	b := New(cfg())
	mustTrip(t, b, "velocity_exceeded", class, "burst")
	if b.EpochNum() != 1 {
		t.Fatal("trip must bump the epoch")
	}
	one := bundle(t, class, 2, 1, s[:1], []string{"op1"})
	if _, err := b.Reset(one, o, t0); !errors.Is(err, proto.ErrQuorumNotMet) {
		t.Fatalf("1-of-3: %v", err)
	}
	same := bundle(t, class, 2, 1, []keySigner{s[0], s[0]}, []string{"op1", "op1"})
	if _, err := b.Reset(same, o, t0); !errors.Is(err, proto.ErrQuorumNotMet) {
		t.Fatalf("one operator twice: %v", err)
	}
	wrongEpoch := bundle(t, class, 5, 2, s[:2], []string{"op1", "op2"})
	if _, err := b.Reset(wrongEpoch, o, t0); !errors.Is(err, ErrEpoch) {
		t.Fatalf("wrong epoch: %v", err)
	}
	notOpen := bundle(t, alice, 2, 3, s[:2], []string{"op1", "op2"})
	if _, err := b.Reset(notOpen, o, t0); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("not open: %v", err)
	}
	if !b.IsOpen(class) || b.EpochNum() != 1 {
		t.Fatal("failed resets must change nothing")
	}
	two := bundle(t, class, 2, 4, s[1:], []string{"op2", "op3"})
	ev, err := b.Reset(two, o, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != EventReset || ev.Epoch != 2 || len(ev.Approvers) != 2 || ev.Bundle == nil || b.IsOpen(class) {
		t.Fatalf("reset event %+v", ev)
	}
	if got := b.AckTime(req()); !got.Equal(t0.Add(time.Minute)) {
		t.Fatalf("AckTime = %v", got)
	}
	// Replay: trip again, then resubmit the same (nonce) bundle re-signed for
	// the right epoch.
	mustTrip(t, b, "velocity_exceeded", class, "burst")
	replay := bundle(t, class, 4, 4, s[1:], []string{"op2", "op3"})
	if _, err := b.Reset(replay, o, t0); !errors.Is(err, ErrNonceSpent) {
		t.Fatalf("replayed nonce: %v", err)
	}
}

func TestEpochStatement(t *testing.T) {
	b := New(cfg())
	mustTrip(t, b, "velocity_exceeded", class, "x")
	mustTrip(t, b, "deny", alice, "x")
	e := b.Epoch(t0)
	if e.Epoch != 2 || len(e.OpenScopes) != 2 || e.OpenScopes[0] != class || e.IssuedAt != proto.FormatTime(t0) {
		t.Fatalf("epoch %+v", e)
	}
	if New(cfg()).Epoch(t0).OpenScopes == nil {
		t.Fatal("open_scopes must never be null")
	}
}

// Acceptance 14 (breaker half) and C14: restore keeps the more restrictive.
func TestRestore(t *testing.T) {
	o, s := operators()
	trip := func(sc proto.Scope, e uint64) Event { return Event{Type: EventTrip, Scope: sc, Epoch: e, TS: t0} }
	reset := func(sc proto.Scope, e uint64, nonce byte, signers []keySigner) Event {
		b := bundle(t, sc, e, nonce, signers, []string{"op1", "op2", "op3"}[:len(signers)])
		return Event{Type: EventReset, Scope: sc, Epoch: e, Bundle: &b, TS: t0.Add(time.Duration(e) * time.Minute)}
	}
	bob := proto.Scope{Kind: proto.ScopePrincipal, Value: "bob"}
	h1 := proto.Scope{Kind: proto.ScopeOriginHost, Value: "h1"}
	d := proto.Scope{Kind: proto.ScopeDestination, Value: "addr"}

	b := New(cfg())
	if b.Restored() {
		t.Fatal("restored before Restore")
	}
	verified := []Event{
		trip(class, 1), reset(class, 2, 1, s[:2]), // closed by a good log reset
		trip(alice, 3), reset(alice, 4, 2, s[:1]), // log reset without quorum: stays open
		trip(bob, 5),
		trip(d, 7), reset(d, 7, 5, s[:2]), // tie: stays open
	}
	local := []Event{
		trip(h1, 6),             // trip not yet in the log: counts
		reset(bob, 8, 3, s[:2]), // reset only in local state: does not count
	}
	b.Restore(verified, local, o)
	if !b.Restored() {
		t.Fatal("not restored")
	}
	for sc, want := range map[proto.Scope]bool{class: false, alice: true, bob: true, h1: true, d: true} {
		if b.IsOpen(sc) != want {
			t.Errorf("%s open = %v, want %v", sc, !want, want)
		}
	}
	if b.EpochNum() != 8 {
		t.Errorf("epoch = %d, want the highest seen (8)", b.EpochNum())
	}
	// The local-only reset's nonce is spent even though it did not count.
	mustTrip(t, b, "velocity_exceeded", class, "x")
	again := bundle(t, bob, b.EpochNum()+1, 3, s[:2], []string{"op1", "op2"})
	if _, err := b.Reset(again, o, t0); !errors.Is(err, ErrNonceSpent) {
		t.Fatalf("nonce from local reset: %v", err)
	}
	if got := b.AckTime(req()); !got.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("lastReset from verified reset: %v", got)
	}
}

func TestRestoreRejectsMismatchedBundle(t *testing.T) {
	o, s := operators()
	b := New(cfg())
	good := bundle(t, alice, 2, 1, s[:2], []string{"op1", "op2"})
	// A valid bundle for alice relabelled as closing the class scope.
	b.Restore([]Event{{Type: EventTrip, Scope: class, Epoch: 1}, {Type: EventReset, Scope: class, Epoch: 2, Bundle: &good}}, nil, o)
	if !b.IsOpen(class) {
		t.Fatal("a reset event whose bundle names another scope must not close this one")
	}
}

func TestAdapters(t *testing.T) {
	var buf bytes.Buffer
	ev := Event{Type: EventTrip, Scope: class, Epoch: 7, Trigger: "drift_detected", Reason: "r", TS: t0}
	if err := (&LogOnly{W: &buf}).OnTrip(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"epoch":"7"`) || !strings.Contains(buf.String(), `"scope":"class:withdrawal_hot"`) {
		t.Fatalf("log line %s", buf.String())
	}
	if err := (ExecHook{Path: "hook.sh"}).OnTrip(context.Background(), ev); !errors.Is(err, ErrHookPath) {
		t.Fatalf("relative hook: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	script := filepath.Join(dir, "hook.sh")
	mustWrite(t, script, []byte("#!/bin/sh\nenv | sort > "+out+"\n"), 0o700)
	if err := (ExecHook{Path: script}).OnTrip(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	for _, want := range []string{"GATE_SCOPE_KIND=class", "GATE_SCOPE_VALUE=withdrawal_hot", "GATE_EPOCH=7", "GATE_TRIGGER=drift_detected"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("hook env missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "HOME=") {
		t.Error("hook must not inherit the gate's environment")
	}
	fail := filepath.Join(dir, "fail.sh")
	mustWrite(t, fail, []byte("#!/bin/sh\necho nope; exit 3\n"), 0o700)
	if err := (ExecHook{Path: fail}).OnTrip(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("failing hook: %v", err)
	}
}

func mustTrip(t *testing.T, b *Breaker, trigger string, s proto.Scope, why string) {
	t.Helper()
	if _, err := b.Trip(trigger, s, why, t0); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
