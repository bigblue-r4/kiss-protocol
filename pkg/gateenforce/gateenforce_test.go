package gateenforce_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func newSigner(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))}
}

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func request() gateenforce.ActionRequest {
	return gateenforce.ActionRequest{
		V: 1, Class: "withdrawal_hot", Target: "wallet-svc", Asset: "BTC", Amount: "0.5",
		Destination: "bc1qexampledestination", RequestNonce: strings.Repeat("ab", 16),
		Principal: "svc-withdrawals", OriginHost: "app-01", TS: proto.FormatTime(t0),
	}
}

var idCounter atomic.Uint32

func mint(t *testing.T, s keySigner, req gateenforce.ActionRequest, epoch uint64, issued time.Time) []byte {
	t.Helper()
	h, err := proto.ActionHashHex(req)
	if err != nil {
		t.Fatal(err)
	}
	id := idCounter.Add(1)
	tok, err := proto.SignToken(proto.Token{
		V: 1, TokenID: strings.Repeat("0", 24) + strings.Repeat(string("0123456789abcdef"[id%16]), 8),
		ActionHash: h, IssuedAt: proto.FormatTime(issued), ExpiresAt: proto.FormatTime(issued.Add(30 * time.Second)),
		BreakerEpoch: epoch, PolicyHash: strings.Repeat("ee", 32),
	}, s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Canonical(tok)
	return raw
}

func epochBytes(t *testing.T, s keySigner, n uint64, issued time.Time, scopes ...gateenforce.Scope) []byte {
	t.Helper()
	e, err := proto.SignEpoch(proto.Epoch{V: 1, Epoch: n, IssuedAt: proto.FormatTime(issued), OpenScopes: scopes}, s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Canonical(e)
	return raw
}

func setup(t *testing.T) (*gateenforce.Verifier, keySigner, *clock, *bytes.Buffer) {
	t.Helper()
	gate := newSigner(3)
	c := &clock{t: t0}
	var out bytes.Buffer
	v, err := gateenforce.New(gateenforce.Config{GateKeys: []ed25519.PublicKey{gate.PublicKey()}, Now: c.Now, Refusals: &out})
	if err != nil {
		t.Fatal(err)
	}
	return v, gate, c, &out
}

func code(err error) string {
	var r *gateenforce.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return "OK"
	}
	return "NOT_A_REFUSAL: " + err.Error()
}

func TestCheck(t *testing.T) {
	high := gateenforce.Options{HighTier: true}
	low := gateenforce.Options{}
	other := request()
	other.Amount = "500"
	attackerDest := request()
	attackerDest.Destination = "bc1qattacker"

	cases := []struct {
		name  string
		run   func(t *testing.T, v *gateenforce.Verifier, gate keySigner, c *clock) error
		want  string
		notes string
	}{
		{"valid, fresh epoch", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_ = v.UpdateEpoch(epochBytes(t, g, 5, t0))
			_, err := v.Check(request(), mint(t, g, request(), 5, t0), high)
			return err
		}, "OK", ""},
		{"replay", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_ = v.UpdateEpoch(epochBytes(t, g, 5, t0))
			raw := mint(t, g, request(), 5, t0)
			if _, err := v.Check(request(), raw, high); err != nil {
				t.Fatalf("first use refused: %v", err)
			}
			_, err := v.Check(request(), raw, high)
			return err
		}, gateenforce.TokenReplayed, "acceptance 5"},
		{"token reused for a different amount", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(other, mint(t, g, request(), 0, t0), low)
			return err
		}, gateenforce.ActionMismatch, "acceptance 5"},
		{"token reused for a different destination", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(attackerDest, mint(t, g, request(), 0, t0), low)
			return err
		}, gateenforce.ActionMismatch, "acceptance 5"},
		{"expired", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			raw := mint(t, g, request(), 0, t0)
			c.Add(33 * time.Second)
			_, err := v.Check(request(), raw, low)
			return err
		}, gateenforce.TokenExpired, ""},
		{"forged token (unpinned key)", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(request(), mint(t, newSigner(9), request(), 0, t0), low)
			return err
		}, gateenforce.TokenInvalid, ""},
		{"garbage", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(request(), []byte(`{"v":1}`), low)
			return err
		}, gateenforce.TokenInvalid, ""},
		{"high tier, no epoch yet", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(request(), mint(t, g, request(), 0, t0), high)
			return err
		}, gateenforce.EpochStale, "acceptance 13"},
		{"low tier, no epoch yet", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_, err := v.Check(request(), mint(t, g, request(), 0, t0), low)
			return err
		}, "OK", ""},
		{"high tier, stale epoch", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_ = v.UpdateEpoch(epochBytes(t, g, 5, t0))
			c.Add(15 * time.Second)
			_, err := v.Check(request(), mint(t, g, request(), 5, c.Now()), high)
			return err
		}, gateenforce.EpochStale, "acceptance 13"},
		{"token from before a trip", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			raw := mint(t, g, request(), 5, t0)
			_ = v.UpdateEpoch(epochBytes(t, g, 6, t0, gateenforce.Scope{Kind: "class", Value: "prod_deploy"}))
			_, err := v.Check(request(), raw, low)
			return err
		}, gateenforce.EpochSuperseded, ""},
		{"scope frozen in the current epoch", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_ = v.UpdateEpoch(epochBytes(t, g, 6, t0, gateenforce.Scope{Kind: "asset", Value: "BTC"}))
			_, err := v.Check(request(), mint(t, g, request(), 6, t0), high)
			return err
		}, gateenforce.ScopeFrozen, ""},
		{"commit-wait class, token has no evidence", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			_ = v.UpdateEpoch(epochBytes(t, g, 5, t0))
			_, err := v.Check(request(), mint(t, g, request(), 5, t0), gateenforce.Options{HighTier: true, CommitWait: true})
			return err
		}, gateenforce.CommitWaitMissing, ""},
		{"invalid request", func(t *testing.T, v *gateenforce.Verifier, g keySigner, c *clock) error {
			bad := request()
			bad.Amount = "-1"
			_, err := v.Check(bad, mint(t, g, request(), 0, t0), low)
			return err
		}, gateenforce.RequestInvalid, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, g, c, _ := setup(t)
			if got := code(tc.run(t, v, g, c)); got != tc.want {
				t.Fatalf("got %s, want %s %s", got, tc.want, tc.notes)
			}
		})
	}
}

// TestEpochUpdates: forged, older and future epochs never replace the held one.
func TestEpochUpdates(t *testing.T) {
	v, g, _, _ := setup(t)
	if err := v.UpdateEpoch(epochBytes(t, g, 5, t0)); err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEpoch(epochBytes(t, newSigner(9), 9, t0)); err == nil {
		t.Error("epoch from an unpinned key accepted")
	}
	if err := v.UpdateEpoch(epochBytes(t, g, 4, t0)); err == nil {
		t.Error("older epoch accepted")
	}
	if err := v.UpdateEpoch(epochBytes(t, g, 6, t0.Add(time.Minute))); err == nil {
		t.Error("epoch issued in the future accepted")
	}
	// A forged "all clear" for a later epoch must not lift a freeze.
	if err := v.UpdateEpoch(epochBytes(t, g, 6, t0, gateenforce.Scope{Kind: "global"})); err != nil {
		t.Fatal(err)
	}
	if err := v.UpdateEpoch(epochBytes(t, newSigner(9), 7, t0)); err == nil {
		t.Error("forged clearing epoch accepted")
	}
	if _, err := v.Check(request(), mint(t, g, request(), 6, t0), gateenforce.Options{HighTier: true}); code(err) != gateenforce.ScopeFrozen {
		t.Errorf("freeze lifted by a forged epoch: %v", err)
	}
}

// TestRefusalNotBurned: a token refused for a reason that later clears (no
// epoch yet) still works once the reason is gone; it was not marked used.
func TestRefusalNotBurned(t *testing.T) {
	v, g, _, _ := setup(t)
	raw := mint(t, g, request(), 5, t0)
	if _, err := v.Check(request(), raw, gateenforce.Options{HighTier: true}); code(err) != gateenforce.EpochStale {
		t.Fatalf("want EPOCH_STALE, got %v", err)
	}
	_ = v.UpdateEpoch(epochBytes(t, g, 5, t0))
	if _, err := v.Check(request(), raw, gateenforce.Options{HighTier: true}); err != nil {
		t.Fatalf("token refused after the epoch arrived: %v", err)
	}
}

// TestConcurrentReplay: one token raced from many goroutines is accepted once.
func TestConcurrentReplay(t *testing.T) {
	v, g, _, _ := setup(t)
	raw := mint(t, g, request(), 0, t0)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Check(request(), raw, gateenforce.Options{}); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("token accepted %d times, want once", ok.Load())
	}
}

// TestRefusalFeed: each refusal is one NDJSON line a witness feed can record:
// a kind, WARN, and only string values (feed lines are re-encoded and numbers
// would become floats).
func TestRefusalFeed(t *testing.T) {
	v, g, _, out := setup(t)
	other := request()
	other.Destination = "bc1qattacker"
	_, _ = v.Check(other, mint(t, g, request(), 0, t0), gateenforce.Options{})
	_, _ = v.Check(request(), []byte("junk"), gateenforce.Options{})
	text := out.String()
	sc := bufio.NewScanner(strings.NewReader(text))
	n := 0
	for sc.Scan() {
		n++
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %d not JSON: %v", n, err)
		}
		if m["kind"] != "gate_refusal" || m["level"] != "WARN" {
			t.Errorf("line %d: kind/level = %v/%v", n, m["kind"], m["level"])
		}
		for k, val := range m {
			if _, isStr := val.(string); !isStr {
				t.Errorf("line %d: field %s is %T, want string", n, k, val)
			}
		}
	}
	if n != 2 {
		t.Fatalf("%d refusal lines, want 2", n)
	}
	if !strings.Contains(text, `"code":"ACTION_MISMATCH"`) {
		t.Errorf("mismatch not recorded: %s", text)
	}
}

func TestNewNeedsAKey(t *testing.T) {
	if _, err := gateenforce.New(gateenforce.Config{}); err == nil {
		t.Fatal("verifier without pinned gate keys")
	}
}
