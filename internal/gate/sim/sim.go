// Package sim drives the real gate socket and a signed witness store. Keys are
// deterministic test fixtures and must never be used outside simulations.
package sim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/feeds"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/daemon"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce/witnessproof"
)

type Key struct{ priv ed25519.PrivateKey }

func key(seed byte) Key                     { s := make([]byte, 32); s[31] = seed; return Key{ed25519.NewKeyFromSeed(s)} }
func (k Key) Sign(b []byte) ([]byte, error) { return ed25519.Sign(k.priv, b), nil }
func (k Key) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

// Policy builds a bounded ten-asset envelope and a two-approval manual class.
func Policy(w Key, commit bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `version = 1
[global]
witness_keys = ["%s"]
witness_drift_interval_sec = 30
reset_quorum = 2
budget = { window = "1h", max_value = "100" }
`, hex.EncodeToString(w.PublicKey()))
	var assets []string
	for i := 0; i < 10; i++ {
		a := fmt.Sprintf("A%d", i)
		assets = append(assets, fmt.Sprintf("%q", a))
		fmt.Fprintf(&b, "[assets.%s]\ndecimals = 0\nref_value = \"1\"\n", a)
	}
	fmt.Fprintf(&b, `[classes.hot]
tier = "high"
root = "automated_envelope"
targets = ["wallet"]
assets = [%s]
destinations = ["cold"]
max_value = "100"
commit_wait = %t
commit_wait_timeout = "10s"
budget = { window = "1h", max_value = "1000" }
inflight = { class = 512, principal = 512, origin_host = 512 }
tighten = { first_seen_edge = "off" }
[classes.manual]
tier = "high"
root = "approval"
approvals_required = 2
targets = ["wallet"]
assets = ["A0"]
tighten = { first_seen_edge = "off" }
`, strings.Join(assets, ","), commit)
	return b.String()
}

// Env owns all resources. Poll is deliberately manual; Serve runs without Run.
type Env struct {
	T                testing.TB
	Dir              string
	Store            *store.Store
	Gate             *daemon.Daemon
	Witness, GateKey Key
	Ops              []Key
	Client           *http.Client
	bridge           *feeds.Bridge
	logKey           []byte
	cancel           context.CancelFunc
	served           chan error
	clock            atomic.Int64
	serial           atomic.Uint64
}

func (e *Env) Path(p string) string    { return filepath.Join(e.Dir, p) }
func (e *Env) Now() time.Time          { return time.Unix(0, e.clock.Load()) }
func (e *Env) Advance(d time.Duration) { e.clock.Add(int64(d)) }
func (e *Env) must(err error) {
	e.T.Helper()
	if err != nil {
		e.T.Fatal(err)
	}
}
func (e *Env) Write(p string, b []byte) { e.T.Helper(); e.must(os.WriteFile(e.Path(p), b, 0600)) }
func (e *Env) Wait(what string, f func() bool) {
	e.T.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			e.T.Fatalf("waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// New creates the feed BEFORE starting the real bridge, and waits for its
// recorded open event before any daemon can write into it.
func New(t testing.TB, commit bool, edit func(string) string) *Env {
	t.Helper()
	dir, err := os.MkdirTemp("", "gsim-")
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{T: t, Dir: dir, Witness: key(50), GateKey: key(60), Ops: []Key{key(1), key(2), key(3)}}
	t.Cleanup(func() {
		e.Stop()
		if e.bridge != nil {
			e.bridge.Stop()
		}
		if e.Store != nil {
			e.Store.Close()
		}
		os.RemoveAll(dir)
	})
	e.clock.Store(time.Now().UnixNano())
	e.logKey, err = encrypt.DeriveKey("gate-sim")
	e.must(err)
	e.must(os.MkdirAll(e.Path("state"), 0700))
	e.Write("state/gate.jsonl", nil)
	var ops strings.Builder
	for i, k := range e.Ops {
		fmt.Fprintf(&ops, "op%d %s\n", i+1, hex.EncodeToString(k.PublicKey()))
	}
	e.Write("operators", []byte(ops.String()))
	p := Policy(e.Witness, commit)
	if edit != nil {
		p = edit(p)
	}
	e.Write("policy", []byte(p))
	sig, err := policy.Sign([]byte(p), e.Ops[0])
	e.must(err)
	e.Write("policy.sig", sig)
	e.Store, err = store.Open(e.Path("w"), e.logKey, e.Witness)
	e.must(err)
	e.Append("INFO", "daemon_start", "witness", nil)
	e.bridge = feeds.New(e.Path("state/gate.jsonl"), "gate", e.Store)
	e.bridge.ResumeFrom(e.Path("bridge-position"))
	e.bridge.Start()
	e.Wait("bridge open", func() bool {
		es, err := store.ReadAll(e.Path("w"), e.logKey)
		if err != nil {
			return false
		}
		return len(es) > 1
	})
	return e
}
func (e *Env) Start() {
	e.T.Helper()
	var err error
	e.Gate, err = daemon.New(daemon.Config{WitnessDir: e.Path("w"), LogKey: e.logKey, PolicyPath: e.Path("policy"), OperatorsPath: e.Path("operators"), StateDir: e.Path("state"), Signer: e.GateKey, Now: e.Now, Log: io.Discard})
	e.must(err)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.served = make(chan error, 1)
	go func() { e.served <- e.Gate.Serve(ctx, e.Path("g.sock"), nil) }()
	e.Wait("socket", func() bool {
		select {
		case err := <-e.served:
			e.cancel = nil
			e.Gate.Close()
			e.T.Fatalf("serve: %v", err)
		default:
		}
		c, err := net.Dial("unix", e.Path("g.sock"))
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	e.Client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialUnix(ctx, e.Path("g.sock"))
	}}}
	e.Gate.Poll()
}

// dialUnix retries a refused connect for a short while. On macOS a unix-socket
// connect fails at once with ECONNREFUSED when the listen backlog is full
// (kern.ipc.somaxconn, 128 by default), where Linux would wait; bursts of
// concurrent requests from the simulations would otherwise fail spuriously.
func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	deadline := time.Now().Add(2 * time.Second)
	wait := time.Millisecond
	for {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
		if wait < 50*time.Millisecond {
			wait *= 2
		}
	}
}
func (e *Env) Stop() {
	if e.cancel != nil {
		if e.Client != nil {
			e.Client.CloseIdleConnections()
		}
		e.cancel()
		e.must(<-e.served)
		e.must(e.Gate.Close())
		e.cancel = nil
	}
}
func (e *Env) Append(level, event, source string, data any) {
	e.T.Helper()
	e.must(e.Store.Append(level, event, source, data))
}
func (e *Env) Request(class, amount string) proto.ActionRequest {
	return proto.ActionRequest{V: 1, Class: class, Target: "wallet", Asset: "A0", Amount: amount, Destination: "cold", Principal: "payouts", OriginHost: "signer", RequestNonce: fmt.Sprintf("%032x", e.serial.Add(1)), TS: proto.FormatTime(e.Now())}
}
func (e *Env) Approve(r proto.ActionRequest, who ...int) []proto.Approval {
	h, err := proto.ActionHashHex(r)
	e.must(err)
	var out []proto.Approval
	for _, i := range who {
		a, err := proto.SignApproval(proto.Approval{V: 1, ActionHash: h, ApproverLabel: fmt.Sprintf("op%d", i+1), ExpiresAt: proto.FormatTime(e.Now().Add(time.Minute))}, e.Ops[i])
		e.must(err)
		out = append(out, a)
	}
	return out
}
func (e *Env) Call(method, path string, body any, out any) int {
	e.T.Helper()
	var b []byte
	var err error
	if body != nil {
		b, err = json.Marshal(body)
		e.must(err)
	}
	req, err := http.NewRequest(method, "http://gate"+path, bytes.NewReader(b))
	e.must(err)
	resp, err := e.Client.Do(req)
	e.must(err)
	defer resp.Body.Close()
	if out != nil {
		e.must(json.NewDecoder(resp.Body).Decode(out))
	} else {
		_, err = io.Copy(io.Discard, resp.Body)
		e.must(err)
	}
	return resp.StatusCode
}
func (e *Env) Decide(r proto.ActionRequest, apps ...proto.Approval) daemon.Decision {
	e.T.Helper()
	raw, err := proto.Canonical(r)
	e.must(err)
	b := daemon.DecideRequest{Request: raw}
	for _, a := range apps {
		raw, err := proto.Canonical(a)
		e.must(err)
		b.Approvals = append(b.Approvals, raw)
	}
	var d daemon.Decision
	if c := e.Call("POST", "/v1/decide", b, &d); c != 200 {
		e.T.Fatalf("decide HTTP %d: %+v", c, d)
	}
	return d
}
func (e *Env) Status() daemon.Status {
	var s daemon.Status
	e.Call("GET", "/v1/status", nil, &s)
	return s
}
func (e *Env) Epoch() json.RawMessage {
	var b json.RawMessage
	e.Call("GET", "/v1/epoch", nil, &b)
	return b
}
func (e *Env) Verifier(now func() time.Time) *gateenforce.Verifier {
	w, err := witnessproof.New([]ed25519.PublicKey{e.Witness.PublicKey()})
	e.must(err)
	v, err := gateenforce.New(gateenforce.Config{GateKeys: []ed25519.PublicKey{e.GateKey.PublicKey()}, Witness: w, Now: now})
	e.must(err)
	e.must(v.UpdateEpoch(e.Epoch()))
	return v
}
func (e *Env) Witnessed(r proto.ActionRequest) bool {
	h, err := proto.ActionHashHex(r)
	e.must(err)
	// Only records a signed head covers count: the witness writes the log
	// before the head, and the gate's Inclusion needs the head.
	_, es, _, err := store.ReadSince(e.Path("w"), e.logKey, 0, 0)
	if err != nil {
		return false
	}
	for _, en := range es {
		if en.Event == "gate_request" && strings.Contains(string(en.Data), h) {
			return true
		}
	}
	return false
}
