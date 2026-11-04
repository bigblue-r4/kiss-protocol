package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/feeds"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/feed"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce/witnessproof"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func signer(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(append(make([]byte, 31), seed))}
}

const policyTmpl = `
version = 1
[global]
witness_keys = ["%s"]
witness_drift_interval_sec = 30
reset_quorum = 2
budget = { window = "1h", max_value = "100000" }
[assets.USDC]
decimals = 6
ref_value = "1"
[classes.hot]
tier = "high"
root = "automated_envelope"
targets = ["wallet-svc"]
assets = ["USDC"]
destinations = ["cold"]
max_value = "5000"
commit_wait = true
commit_wait_timeout = "%s"
budget = { window = "1h", max_value = "50000" }
tighten = { first_seen_edge = "off" }
[classes.manual]
tier = "high"
root = "approval"
approvals_required = 2
targets = ["wallet-svc"]
assets = ["USDC"]
tighten = { first_seen_edge = "off" }
`

// env is a witness host with a gate on it: a real witness store, the real
// event-feed bridge tailing the gate feed into it, and a gate daemon.
type env struct {
	t       *testing.T
	dir     string // root
	wdir    string // witness primary
	key     []byte
	witness keySigner
	gateKey keySigner
	ops     []keySigner
	st      *store.Store
	bridge  *feeds.Bridge
	d       *Daemon
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	sock    string
	logBuf  *syncBuf
	poll    time.Duration
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newEnv(t *testing.T, timeout string) *env {
	t.Helper()
	root, err := os.MkdirTemp("", "gate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	e := &env{t: t, dir: root, wdir: filepath.Join(root, "w"), witness: signer(50), gateKey: signer(60),
		sock: filepath.Join(root, "g.sock"), logBuf: &syncBuf{}}
	e.key, _ = encrypt.DeriveKey("gate-daemon-test")
	var opsTxt strings.Builder
	for i := byte(1); i <= 3; i++ {
		s := signer(i)
		e.ops = append(e.ops, s)
		fmt.Fprintf(&opsTxt, "op%d %s\n", i, hex.EncodeToString(s.PublicKey()))
	}
	os.MkdirAll(filepath.Join(root, "etc"), 0o700)
	os.WriteFile(e.path("etc/operators.txt"), []byte(opsTxt.String()), 0o600)
	pol := []byte(fmt.Sprintf(policyTmpl, hex.EncodeToString(e.witness.PublicKey()), timeout))
	os.WriteFile(e.path("etc/gate-policy.toml"), pol, 0o600)
	sig, _ := policy.Sign(pol, e.ops[0])
	os.WriteFile(e.path("etc/gate-policy.toml.sig"), sig, 0o600)
	e.st, err = store.Open(e.wdir, e.key, e.witness)
	if err != nil {
		t.Fatal(err)
	}
	e.st.Append("INFO", "daemon_start", "witness", nil)
	t.Cleanup(func() { e.st.Close() })
	e.startBridge()
	return e
}

func (e *env) pollEvery() time.Duration {
	if e.poll > 0 {
		return e.poll
	}
	return 50 * time.Millisecond
}

func (e *env) path(p string) string { return filepath.Join(e.dir, p) }

func (e *env) startBridge() {
	e.bridge = feeds.New(e.path("state/gate.jsonl"), "gate", e.st)
	e.bridge.Start()
}

func (e *env) stopBridge() {
	if e.bridge != nil {
		e.bridge.Stop()
		e.bridge = nil
	}
}

func (e *env) start() {
	e.t.Helper()
	d, err := New(Config{WitnessDir: e.wdir, LogKey: e.key, PolicyPath: e.path("etc/gate-policy.toml"),
		OperatorsPath: e.path("etc/operators.txt"), StateDir: e.path("state"), Signer: e.gateKey,
		PollInterval: e.pollEvery(), Log: e.logBuf})
	if err != nil {
		e.t.Fatal(err)
	}
	e.d = d
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.wg.Add(2)
	go func() { defer e.wg.Done(); d.Run(ctx) }()
	go func() {
		defer e.wg.Done()
		if err := d.Serve(ctx, e.sock, nil); err != nil {
			e.t.Error(err)
		}
	}()
	e.t.Cleanup(e.stop)
	e.waitFor("socket", func() bool { _, err := os.Stat(e.sock); return err == nil })
}

func (e *env) stop() {
	if e.cancel != nil {
		e.cancel()
		e.wg.Wait()
		e.d.Close()
		e.cancel = nil
	}
}

func (e *env) waitFor(what string, cond func() bool) {
	e.t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	e.t.Fatalf("timed out waiting for %s; gate log:\n%s", what, e.logBuf.String())
}

func (e *env) client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", e.sock)
		}}}
}

func (e *env) get(path string, v any) {
	e.t.Helper()
	resp, err := e.client().Get("http://gate" + path)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			e.t.Fatalf("%s: %v: %s", path, err, b)
		}
	}
}

func (e *env) status() Status {
	var s Status
	e.get("/v1/status", &s)
	return s
}

func (e *env) synced() {
	e.waitFor("gate synced", func() bool { return e.status().DenyAllReason == "" })
}

var nonce byte

func (e *env) req(class, amount string) proto.ActionRequest {
	nonce++
	return proto.ActionRequest{V: 1, Class: class, Target: "wallet-svc", Asset: "USDC", Amount: amount,
		Destination: "cold", RequestNonce: fmt.Sprintf("%030x%02x", time.Now().UnixNano(), nonce),
		Principal: "svc-payouts", OriginHost: "signer-01", TS: proto.FormatTime(time.Now())}
}

func (e *env) decide(r proto.ActionRequest, apps ...proto.Approval) Decision {
	e.t.Helper()
	body := DecideRequest{}
	body.Request, _ = proto.Canonical(r)
	for _, a := range apps {
		raw, _ := proto.Canonical(a)
		body.Approvals = append(body.Approvals, raw)
	}
	b, _ := json.Marshal(body)
	resp, err := e.client().Post("http://gate/v1/decide", "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var d Decision
	json.NewDecoder(resp.Body).Decode(&d)
	return d
}

func (e *env) approve(r proto.ActionRequest, who ...int) []proto.Approval {
	h, _ := proto.ActionHashHex(r)
	var out []proto.Approval
	for _, i := range who {
		a, _ := proto.SignApproval(proto.Approval{V: 1, ActionHash: h, ApproverLabel: fmt.Sprintf("op%d", i+1),
			ExpiresAt: proto.FormatTime(time.Now().Add(time.Minute))}, e.ops[i])
		out = append(out, a)
	}
	return out
}

func (e *env) feedKinds() []string {
	lines, _ := feed.Read(e.path("state/gate.jsonl"))
	var k []string
	for _, l := range lines {
		k = append(k, l["kind"])
	}
	return k
}

func (e *env) verifier() *gateenforce.Verifier {
	e.t.Helper()
	wv, err := witnessproof.New([]ed25519.PublicKey{e.witness.PublicKey()})
	if err != nil {
		e.t.Fatal(err)
	}
	v, err := gateenforce.New(gateenforce.Config{GateKeys: []ed25519.PublicKey{e.gateKey.PublicKey()}, Witness: wv})
	if err != nil {
		e.t.Fatal(err)
	}
	var raw json.RawMessage
	e.get("/v1/epoch", &raw)
	if err := v.UpdateEpoch(raw); err != nil {
		e.t.Fatalf("epoch from the gate refused: %v", err)
	}
	return v
}

// The whole path: decide → gate_request in the feed → the witness records it
// → the gate's verified view covers it → token with inclusion proof, which the
// enforcement point accepts (acceptance 16), once (acceptance 5).
func TestEndToEndCommitWait(t *testing.T) {
	e := newEnv(t, "5s")
	e.start()
	e.synced()
	r := e.req("hot", "1000")
	start := time.Now()
	d := e.decide(r)
	if d.Outcome != "allow" || len(d.Token) == 0 {
		t.Fatalf("decision %+v\n%s", d, e.logBuf.String())
	}
	t.Logf("commit-wait decide took %s", time.Since(start).Round(time.Millisecond))
	v := e.verifier()
	tok, err := v.Check(r, d.Token, gateenforce.Options{HighTier: true, CommitWait: true})
	if err != nil {
		t.Fatalf("enforcement point refused the gate's token: %v", err)
	}
	if tok.Witnessed == nil || tok.Witnessed.Head.SignerKey != hex.EncodeToString(e.witness.PublicKey()) {
		t.Fatal("token lacks witness evidence")
	}
	if _, err := v.Check(r, d.Token, gateenforce.Options{HighTier: true, CommitWait: true}); err == nil {
		t.Fatal("replayed token accepted")
	}
	// The same proof against a different pinned witness key fails.
	if err := witnessproof.Verify(*tok.Witnessed, d.ActionHash, []ed25519.PublicKey{signer(99).PublicKey()}); err == nil {
		t.Fatal("proof verified against an unpinned witness key")
	}
	// The same request again: one approval/envelope check, one token (C20).
	if d2 := e.decide(r); d2.Outcome != "deny" || d2.Reasons[0] != "REQUEST_REPLAYED" {
		t.Fatalf("second decide %+v", d2)
	}
	kinds := strings.Join(e.feedKinds(), " ")
	for _, k := range []string{"gate_start", "policy_load", "breaker_restored", "gate_request", "gate_issued", "gate_decision"} {
		if !strings.Contains(kinds, k) {
			t.Errorf("feed lacks %s: %s", k, kinds)
		}
	}
}

// Acceptance 1 at the socket: a manual-class withdrawal with no approval
// escalates and issues nothing; two approvals allow.
func TestManualEscalatesThenAllows(t *testing.T) {
	e := newEnv(t, "5s")
	e.start()
	e.synced()
	r := e.req("manual", "20000")
	if d := e.decide(r); d.Outcome != "escalate" || d.Reasons[0] != "NO_ROOT" || len(d.Token) != 0 {
		t.Fatalf("no approval: %+v", d)
	}
	if d := e.decide(r, e.approve(r, 0)...); d.Outcome != "escalate" {
		t.Fatalf("one approval: %+v", d)
	}
	d := e.decide(r, e.approve(r, 0, 2)...)
	if d.Outcome != "allow" || strings.Join(d.Approvers, ",") != "op1,op3" {
		t.Fatalf("two approvals: %+v", d)
	}
	if _, err := e.verifier().Check(r, d.Token, gateenforce.Options{HighTier: true}); err != nil {
		t.Fatal(err)
	}
}

// Acceptance 15: an unwritable feed means no tokens.
func TestFeedUnwritableIssuesNothing(t *testing.T) {
	e := newEnv(t, "5s")
	os.MkdirAll(e.path("state/gate.jsonl"), 0o700) // a directory where the feed should be
	e.start()
	e.waitFor("synced", func() bool { s := e.status(); return s.Synced && s.Restored })
	s := e.status()
	if s.FeedError == "" || s.DenyAllReason != "FEED_WRITE_FAILED" {
		t.Fatalf("status %+v", s)
	}
	r := e.req("manual", "1")
	d := e.decide(r, e.approve(r, 0, 1)...)
	if d.Outcome != "deny" || d.Reasons[0] != "FEED_WRITE_FAILED" || len(d.Token) != 0 {
		t.Fatalf("issued with no feed: %+v", d)
	}
}

// failOn is a feed that refuses one record kind, to test each write guard
// on its own.
type failOn struct {
	feedWriter
	kind string
}

func (f failOn) Write(kind, level string, fields map[string]string) error {
	if kind == f.kind {
		return feed.ErrBroken
	}
	return f.feedWriter.Write(kind, level, fields)
}

func TestEachIssuingWriteGuards(t *testing.T) {
	for _, kind := range []string{"gate_request", "gate_issued"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t, "5s")
			e.start()
			e.synced()
			e.d.feed = failOn{e.d.feed, kind}
			r := e.req("manual", "1")
			d := e.decide(r, e.approve(r, 0, 1)...)
			if d.Outcome != "deny" || d.Reasons[0] != "FEED_WRITE_FAILED" || len(d.Token) != 0 {
				t.Fatalf("%s write failed but: %+v", kind, d)
			}
			if e.d.core.Pending() != 0 {
				t.Fatal("reservation leaked")
			}
			// Refunded: the same request may be decided again once the feed works.
			e.d.feed = e.d.feed.(failOn).feedWriter
			if d := e.decide(r, e.approve(r, 0, 1)...); d.Outcome != "allow" {
				t.Fatalf("after the feed recovered: %+v", d)
			}
		})
	}
}

// Acceptance 11 at the daemon: an unsigned or tampered policy is deny-all.
func TestPolicyInvalidDenyAll(t *testing.T) {
	e := newEnv(t, "5s")
	os.WriteFile(e.path("etc/gate-policy.toml"), []byte("version = 1\n# edited after signing\n"), 0o600)
	e.start()
	s := e.status()
	if s.DenyAllReason != "POLICY_INVALID" || !strings.Contains(s.PolicyError, "POLICY_INVALID") {
		t.Fatalf("status %+v", s)
	}
	if d := e.decide(e.req("hot", "1")); d.Outcome != "deny" || d.Reasons[0] != "POLICY_INVALID" {
		t.Fatalf("decision %+v", d)
	}
	if !strings.Contains(strings.Join(e.feedKinds(), " "), "policy_invalid") {
		t.Fatal("policy_invalid not recorded")
	}
}

// The witness stops tailing: commit-wait times out, nothing is issued, the
// budget is refunded.
func TestCommitWaitTimeout(t *testing.T) {
	e := newEnv(t, "300ms")
	e.start()
	e.synced()
	e.stopBridge()
	d := e.decide(e.req("hot", "1000"))
	if d.Outcome != "deny" || d.Reasons[0] != "COMMIT_WAIT_TIMEOUT" || len(d.Token) != 0 {
		t.Fatalf("decision %+v", d)
	}
	if e.d.core.Pending() != 0 {
		t.Fatal("reservation leaked")
	}
}

func trip(t *testing.T, e *env) {
	t.Helper()
	// Drift on the gate host trips every class.
	if err := e.st.Append("DRIFT", "drift_detected", "drift", []map[string]string{{"kind": "new_process", "name": "xmrig"}}); err != nil {
		t.Fatal(err)
	}
	e.waitFor("drift trip", func() bool { return len(e.status().OpenScopes) == 2 })
}

// Acceptance 12 and 14 at the daemon: a restart mid-incident stays tripped
// (rebuilt from the verified log), reports GATE_NOT_SYNCED until rebuilt,
// and only a 2-of-3 reset closes a scope; a replayed reset is refused.
func TestRestartStaysTrippedAndQuorumReset(t *testing.T) {
	e := newEnv(t, "5s")
	e.start()
	e.synced()
	trip(t, e)
	epoch := e.status().Epoch
	// Wait until the trips are in the witness log, then restart.
	e.waitFor("trip witnessed", func() bool {
		n := 0
		for _, s := range e.d.view.GateEvents() {
			if s.Event == "breaker_trip" {
				n++
			}
		}
		return n == 2
	})
	e.stop()
	d2, err := New(Config{WitnessDir: e.wdir, LogKey: e.key, PolicyPath: e.path("etc/gate-policy.toml"),
		OperatorsPath: e.path("etc/operators.txt"), StateDir: e.path("state"), Signer: e.gateKey, Log: e.logBuf})
	if err != nil {
		t.Fatal(err)
	}
	if s := d2.Status(); s.DenyAllReason != "GATE_NOT_SYNCED" {
		t.Fatalf("before rebuild: %+v", s)
	}
	if d := d2.Decide(context.Background(), e.req("hot", "1"), nil); d.Reasons[0] != "GATE_NOT_SYNCED" {
		t.Fatalf("decide before rebuild: %+v", d)
	}
	d2.Close()
	e.start()
	e.waitFor("rebuilt", func() bool { return e.status().Restored })
	s := e.status()
	if len(s.OpenScopes) != 2 || s.Epoch < epoch {
		t.Fatalf("after restart %+v (epoch before %d)", s, epoch)
	}
	if d := e.decide(e.req("hot", "1")); d.Reasons[0] != "BREAKER_OPEN" {
		t.Fatalf("after restart: %+v", d)
	}

	// Reset class:hot. 1 of 3 is refused, 2 of 3 accepted, replay refused.
	scope := proto.Scope{Kind: proto.ScopeClass, Value: "hot"}
	reset := proto.Reset{V: 1, Scope: scope, NewEpoch: s.Epoch + 1, Reason: "drift reviewed: approved patch",
		Nonce: fmt.Sprintf("%032x", time.Now().UnixNano()), TS: proto.FormatTime(time.Now())}
	bundle := func(who ...int) []byte {
		b := proto.ResetBundle{Reset: reset}
		for _, i := range who {
			p, _ := proto.SignReset(reset, fmt.Sprintf("op%d", i+1), e.ops[i])
			b.Partials = append(b.Partials, p)
		}
		raw, _ := proto.Canonical(b)
		return raw
	}
	post := func(raw []byte) int {
		resp, err := e.client().Post("http://gate/v1/reset", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post(bundle(0)); c != http.StatusConflict {
		t.Fatalf("1-of-3 reset: %d", c)
	}
	if c := post(bundle(1, 2)); c != http.StatusOK {
		t.Fatalf("2-of-3 reset: %d\n%s", c, e.logBuf.String())
	}
	if c := post(bundle(1, 2)); c != http.StatusConflict {
		t.Fatalf("replayed reset: %d", c)
	}
	if s := e.status(); len(s.OpenScopes) != 1 || s.Epoch != reset.NewEpoch {
		t.Fatalf("after reset %+v", s)
	}
	if d := e.decide(e.req("hot", "1")); d.Outcome != "allow" {
		t.Fatalf("after reset: %+v", d)
	}
	if d := e.decide(e.req("manual", "1")); d.Reasons[0] != "BREAKER_OPEN" {
		t.Fatalf("manual still tripped: %+v", d)
	}
}

// C14: a trip that reached the local feed but not the witness log still
// counts after a restart. The trip comes from commit-wait timeouts, which
// nothing in the log can re-derive, so only the restore can bring it back.
func TestLocalOnlyTripSurvivesRestart(t *testing.T) {
	e := newEnv(t, "200ms")
	e.start()
	e.synced()
	e.stopBridge()           // the witness stops recording the gate feed
	for i := 0; i < 3; i++ { // weight 4 each, halt at 10
		r := e.req("hot", "1")
		if d := e.decide(r, e.approve(r, 0, 1)...); d.Reasons[0] != "COMMIT_WAIT_TIMEOUT" {
			t.Fatalf("timeout %d: %+v", i, d)
		}
	}
	if s := e.status(); len(s.OpenScopes) != 1 || s.OpenScopes[0] != "class:hot" {
		t.Fatalf("expected class:hot tripped: %+v", s)
	}
	e.stop()
	e.start()
	e.waitFor("rebuilt", func() bool { return e.status().Restored })
	if s := e.status(); len(s.OpenScopes) != 1 {
		t.Fatalf("local-only trip lost at restart: %+v", s)
	}
}

// The other half: the local feed is lost (disk replaced, state wiped) but
// the trip is in the verified witness log. The trip comes from the budget,
// which the log cannot re-derive either.
func TestVerifiedTripSurvivesLostLocalFeed(t *testing.T) {
	e := newEnv(t, "5s")
	e.start()
	e.synced()
	for i := 0; ; i++ {
		d := e.decide(e.req("hot", "5000"))
		if d.Outcome != "allow" {
			if d.Reasons[0] != "VELOCITY_EXCEEDED" || i != 10 {
				t.Fatalf("request %d: %+v", i, d)
			}
			break
		}
	}
	e.waitFor("trip witnessed", func() bool {
		for _, s := range e.d.view.GateEvents() {
			if s.Event == "breaker_trip" {
				return true
			}
		}
		return false
	})
	e.stop()
	e.stopBridge()
	os.Remove(e.path("state/gate.jsonl"))
	e.start()
	e.waitFor("rebuilt", func() bool { return e.status().Restored })
	if s := e.status(); len(s.OpenScopes) != 1 || s.OpenScopes[0] != "class:hot" {
		t.Fatalf("verified trip lost with the local feed: %+v", s)
	}
}

func TestCallerUIDChecked(t *testing.T) {
	e := newEnv(t, "5s")
	d, err := New(Config{WitnessDir: e.wdir, LogKey: e.key, PolicyPath: e.path("etc/gate-policy.toml"),
		OperatorsPath: e.path("etc/operators.txt"), StateDir: e.path("state"), Signer: e.gateKey, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// httptest connections carry no SO_PEERCRED identity: refused.
	srv := httptest.NewServer(d.Handler(nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("caller without credentials: %d", resp.StatusCode)
	}
}

func TestMalformedBodies(t *testing.T) {
	e := newEnv(t, "5s")
	e.start()
	e.synced()
	for name, body := range map[string]string{
		"not json":      "{",
		"unknown field": `{"request":{},"x":1}`,
		"non-canonical": `{"request":{"v":1,  "class":"hot"}}`,
		"too big":       `{"request":"` + strings.Repeat("a", MaxBody) + `"}`,
	} {
		resp, err := e.client().Post("http://gate/v1/decide", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
}

// Acceptance 19 at the socket: the breaker trips while a request is in
// commit-wait. The request is denied at re-validation and nothing issues.
// Polls are driven by hand so the order is fixed.
func TestTripDuringCommitWait(t *testing.T) {
	e := newEnv(t, "10s")
	e.poll = time.Hour
	e.start()
	e.d.Poll()
	e.synced()
	done := make(chan Decision, 1)
	r := e.req("hot", "1000")
	go func() { done <- e.decide(r) }()
	h, _ := proto.ActionHashHex(r)
	e.waitFor("gate_request in the witness log", func() bool {
		es, _ := store.ReadAll(e.wdir, e.key)
		for _, en := range es {
			if en.Event == "gate_request" && strings.Contains(string(en.Data), h) {
				return true
			}
		}
		return false
	})
	if err := e.st.Append("DRIFT", "drift_detected", "drift", nil); err != nil {
		t.Fatal(err)
	}
	e.d.Poll() // sees the gate_request and the drift in one verified head
	d := <-done
	if d.Outcome != "deny" || len(d.Reasons) < 2 || d.Reasons[0] != "REVALIDATION_FAILED" || d.Reasons[1] != "BREAKER_OPEN" || len(d.Token) != 0 {
		t.Fatalf("decision %+v", d)
	}
	if e.d.core.Pending() != 0 {
		t.Fatal("reservation leaked")
	}
}
