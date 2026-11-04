// Package daemon is the running gate: it owns the evidence view, the policy,
// the breaker and the decision core, serves them on a unix socket, writes
// every decision, trip, reset and policy load to the gate feed, and signs
// tokens and epochs. cmd/gate is a thin CLI around it.
//
// What the gate writes: its feed (fsynced, fail closed), its state file and
// nothing else. It reads the witness log through the read-only evidence view
// and never opens it for writing.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/breaker"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/core"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/feed"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Defaults.
const (
	DefaultPollInterval    = time.Second
	DefaultFullVerifyEvery = 10 * time.Minute
)

// Config wires a Daemon.
type Config struct {
	WitnessDir      string // the witness primary directory (read only)
	LogKey          []byte // machine-derived log key (encrypt.DeriveKey(machid.Get()))
	PolicyPath      string // gate-policy.toml; its signature is PolicyPath + ".sig"
	OperatorsPath   string // operators.txt
	StateDir        string // state.json lives here
	FeedPath        string // the gate feed; default StateDir/gate.jsonl
	Signer          proto.Signer
	PollInterval    time.Duration
	FullVerifyEvery time.Duration
	Adapter         breaker.TripAdapter // default: log-only to Log
	Log             io.Writer           // operator-facing messages; default stderr
	Now             func() time.Time
}

// Daemon is the gate process.
// feedWriter is the gate feed (feed.Writer); an interface so tests can
// inject a failure on one record kind.
type feedWriter interface {
	Write(kind, level string, fields map[string]string) error
	Healthy() error
	Close() error
}

type Daemon struct {
	cfg  Config
	feed feedWriter
	br   *breaker.Breaker
	core *core.Core
	key  string // hex gate key

	mu        sync.Mutex
	view      *evidence.View
	pol       *policy.Loaded
	polErr    error
	ops       []proto.Operator
	restored  bool
	epoch     []byte // canonical signed Epoch
	epochErr  error
	pollErr   error
	pollCh    chan struct{} // closed after every poll, then replaced
	lastFull  time.Time
	edgesSeen int
	priorTop  uint64
	priorN    int
}

// New loads operators, the policy and the persisted state and opens the
// feed. Problems with any of them do not stop the gate: it runs in deny-all
// and says why in status and in the feed (a gate that refuses to start
// leaves the enforcement point with no fresh epoch, which also fails closed,
// but tells the operator less).
func New(cfg Config) (*Daemon, error) {
	if cfg.Signer == nil {
		return nil, errors.New("gate: a signer is required")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("gate: a state directory is required")
	}
	if cfg.FeedPath == "" {
		cfg.FeedPath = filepath.Join(cfg.StateDir, "gate.jsonl")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.FullVerifyEvery <= 0 {
		cfg.FullVerifyEvery = DefaultFullVerifyEvery
	}
	if cfg.Log == nil {
		cfg.Log = os.Stderr
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Adapter == nil {
		cfg.Adapter = &breaker.LogOnly{W: cfg.Log}
	}
	d := &Daemon{cfg: cfg, br: breaker.New(breaker.Config{}), key: hex.EncodeToString(cfg.Signer.PublicKey()),
		pollCh: make(chan struct{})}
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		return nil, err
	}
	if w, err := feed.Open(cfg.FeedPath, cfg.Now); err != nil {
		d.logf("gate feed %s cannot be opened: %v: no tokens will be issued", cfg.FeedPath, err)
	} else {
		d.feed = w
	}
	st := d.loadState()
	d.core = core.New(core.Config{Breaker: d.br, Evidence: noEvidence{}, Now: cfg.Now})
	d.core.LearnEdges(st.Edges...)
	d.edgesSeen = len(st.Edges)
	d.record("gate_start", "", map[string]string{"gate_key": d.key})
	d.selfCheck()
	d.loadPolicy(st.Priors)
	d.signEpoch()
	return d, nil
}

func (d *Daemon) logf(format string, a ...any) {
	fmt.Fprintf(d.cfg.Log, "[gate] "+format+"\n", a...)
}

// record writes one feed line. It returns the error so issuing paths can fail
// closed; callers that only inform (denies, status) log and carry on.
func (d *Daemon) record(kind, level string, fields map[string]string) error {
	if d.feed == nil {
		return fmt.Errorf("%w: not open", feed.ErrBroken)
	}
	err := d.feed.Write(kind, level, fields)
	if err != nil {
		d.logf("feed write %s failed: %v", kind, err)
	}
	return err
}

// selfCheck signs and verifies a token-domain test message. A gate whose key
// cannot sign correctly trips Global (one of the two triggers allowed to).
func (d *Daemon) selfCheck() {
	msg := []byte(proto.DomainToken + "self-check")
	sig, err := d.cfg.Signer.Sign(msg)
	if err == nil && !ed25519.Verify(d.cfg.Signer.PublicKey(), msg, sig) {
		err = errors.New("signature does not verify")
	}
	if err != nil {
		ev, _ := d.br.Trip("self_check", proto.Scope{Kind: proto.ScopeGlobal}, "gate key self-check failed: "+err.Error(), d.cfg.Now())
		d.recordEvents(nilIfNil(ev))
	}
}

func nilIfNil(e *breaker.Event) []breaker.Event {
	if e == nil {
		return nil
	}
	return []breaker.Event{*e}
}

// loadPolicy (re)loads the signed policy. A failure keeps the previous valid
// policy if there is one, else deny-all, and is recorded as POLICY_INVALID.
func (d *Daemon) loadPolicy(priors []store.TreeHead) {
	ops, err := policy.LoadOperators(d.cfg.OperatorsPath)
	var l *policy.Loaded
	if err == nil {
		l, err = policy.Load(d.cfg.PolicyPath, ops)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.polErr = err
		d.logf("policy not loaded (%v); %s", err, map[bool]string{true: "keeping the previous policy", false: "deny-all"}[d.pol != nil])
		d.record("policy_invalid", "CRITICAL", map[string]string{"error": err.Error(), "path": d.cfg.PolicyPath})
		return
	}
	if d.view == nil {
		v, verr := evidence.New(evidence.Config{Dir: d.cfg.WitnessDir, Key: d.cfg.LogKey,
			Pins: l.Policy.WitnessKeys(), Priors: priors, Now: d.cfg.Now})
		if verr != nil {
			d.polErr = fmt.Errorf("%w: evidence view: %v", policy.ErrInvalid, verr)
			d.record("policy_invalid", "CRITICAL", map[string]string{"error": d.polErr.Error()})
			return
		}
		d.view = v
		d.core = core.New(core.Config{Policy: l, Operators: ops, Breaker: d.br, Evidence: v, Now: d.cfg.Now})
		d.core.LearnEdges(d.loadState().Edges...)
	} else {
		// The view's pins are fixed at its creation: a reload that changes
		// witness_keys takes effect at the next restart, and says so.
		if !sameKeys(l.Policy.WitnessKeys(), d.pol.Policy.WitnessKeys()) {
			d.logf("policy changes witness_keys: restart the gate to re-pin the witness")
		}
		d.core.SetPolicy(l)
	}
	d.pol, d.polErr, d.ops = l, nil, ops
	d.record("policy_load", "", map[string]string{"policy_hash": l.Hash, "signed_by": l.SignedBy, "path": d.cfg.PolicyPath})
}

func sameKeys(a, b []ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// ReloadPolicy is SIGHUP.
func (d *Daemon) ReloadPolicy() { d.loadPolicy(nil) }

// noEvidence stands in before a policy (and so the witness pins) is known.
type noEvidence struct{}

func (noEvidence) Status() evidence.Status                               { return evidence.Status{} }
func (noEvidence) Signals(time.Time, ...evidence.Kind) []evidence.Signal { return nil }

// Poll is one cycle of the background loop: poll the evidence, rebuild the
// breaker on the first verified poll, feed new signals to the core, record
// trips, persist state, re-sign the epoch, and wake commit-waiters.
func (d *Daemon) Poll() {
	d.mu.Lock()
	v, c := d.view, d.core
	d.mu.Unlock()
	var err error
	if v != nil {
		err = v.Poll()
		if err == nil && !d.isRestored() {
			d.restore(v)
		}
		if d.isRestored() || errors.Is(err, evidence.ErrChainUnverified) {
			d.recordEvents(c.Sync())
		}
		d.saveState(v, c)
	}
	d.mu.Lock()
	d.pollErr = err
	ch := d.pollCh
	d.pollCh = make(chan struct{})
	d.mu.Unlock()
	close(ch)
	d.signEpoch()
}

// FullVerify is the periodic whole-log re-read (evidence.View.FullVerify).
func (d *Daemon) FullVerify() error {
	d.mu.Lock()
	v := d.view
	d.mu.Unlock()
	if v == nil {
		return nil
	}
	err := v.FullVerify()
	if err != nil {
		d.Poll() // a chain failure trips Global through Sync
	}
	return err
}

func (d *Daemon) isRestored() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.restored
}

// restore rebuilds the breaker (C14): trips from the verified log and the
// local feed, resets only from the verified log with quorum re-checked.
func (d *Daemon) restore(v *evidence.View) {
	var verified []breaker.Event
	for _, s := range v.GateEvents() {
		var m map[string]any
		if json.Unmarshal(s.Data, &m) != nil {
			continue
		}
		f := map[string]string{}
		for k, x := range m {
			if str, ok := x.(string); ok {
				f[k] = str
			}
		}
		f["kind"] = s.Event
		if e, ok := decodeEvent(f); ok {
			verified = append(verified, e)
		}
	}
	var local []breaker.Event
	lines, err := feed.Read(d.cfg.FeedPath)
	if err != nil {
		d.logf("reading the local feed for restore: %v", err)
	}
	for _, f := range lines {
		if e, ok := decodeEvent(f); ok {
			local = append(local, e)
		}
	}
	d.mu.Lock()
	ops := d.ops
	d.mu.Unlock()
	d.br.Restore(verified, local, ops)
	d.mu.Lock()
	d.restored = true
	d.mu.Unlock()
	open := d.br.OpenScopes()
	names := make([]string, len(open))
	for i, s := range open {
		names[i] = s.String()
	}
	d.record("breaker_restored", "", map[string]string{"epoch": strconv.FormatUint(d.br.EpochNum(), 10),
		"open_scopes": strings.Join(names, ","), "verified_events": strconv.Itoa(len(verified)), "local_events": strconv.Itoa(len(local))})
}

// recordEvents writes trips and resets to the feed and runs the trip
// adapter. The breaker state has already changed; a failed write leaves it
// changed (the restrictive direction) and the feed broken, so nothing issues.
func (d *Daemon) recordEvents(evs []breaker.Event) {
	for _, e := range evs {
		level := "WARN"
		if e.Scope.Kind == proto.ScopeGlobal {
			level = "CRITICAL"
		}
		d.record(e.Type, level, encodeEvent(e))
		if e.Type == breaker.EventTrip {
			e := e
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := d.cfg.Adapter.OnTrip(ctx, e); err != nil {
					d.logf("trip adapter: %v", err)
				}
			}()
		}
	}
	if len(evs) > 0 {
		d.signEpoch()
	}
}

// signEpoch re-signs the current Epoch. The enforcement point refuses a
// high-tier action without an epoch fresher than its max age (10 s default),
// so this runs on every poll, not only on change.
func (d *Daemon) signEpoch() {
	e, err := proto.SignEpoch(d.br.Epoch(d.cfg.Now()), d.cfg.Signer)
	var raw []byte
	if err == nil {
		raw, err = proto.Canonical(e)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.epochErr = err
		return
	}
	d.epoch, d.epochErr = raw, nil
}

// Epoch returns the current signed epoch (canonical JSON).
func (d *Daemon) Epoch() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.epoch, d.epochErr
}

// Reset applies a quorum-signed reset and records it. If the record cannot
// be written the scope is tripped again: a reset nobody can see later must
// not stand.
func (d *Daemon) Reset(b proto.ResetBundle) (breaker.Event, error) {
	d.mu.Lock()
	ops := d.ops
	restored := d.restored
	d.mu.Unlock()
	if !restored {
		return breaker.Event{}, errors.New("GATE_NOT_SYNCED: breaker not rebuilt yet")
	}
	ev, err := d.br.Reset(b, ops, d.cfg.Now())
	if err != nil {
		d.record("breaker_reset_rejected", "WARN", map[string]string{"scope": b.Reset.Scope.String(),
			"new_epoch": strconv.FormatUint(b.Reset.NewEpoch, 10), "nonce": b.Reset.Nonce, "error": err.Error()})
		return breaker.Event{}, err
	}
	if werr := d.record(ev.Type, "WARN", encodeEvent(*ev)); werr != nil {
		// self_check is the one trigger allowed on every scope, Global included.
		d.br.Trip("self_check", b.Reset.Scope, "reset could not be written to the gate feed", d.cfg.Now())
		d.signEpoch()
		return breaker.Event{}, fmt.Errorf("%s: %w", core.FeedWriteFailed, werr)
	}
	d.signEpoch()
	return *ev, nil
}

// Decision is what /v1/decide returns.
type Decision struct {
	Outcome    string          `json:"outcome"`
	Reasons    []string        `json:"reasons,omitempty"`
	Detail     string          `json:"detail,omitempty"`
	ActionHash string          `json:"action_hash,omitempty"`
	Approvers  []string        `json:"approvers,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Token      json.RawMessage `json:"token,omitempty"` // canonical proto.Token
}

func strs[T ~string](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = string(x)
	}
	return out
}

func denyOf(cd core.Decision, extra ...core.Reason) Decision {
	return Decision{Outcome: string(core.Deny), Reasons: append(strs(extra), strs(cd.Reasons)...), Detail: cd.Detail,
		ActionHash: cd.ActionHash, Approvers: cd.Approvers, Warnings: strs(cd.Warnings)}
}

func (d *Daemon) logDecision(req proto.ActionRequest, out Decision) {
	level := ""
	if out.Outcome != string(core.Allow) {
		level = "WARN"
	}
	d.record("gate_decision", level, map[string]string{
		"action_hash": out.ActionHash, "outcome": out.Outcome, "reasons": strings.Join(out.Reasons, ","),
		"detail": out.Detail, "class": req.Class, "principal": req.Principal, "origin_host": req.OriginHost,
		"target": req.Target, "destination": req.Destination, "asset": req.Asset, "amount": req.Amount,
		"approvers": strings.Join(out.Approvers, ","), "warnings": strings.Join(out.Warnings, ","),
	})
}

// Decide runs the full decision flow (gate-arch.md section 6) for one
// request, including the feed writes, commit-wait, re-validation and
// signing, and records the outcome.
func (d *Daemon) Decide(ctx context.Context, req proto.ActionRequest, approvals []proto.Approval) Decision {
	d.mu.Lock()
	c := d.core
	d.mu.Unlock()
	cd := c.Decide(req, approvals)
	d.recordEvents(cd.Events)
	if len(cd.Learned) > 0 {
		d.record("gate_edge_learned", "", map[string]string{"edges": strings.Join(cd.Learned, ","), "class": req.Class})
	}
	var out Decision
	switch cd.Outcome {
	case core.Allow:
		out = d.issue(ctx, c, req, cd)
	case core.Escalate:
		out = Decision{Outcome: string(core.Escalate), Reasons: strs(cd.Reasons), Detail: cd.Detail, ActionHash: cd.ActionHash}
	default:
		out = denyOf(cd)
	}
	d.logDecision(req, out)
	return out
}

// issue is steps 7–9 for an admitted request. Every exit that does not
// return a token releases the reservation unissued (refund).
func (d *Daemon) issue(ctx context.Context, c *core.Core, req proto.ActionRequest, cd core.Decision) Decision {
	res := cd.Res
	if err := d.record("gate_request", "", map[string]string{
		"action_hash": cd.ActionHash, "class": req.Class, "principal": req.Principal, "origin_host": req.OriginHost,
		"target": req.Target, "destination": req.Destination, "asset": req.Asset, "amount": req.Amount,
		"approvers": strings.Join(cd.Approvers, ","), "policy_hash": res.PolicyHash,
		"epoch": strconv.FormatUint(d.br.EpochNum(), 10),
	}); err != nil {
		c.Release(res, false)
		return denyOf(cd, core.FeedWriteFailed)
	}
	var witnessed *proto.Witnessed
	if cd.Class.CommitWait {
		w, err := d.waitWitnessed(ctx, cd.ActionHash, cd.Class.CommitWaitTimeout.Duration)
		if err != nil {
			d.recordEvents(c.CommitWaitTimeout(res))
			out := denyOf(cd, core.CommitWaitTimeout)
			out.Detail = err.Error()
			return out
		}
		witnessed = &w
	}
	rv := c.Revalidate(res)
	if rv.Outcome != core.Allow {
		rv.ActionHash = cd.ActionHash
		return denyOf(rv)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		c.Release(res, false)
		return denyOf(cd, core.FeedWriteFailed)
	}
	now := d.cfg.Now()
	tok, err := proto.SignToken(proto.Token{V: proto.Version, TokenID: hex.EncodeToString(id), ActionHash: cd.ActionHash,
		IssuedAt: proto.FormatTime(now), ExpiresAt: proto.FormatTime(now.Add(cd.Class.TokenLifetime.Duration)),
		BreakerEpoch: d.br.EpochNum(), PolicyHash: res.PolicyHash, Witnessed: witnessed}, d.cfg.Signer)
	var raw []byte
	if err == nil {
		raw, err = proto.Canonical(tok)
	}
	if err != nil {
		d.logf("signing token: %v", err)
		c.Release(res, false)
		ev, _ := d.br.Trip("self_check", proto.Scope{Kind: proto.ScopeGlobal}, "token signing failed: "+err.Error(), now)
		d.recordEvents(nilIfNil(ev))
		return denyOf(cd, core.BreakerOpen)
	}
	// The key-use record goes out before the token does.
	if err := d.record("gate_issued", "", map[string]string{"action_hash": cd.ActionHash, "token_id": tok.TokenID,
		"expires_at": tok.ExpiresAt, "epoch": strconv.FormatUint(tok.BreakerEpoch, 10),
		"witnessed": strconv.FormatBool(witnessed != nil)}); err != nil {
		c.Release(res, false)
		return denyOf(cd, core.FeedWriteFailed)
	}
	c.Release(res, true)
	return Decision{Outcome: string(core.Allow), ActionHash: cd.ActionHash, Approvers: cd.Approvers,
		Warnings: strs(cd.Warnings), Token: raw}
}

// waitWitnessed blocks until a verified head covers the gate_request record,
// or timeout. Commit-wait latency is the witness feed tail (≤ 0.2 s) plus
// its append plus the gate's next poll.
func (d *Daemon) waitWitnessed(ctx context.Context, hash string, timeout time.Duration) (proto.Witnessed, error) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		d.mu.Lock()
		v, ch := d.view, d.pollCh
		d.mu.Unlock()
		if v == nil {
			return proto.Witnessed{}, errors.New("no evidence view")
		}
		w, err := v.Inclusion(hash)
		if err == nil {
			return w, nil
		}
		if !errors.Is(err, evidence.ErrNotWitnessed) {
			return proto.Witnessed{}, err
		}
		select {
		case <-ch:
		case <-t.C:
			return proto.Witnessed{}, fmt.Errorf("gate_request not in a verified witness head after %s", timeout)
		case <-ctx.Done():
			return proto.Witnessed{}, ctx.Err()
		}
	}
}

// Status is /v1/status.
type Status struct {
	GateKey       string   `json:"gate_key"`
	Synced        bool     `json:"synced"`
	Restored      bool     `json:"breaker_restored"`
	ChainFailure  string   `json:"chain_failure,omitempty"`
	PollError     string   `json:"poll_error,omitempty"`
	HeadSize      uint64   `json:"head_size"`
	HeadAgeSec    float64  `json:"head_age_seconds"`
	Epoch         uint64   `json:"epoch"`
	OpenScopes    []string `json:"open_scopes"`
	PolicyHash    string   `json:"policy_hash,omitempty"`
	PolicyError   string   `json:"policy_error,omitempty"`
	FeedError     string   `json:"feed_error,omitempty"`
	Pending       int      `json:"pending"`
	DenyAllReason string   `json:"deny_all,omitempty"`
}

// Status reports health for operators.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	v, pol, polErr, pollErr, restored, c := d.view, d.pol, d.polErr, d.pollErr, d.restored, d.core
	d.mu.Unlock()
	s := Status{GateKey: d.key, Restored: restored, Epoch: d.br.EpochNum(), Pending: c.Pending(), OpenScopes: []string{}}
	for _, o := range d.br.OpenScopes() {
		s.OpenScopes = append(s.OpenScopes, o.String())
	}
	if v != nil {
		st := v.Status()
		s.Synced, s.HeadSize = st.Synced, st.Size
		if st.HeadAge < time.Duration(1<<62) {
			s.HeadAgeSec = st.HeadAge.Seconds()
		} else {
			s.HeadAgeSec = -1
		}
		if st.Failure != nil {
			s.ChainFailure = st.Failure.Error()
		}
	}
	if pollErr != nil {
		s.PollError = pollErr.Error()
	}
	if pol != nil {
		s.PolicyHash = pol.Hash
	}
	if polErr != nil {
		s.PolicyError = polErr.Error()
	}
	if d.feed == nil {
		s.FeedError = "feed not open"
	} else if err := d.feed.Healthy(); err != nil {
		s.FeedError = err.Error()
	}
	switch {
	case pol == nil:
		s.DenyAllReason = string(core.PolicyInvalid)
	case s.FeedError != "":
		s.DenyAllReason = string(core.FeedWriteFailed)
	case s.ChainFailure != "":
		s.DenyAllReason = string(core.ChainUnverified)
	case !s.Synced || !restored:
		s.DenyAllReason = string(core.GateNotSynced)
	}
	return s
}

// Run polls until ctx ends.
func (d *Daemon) Run(ctx context.Context) {
	poll := time.NewTicker(d.cfg.PollInterval)
	defer poll.Stop()
	full := time.NewTicker(d.cfg.FullVerifyEvery)
	defer full.Stop()
	d.Poll()
	for {
		select {
		case <-ctx.Done():
			d.record("gate_stop", "", nil)
			return
		case <-poll.C:
			d.Poll()
		case <-full.C:
			go func() {
				if err := d.FullVerify(); err != nil {
					d.logf("full verify: %v", err)
				}
			}()
		}
	}
}

// Close closes the feed.
func (d *Daemon) Close() error {
	if d.feed != nil {
		return d.feed.Close()
	}
	return nil
}
