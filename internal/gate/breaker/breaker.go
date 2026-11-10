// Package breaker is the gate's circuit breaker (gate-arch.md section 7).
//
// Scopes open on weighted ticks (the soul's warn/escalate/halt model) or on
// an explicit trip. An open scope closes ONLY through a Reset signed by a
// quorum of operators: there is no timer, no half-open state, and nothing in
// this package closes a scope by itself. Every trip and reset bumps the epoch,
// so a token issued before the change is void at the enforcement point.
//
// The package is pure state: no I/O, no clock of its own. The daemon records
// the returned Events in the gate feed and runs the TripAdapter.
package breaker

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// Levels a scope's tick total can reach below a trip.
const (
	LevelNone     = ""
	LevelWarn     = "warn"
	LevelEscalate = "escalate"
)

// Event types, as written to the gate feed.
const (
	EventTrip  = "breaker_trip"
	EventReset = "breaker_reset"
)

// GlobalTriggers are the only triggers allowed to trip the Global scope
// (addendum 6: trips are an availability lever; Global is reserved for a
// broken chain and the gate failing its own self-check).
var GlobalTriggers = map[string]bool{"chain_unverified": true, "self_check": true}

// Errors from Reset.
var (
	ErrNonceSpent = errors.New("reset nonce already used")
	ErrEpoch      = errors.New("reset new_epoch is not the current epoch + 1")
	ErrNotOpen    = errors.New("scope is not open")
	ErrNotGlobal  = errors.New("trigger may not trip the global scope")
)

// Config is the tick model, from the policy's [breaker] table.
type Config struct {
	Window     time.Duration
	WarnAt     int
	EscalateAt int
	HaltAt     int
	Weights    map[string]int // trigger -> weight; missing or 0 = ignored
	Quorum     int            // M for Reset
}

// Event is one state change. Trips carry the trigger; resets carry the
// signed bundle, so a restart can re-check the quorum from the log.
type Event struct {
	Type      string
	Scope     proto.Scope
	Epoch     uint64 // epoch after the change
	Trigger   string
	Reason    string
	Approvers []string
	Bundle    *proto.ResetBundle
	TS        time.Time
}

type tick struct {
	at time.Time
	w  int
}

type openScope struct {
	scope   proto.Scope
	epoch   uint64
	since   time.Time
	trigger string
}

// Breaker holds the epoch, open scopes, tick history and spent reset nonces.
type Breaker struct {
	mu        sync.Mutex
	cfg       Config
	epoch     uint64
	open      map[string]openScope
	ticks     map[string][]tick
	lastReset map[string]time.Time
	nonces    map[string]bool
	restored  bool
}

// New returns a breaker at epoch 0 with nothing open. It reports not
// restored until Restore has run (GATE_NOT_SYNCED until then).
func New(cfg Config) *Breaker {
	return &Breaker{cfg: cfg, open: map[string]openScope{}, ticks: map[string][]tick{},
		lastReset: map[string]time.Time{}, nonces: map[string]bool{}}
}

// SetConfig replaces the tick model (policy reload). Open scopes, the epoch
// and spent nonces are kept.
func (b *Breaker) SetConfig(cfg Config) {
	b.mu.Lock()
	b.cfg = cfg
	b.mu.Unlock()
}

// Covering returns every scope that covers r, broadest first.
func Covering(r proto.ActionRequest) []proto.Scope {
	s := []proto.Scope{
		{Kind: proto.ScopeGlobal},
		{Kind: proto.ScopeClass, Value: r.Class},
		{Kind: proto.ScopePrincipal, Value: r.Principal},
		{Kind: proto.ScopeOriginHost, Value: r.OriginHost},
		{Kind: proto.ScopeDestination, Value: r.Destination},
	}
	if r.Asset != "" {
		s = append(s, proto.Scope{Kind: proto.ScopeAsset, Value: r.Asset})
	}
	return s
}

// Restored reports whether Restore has run.
func (b *Breaker) Restored() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.restored
}

// EpochNum returns the current epoch.
func (b *Breaker) EpochNum() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.epoch
}

// Open returns the first open scope covering r.
func (b *Breaker) Open(r proto.ActionRequest) (proto.Scope, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.open) == 0 {
		return proto.Scope{}, false
	}
	for _, s := range Covering(r) {
		if _, ok := b.open[s.String()]; ok {
			return s, true
		}
	}
	// A scope kind this build does not know covers everything (fail closed),
	// matching proto.Scope.Covers.
	for _, o := range b.open {
		if o.scope.Covers(r) {
			return o.scope, true
		}
	}
	return proto.Scope{}, false
}

// IsOpen reports whether exactly this scope is open.
func (b *Breaker) IsOpen(s proto.Scope) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.open[s.String()]
	return ok
}

func (b *Breaker) sum(key string, now time.Time) int {
	cut := now.Add(-b.cfg.Window)
	ts := b.ticks[key]
	i := 0
	for i < len(ts) && !ts[i].at.After(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(b.ticks, key)
	} else {
		b.ticks[key] = ts
	}
	n := 0
	for _, t := range ts {
		n += t.w
	}
	return n
}

func (b *Breaker) level(n int) string {
	switch {
	case n >= b.cfg.EscalateAt:
		return LevelEscalate
	case n >= b.cfg.WarnAt:
		return LevelWarn
	}
	return LevelNone
}

// Level returns the highest tick level among the scopes covering r.
func (b *Breaker) Level(r proto.ActionRequest, now time.Time) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	best := LevelNone
	for _, s := range Covering(r) {
		switch b.level(b.sum(s.String(), now)) {
		case LevelEscalate:
			return LevelEscalate
		case LevelWarn:
			best = LevelWarn
		}
	}
	return best
}

// AckTime returns the latest reset time among the scopes covering r. Signals
// at or before it were in front of the operators who signed that reset, so
// they no longer count against health or tightening.
func (b *Breaker) AckTime(r proto.ActionRequest) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	var t time.Time
	for _, s := range Covering(r) {
		if x := b.lastReset[s.String()]; x.After(t) {
			t = x
		}
	}
	return t
}

// Tick adds trigger's weight to scope and trips it at halt. It returns the
// scope's level and the trip event, if it tripped. Ticks on an open scope are
// dropped (it cannot get more open). A trigger outside GlobalTriggers cannot
// touch Global.
func (b *Breaker) Tick(trigger string, s proto.Scope, now time.Time) (string, *Event, error) {
	if err := s.Validate(); err != nil {
		return "", nil, err
	}
	if s.Kind == proto.ScopeGlobal && !GlobalTriggers[trigger] {
		return "", nil, fmt.Errorf("%w: %s", ErrNotGlobal, trigger)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.cfg.Weights[trigger]
	key := s.String()
	if w <= 0 {
		return b.level(b.sum(key, now)), nil, nil
	}
	if _, ok := b.open[key]; ok {
		return LevelNone, nil, nil
	}
	b.ticks[key] = append(b.ticks[key], tick{at: now, w: w})
	n := b.sum(key, now)
	if n >= b.cfg.HaltAt {
		ev := b.trip(s, trigger, fmt.Sprintf("%s reached %d (halt_at %d)", trigger, n, b.cfg.HaltAt), now)
		return LevelNone, &ev, nil
	}
	return b.level(n), nil, nil
}

// Trip opens s now. Tripping an open scope is a no-op (nil event).
func (b *Breaker) Trip(trigger string, s proto.Scope, reason string, now time.Time) (*Event, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.Kind == proto.ScopeGlobal && !GlobalTriggers[trigger] {
		return nil, fmt.Errorf("%w: %s", ErrNotGlobal, trigger)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.open[s.String()]; ok {
		return nil, nil
	}
	ev := b.trip(s, trigger, reason, now)
	return &ev, nil
}

func (b *Breaker) trip(s proto.Scope, trigger, reason string, now time.Time) Event {
	b.epoch++
	b.open[s.String()] = openScope{scope: s, epoch: b.epoch, since: now, trigger: trigger}
	delete(b.ticks, s.String())
	return Event{Type: EventTrip, Scope: s, Epoch: b.epoch, Trigger: trigger, Reason: reason, TS: now}
}

// Reset closes bundle.Reset.Scope if at least Quorum distinct operators in
// ops signed it, its nonce is unused, it names the next epoch and the scope
// is open. Any failure changes nothing.
func (b *Breaker) Reset(bundle proto.ResetBundle, ops []proto.Operator, now time.Time) (*Event, error) {
	labels, err := proto.VerifyResetQuorum(bundle, ops, b.quorum())
	if err != nil {
		return nil, err
	}
	r := bundle.Reset
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nonces[r.Nonce] {
		return nil, ErrNonceSpent
	}
	if r.NewEpoch != b.epoch+1 {
		return nil, fmt.Errorf("%w (current %d, reset names %d): re-sign against the current epoch", ErrEpoch, b.epoch, r.NewEpoch)
	}
	key := r.Scope.String()
	if _, ok := b.open[key]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotOpen, key)
	}
	b.nonces[r.Nonce] = true
	b.epoch = r.NewEpoch
	delete(b.open, key)
	delete(b.ticks, key)
	b.lastReset[key] = now
	bb := bundle
	return &Event{Type: EventReset, Scope: r.Scope, Epoch: b.epoch, Reason: r.Reason,
		Approvers: labels, Bundle: &bb, TS: now}, nil
}

func (b *Breaker) quorum() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.Quorum
}

// SpendNonce marks a reset nonce used without applying the reset (a nonce
// seen anywhere, even in an unverified local record, is spent).
func (b *Breaker) SpendNonce(n string) {
	b.mu.Lock()
	b.nonces[n] = true
	b.mu.Unlock()
}

// Epoch returns the unsigned Epoch statement; the daemon signs it.
func (b *Breaker) Epoch(now time.Time) proto.Epoch {
	b.mu.Lock()
	defer b.mu.Unlock()
	scopes := make([]proto.Scope, 0, len(b.open))
	for _, o := range b.open {
		scopes = append(scopes, o.scope)
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].String() < scopes[j].String() })
	return proto.Epoch{V: proto.Version, Epoch: b.epoch, OpenScopes: scopes, IssuedAt: proto.FormatTime(now)}
}

// OpenScopes returns the open scopes, sorted.
func (b *Breaker) OpenScopes() []proto.Scope { return b.Epoch(time.Time{}).OpenScopes }

// Restore rebuilds state after a restart (gate-arch.md C14) and marks the
// breaker restored. The rule is that the more restrictive source wins:
//
//   - a trip counts from either source (the verified log, or the gate's local
//     feed/state, whose newest lines may not have reached the log yet);
//   - a reset counts only from the verified log, and only if its quorum
//     re-verifies against ops now;
//   - a scope is open if its newest trip epoch is not below its newest
//     counted reset epoch (a tie stays open);
//   - every reset nonce seen in either source is spent;
//   - the epoch is the highest seen anywhere.
//
// Tick history is not restored: it only ever leads to a trip, and trips are.
func (b *Breaker) Restore(verified, local []Event, ops []proto.Operator) {
	b.mu.Lock()
	defer b.mu.Unlock()
	quorum := b.cfg.Quorum
	tripE := map[string]uint64{}
	tripS := map[string]openScope{}
	resetE := map[string]uint64{}
	resetT := map[string]time.Time{}
	epoch := b.epoch
	see := func(e Event, fromLog bool) {
		if e.Epoch > epoch {
			epoch = e.Epoch
		}
		key := e.Scope.String()
		switch e.Type {
		case EventTrip:
			if _, seen := tripE[key]; !seen || e.Epoch >= tripE[key] {
				tripE[key] = e.Epoch
				tripS[key] = openScope{scope: e.Scope, epoch: e.Epoch, since: e.TS, trigger: e.Trigger}
			}
		case EventReset:
			if e.Bundle != nil {
				b.nonces[e.Bundle.Reset.Nonce] = true
			}
			if !fromLog || e.Bundle == nil || e.Bundle.Reset.Scope != e.Scope || e.Bundle.Reset.NewEpoch != e.Epoch {
				return
			}
			if _, err := proto.VerifyResetQuorum(*e.Bundle, ops, quorum); err != nil {
				return
			}
			if e.Epoch >= resetE[key] {
				resetE[key] = e.Epoch
				resetT[key] = e.TS
			}
		}
	}
	for _, e := range verified {
		see(e, true)
	}
	for _, e := range local {
		see(e, false)
	}
	for key, te := range tripE {
		if re, ok := resetE[key]; ok && re > te {
			delete(b.open, key)
			continue
		}
		b.open[key] = tripS[key]
	}
	// Only a reset that actually closed its scope acknowledges signals.
	for key, t := range resetT {
		if _, open := b.open[key]; !open && t.After(b.lastReset[key]) {
			b.lastReset[key] = t
		}
	}
	b.epoch = epoch
	b.restored = true
}

// AckedAt returns the latest reset of s or of Global: a signal at or before
// it has been reviewed by a quorum and must not tick s again.
func (b *Breaker) AckedAt(s proto.Scope) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.lastReset[s.String()]
	if g := b.lastReset[proto.Scope{Kind: proto.ScopeGlobal}.String()]; g.After(t) {
		t = g
	}
	return t
}
