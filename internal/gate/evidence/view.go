// Package evidence is the gate's read-only, verified view of one witness log.
//
// The gate never opens the log for writing and never calls store.Open,
// OpenTrusting or OpenPinned. It reads with store.ReadSince (incremental) and
// store.ExportDir (periodic full check), both read-only. A record counts as
// evidence only after:
//
//   - the head is signed by a pinned witness key (the key the head names is
//     never taken at its word);
//   - the root recomputed from every record the gate has verified so far plus
//     the new ones equals the head's root, so each new head extends the last
//     (the append-only check against every head the gate has ever seen, by
//     induction, at O(new records));
//   - every prior head retained from earlier runs is a prefix of the log.
//
// Any failure is a ChainError (CHAIN_UNVERIFIED) and is sticky: the view never
// clears it on its own. A rewritten or truncated log means the evidence is
// gone; only a restart, which re-verifies from scratch against the retained
// priors, builds a new view.
//
// Head age is measured on the gate's own clock as the time since a head with
// MORE records was verified. The head's timestamp is not signed (gate-arch C1)
// and a replayed or re-signed head of the same size does not refresh it.
package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// ErrChainUnverified is the class of every integrity failure (reason code
// CHAIN_UNVERIFIED). Test with errors.Is.
var ErrChainUnverified = errors.New("CHAIN_UNVERIFIED")

// ChainError is an integrity failure of the witness log.
type ChainError struct{ Reason string }

func (e *ChainError) Error() string        { return "CHAIN_UNVERIFIED: " + e.Reason }
func (e *ChainError) Is(target error) bool { return target == ErrChainUnverified }

func chain(format string, a ...any) error { return &ChainError{Reason: fmt.Sprintf(format, a...)} }

// Defaults.
const (
	DefaultLookback   = 24 * time.Hour
	DefaultMaxSignals = 100_000
	maxPriors         = 256
	priorEvery        = time.Minute
)

// Config configures a View.
type Config struct {
	Dir  string              // the witness primary directory
	Key  []byte              // machine-derived log key (encrypt.DeriveKey(machid.Get()))
	Pins []ed25519.PublicKey // witness tree-head keys; at least one
	// Priors are heads retained from earlier runs (Priors() of the last view,
	// persisted by the daemon). Each must be a prefix of the log.
	Priors     []store.TreeHead
	Lookback   time.Duration // how long signals are kept (default 24h)
	MaxSignals int           // cap on kept signals, oldest dropped first (default 100000)
	Now        func() time.Time
}

// View is the verified evidence. Safe for concurrent use; Poll is meant to be
// called from one goroutine.
type View struct {
	cfg Config

	mu        sync.RWMutex
	synced    bool
	failure   error
	leaves    [][32]byte
	fr        frontier
	off       int64
	head      store.TreeHead
	grewAt    time.Time // gate clock: when a larger head was last verified
	lastPoll  time.Time
	priors    []store.TreeHead // retained heads, oldest first
	priorAt   time.Time
	signals   []Signal
	lastSeen  map[string]time.Time // source → newest record timestamp
	lastEvent map[string]Signal    // source + "\x00" + event → newest record
}

// New returns an unsynced view. The first Poll verifies the whole log.
func New(cfg Config) (*View, error) {
	if len(cfg.Pins) == 0 {
		return nil, errors.New("evidence: at least one pinned witness key is required")
	}
	if cfg.Dir == "" || len(cfg.Key) == 0 {
		return nil, errors.New("evidence: witness directory and log key are required")
	}
	if cfg.Lookback <= 0 {
		cfg.Lookback = DefaultLookback
	}
	if cfg.MaxSignals <= 0 {
		cfg.MaxSignals = DefaultMaxSignals
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pr := append([]store.TreeHead(nil), cfg.Priors...)
	sort.Slice(pr, func(i, j int) bool { return pr[i].Size < pr[j].Size })
	cfg.Priors = pr
	return &View{cfg: cfg, lastSeen: map[string]time.Time{}, lastEvent: map[string]Signal{}}, nil
}

// Poll reads and verifies whatever the witness appended since the last poll
// (the whole log on the first). It returns a ChainError on any integrity
// failure (and every later Poll returns the same one), or a plain error for a
// read problem that may clear (the view stays as it was).
func (v *View) Poll() error {
	v.mu.RLock()
	if v.failure != nil {
		defer v.mu.RUnlock()
		return v.failure
	}
	off, have := v.off, uint64(len(v.leaves))
	v.mu.RUnlock()

	head, entries, next, err := store.ReadSince(v.cfg.Dir, v.cfg.Key, off, have)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lastPoll = v.cfg.Now()
	switch {
	case errors.Is(err, store.ErrHeadBehind):
		return v.fail(chain("head covers %d records, %d already verified: log truncated or head rolled back", head.Size, have))
	case errors.Is(err, store.ErrMissingTreeHead):
		return v.fail(chain("tree head missing for a log with records"))
	case errors.Is(err, store.ErrLogShort):
		return v.fail(chain("%v", err))
	case err != nil:
		return fmt.Errorf("evidence: read witness log: %w", err)
	}
	return v.ingest(head, entries, next)
}

// ingest verifies head against the held leaves plus entries and, if it
// holds, accepts them. Called with v.mu held.
func (v *View) ingest(head store.TreeHead, entries []store.Entry, next int64) error {
	have := uint64(len(v.leaves))
	if head.Size != have+uint64(len(entries)) {
		return v.fail(chain("head covers %d records, read %d new after %d", head.Size, len(entries), have))
	}
	if head.Size == 0 {
		// An empty log has no head to verify. A prior with records means
		// the log was truncated to nothing.
		for _, p := range v.cfg.Priors {
			if p.Size > 0 {
				return v.fail(chain("log is empty but a retained head covered %d records: truncated", p.Size))
			}
		}
		v.synced = true
		return nil
	}
	if err := store.VerifyHeadSignature(head, v.cfg.Pins); err != nil {
		return v.fail(chain("tree head (size %d) not signed by a pinned witness key: %v", head.Size, err))
	}
	fr := v.fr.clone()
	leaves := make([][32]byte, len(entries))
	priors := v.cfg.Priors
	for len(priors) > 0 && priors[0].Size <= have {
		priors = priors[1:] // checked by an earlier ingest
	}
	for i, e := range entries {
		leaves[i] = store.LeafHash(e)
		fr.push(leaves[i])
		for len(priors) > 0 && priors[0].Size == fr.n {
			if r := fr.root(); hex.EncodeToString(r[:]) != priors[0].Root {
				return v.fail(chain("a retained head (size %d) is not a prefix of this log: rewritten after that head", priors[0].Size))
			}
			priors = priors[1:]
		}
	}
	if len(priors) > 0 {
		// The witness only appends, so a log shorter than any head the gate
		// has seen was truncated.
		return v.fail(chain("a retained head covered %d records, the log now has %d: truncated", priors[0].Size, head.Size))
	}
	if r := fr.root(); hex.EncodeToString(r[:]) != head.Root {
		if len(entries) == 0 {
			return v.fail(chain("head of size %d has a different root than the verified log: rewritten in place", head.Size))
		}
		return v.fail(chain("head of size %d does not extend the %d verified records: log rewritten", head.Size, have))
	}
	v.accept(head, leaves, fr, next, entries)
	v.synced = true
	return nil
}

func (v *View) accept(head store.TreeHead, leaves [][32]byte, fr frontier, next int64, entries []store.Entry) {
	now := v.cfg.Now()
	if fr.n > uint64(len(v.leaves)) {
		v.grewAt = now
	}
	v.leaves = append(v.leaves, leaves...)
	v.fr, v.off, v.head = fr, next, head
	if len(v.priors) == 0 || now.Sub(v.priorAt) >= priorEvery {
		v.priors = append(v.priors, head)
		v.priorAt = now
		if len(v.priors) > maxPriors {
			v.priors = v.priors[len(v.priors)-maxPriors:]
		}
	}
	for _, e := range entries {
		v.lastSeen[e.Source] = e.Timestamp
		kind, keep := classify(e)
		if !keep {
			continue
		}
		s := Signal{Seq: e.Seq, TS: e.Timestamp, Level: e.Level, Source: e.Source, Event: e.Event,
			Kind: kind, Critical: e.Level == "CRITICAL" || e.Level == "DEATH", Data: e.Data}
		v.signals = append(v.signals, s)
		v.lastEvent[e.Source+"\x00"+e.Event] = s
	}
	v.prune(now)
}

func (v *View) prune(now time.Time) {
	cut := 0
	for cut < len(v.signals) && now.Sub(v.signals[cut].TS) > v.cfg.Lookback {
		cut++
	}
	if over := len(v.signals) - cut - v.cfg.MaxSignals; over > 0 {
		cut += over
	}
	if cut > 0 {
		v.signals = append([]Signal(nil), v.signals[cut:]...)
	}
}

func (v *View) fail(err error) error {
	if v.failure == nil {
		v.failure = err
	}
	v.synced = false
	return v.failure
}

// FullVerify re-reads the whole log through the store's own export path,
// verifies it with store.VerifyExport against the pins, and checks every
// record the view holds is still a prefix of it. Run it periodically (the
// daemon's default is every 10 minutes): it catches a rewrite of old records
// that leaves the newest head alone, which incremental polling cannot see.
func (v *View) FullVerify() error {
	v.mu.RLock()
	if v.failure != nil {
		defer v.mu.RUnlock()
		return v.failure
	}
	held := append([][32]byte(nil), v.leaves...)
	v.mu.RUnlock()

	// A filter matching no source: the export still carries every leaf hash
	// (all this needs) without holding every decrypted record in memory.
	x, err := store.ExportDir(v.cfg.Dir, v.cfg.Key, store.Filter{Sources: []string{"\x00none"}})
	v.mu.Lock()
	defer v.mu.Unlock()
	if err != nil {
		return v.fail(chain("full re-read: %v", err))
	}
	if _, err := store.VerifyExport(x, v.cfg.Pins, nil); err != nil {
		return v.fail(chain("full re-verify: %v", err))
	}
	if len(x.LeafHashes) < len(held) {
		return v.fail(chain("full re-read has %d records, %d were verified before: truncated", len(x.LeafHashes), len(held)))
	}
	for i, h := range held {
		if x.LeafHashes[i] != hex.EncodeToString(h[:]) {
			return v.fail(chain("record %d changed since it was verified", i+1))
		}
	}
	return nil
}

// Status is a snapshot of the view's health.
type Status struct {
	Synced    bool
	Failure   error // non-nil: CHAIN_UNVERIFIED, sticky
	Size      uint64
	Root      string
	SignerKey string
	HeadAge   time.Duration // gate clock since a larger head was verified; MaxInt64 if never
	LastPoll  time.Time
}

// Status returns the current health.
func (v *View) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	age := time.Duration(math.MaxInt64)
	if !v.grewAt.IsZero() {
		age = v.cfg.Now().Sub(v.grewAt)
	}
	return Status{Synced: v.synced && v.failure == nil, Failure: v.failure, Size: v.head.Size,
		Root: v.head.Root, SignerKey: v.head.SignerKey, HeadAge: age, LastPoll: v.lastPoll}
}

// Fresh reports whether the view is synced, unfailed, and has verified a
// larger head within maxAge.
func (v *View) Fresh(maxAge time.Duration) bool {
	s := v.Status()
	return s.Synced && s.HeadAge <= maxAge
}

// Head returns the newest verified head (zero before the first sync).
func (v *View) Head() store.TreeHead {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.head
}

// Priors returns the retained heads, oldest first, for the daemon to persist
// and pass back as Config.Priors after a restart.
func (v *View) Priors() []store.TreeHead {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := append([]store.TreeHead(nil), v.priors...)
	if n := len(out); n == 0 || out[n-1].Size != v.head.Size && v.head.Size > 0 {
		out = append(out, v.head)
	}
	return out
}

// Signals returns kept signals with a witness timestamp at or after since,
// oldest first, optionally limited to kinds.
func (v *View) Signals(since time.Time, kinds ...Kind) []Signal {
	want := map[Kind]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []Signal
	for _, s := range v.signals {
		if s.TS.Before(since) || len(want) > 0 && !want[s.Kind] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// LastSeen returns the newest record timestamp from source (feed silence).
func (v *View) LastSeen(source string) (time.Time, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	t, ok := v.lastSeen[source]
	return t, ok
}

// Last returns the newest kept record from source with event, if any.
func (v *View) Last(source, event string) (Signal, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s, ok := v.lastEvent[source+"\x00"+event]
	return s, ok
}
