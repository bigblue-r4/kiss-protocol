package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// bucket is a sliding-window budget: the sum of reservations made in the
// last Window. Unlike a refilling token bucket, it gives an exact statement
// an auditor can check: inside any window of that length, released value
// never exceeded the cap (acceptance 2 and 18).
type bucket struct {
	limit   policy.Limit
	entries []bentry
	total   *big.Rat
}

type bentry struct {
	at  time.Time
	id  uint64
	val *big.Rat
}

func (b *bucket) prune(now time.Time) {
	cut := now.Add(-b.limit.Window.Duration)
	i := 0
	for i < len(b.entries) && !b.entries[i].at.After(cut) {
		b.total.Sub(b.total, b.entries[i].val)
		i++
	}
	b.entries = b.entries[i:]
}

func (b *bucket) fits(val *big.Rat) error {
	if b.limit.MaxCount > 0 && len(b.entries)+1 > b.limit.MaxCount {
		return fmt.Errorf("max_count %d per %s", b.limit.MaxCount, b.limit.Window.Duration)
	}
	if m := b.limit.Max(); m != nil {
		if next := new(big.Rat).Add(b.total, val); next.Cmp(m) > 0 {
			return fmt.Errorf("max_value %s per %s (in window %s, this request %s)",
				b.limit.MaxValue, b.limit.Window.Duration, b.total.FloatString(2), val.FloatString(2))
		}
	}
	return nil
}

func (b *bucket) refund(id uint64) {
	for i, e := range b.entries {
		if e.id == id {
			b.total.Sub(b.total, e.val)
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			return
		}
	}
}

type spec struct {
	key   string
	limit policy.Limit
	val   *big.Rat
	scope proto.Scope // ticked on VELOCITY_EXCEEDED
}

// reserve debits every applicable bucket or none (addendum 1). The caller
// holds c.mu. On failure it returns the scope to tick: the bucket's own
// scope, except that the class and global buckets tick the class (Global is
// reserved for chain failures, addendum 6).
func (c *Core) reserve(p *policy.Policy, cl policy.Class, req proto.ActionRequest, units, ref *big.Rat, now time.Time) ([]string, proto.Scope, error) {
	class := proto.Scope{Kind: proto.ScopeClass, Value: req.Class}
	specs := []spec{
		{"class/" + req.Class, cl.Budget, ref, class},
		{"class/" + req.Class + "/principal/" + req.Principal, cl.PrincipalBudget, ref, proto.Scope{Kind: proto.ScopePrincipal, Value: req.Principal}},
		{"class/" + req.Class + "/destination/" + req.Destination, cl.DestinationBudget, ref, proto.Scope{Kind: proto.ScopeDestination, Value: req.Destination}},
		{"global", p.Global.Budget, ref, class},
	}
	if req.Asset != "" {
		specs = append(specs, spec{"asset/" + req.Asset, p.Assets[req.Asset].Budget, units, proto.Scope{Kind: proto.ScopeAsset, Value: req.Asset}})
	}
	var use []spec
	for _, s := range specs {
		if !s.limit.Active() {
			continue
		}
		b := c.buckets[s.key]
		if b == nil {
			b = &bucket{total: new(big.Rat)}
			c.buckets[s.key] = b
		}
		b.limit = s.limit // a reload may have changed it
		b.prune(now)
		if err := b.fits(s.val); err != nil {
			return nil, s.scope, fmt.Errorf("%s: %v", s.key, err)
		}
		use = append(use, s)
	}
	id := c.nextID + 1
	keys := make([]string, 0, len(use))
	for _, s := range use {
		b := c.buckets[s.key]
		b.entries = append(b.entries, bentry{at: now, id: id, val: new(big.Rat).Set(s.val)})
		b.total.Add(b.total, s.val)
		keys = append(keys, s.key)
	}
	return keys, proto.Scope{}, nil
}
