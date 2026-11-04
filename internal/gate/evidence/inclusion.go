package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/bits"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// levels caches the root of every complete, aligned subtree: levels[k][j] is
// the root of leaves [j*2^k, (j+1)*2^k). Level 0 is the leaves themselves.
// It costs one extra hash per leaf (about 32 bytes) and turns an inclusion
// proof from a rehash of the whole log (merkle.Prove) into O(log² n) lookups,
// which is what keeps commit-wait fast on a large log.
type levels struct{ l [][][32]byte }

func (lv *levels) push(h [32]byte) {
	if len(lv.l) == 0 {
		lv.l = append(lv.l, nil)
	}
	lv.l[0] = append(lv.l[0], h)
	for k := 0; len(lv.l[k])%2 == 0; k++ {
		if k+1 == len(lv.l) {
			lv.l = append(lv.l, nil)
		}
		n := len(lv.l[k])
		lv.l[k+1] = append(lv.l[k+1], merkle.HashNode(lv.l[k][n-2], lv.l[k][n-1]))
	}
}

// mth is the RFC 6962 hash of leaves [lo, lo+n), n >= 1.
func (lv *levels) mth(lo, n uint64) [32]byte {
	if n&(n-1) == 0 && lo%n == 0 {
		k := bits.TrailingZeros64(n)
		return lv.l[k][lo/n]
	}
	k := uint64(1) << (63 - bits.LeadingZeros64(n-1)) // largest power of two < n
	return merkle.HashNode(lv.mth(lo, k), lv.mth(lo+k, n-k))
}

// path is the RFC 6962 audit path for leaf m within leaves [lo, lo+n),
// leaf-to-root, the order merkle.Verify and witnessproof expect.
func (lv *levels) path(m, lo, n uint64) [][32]byte {
	if n <= 1 {
		return nil
	}
	k := uint64(1) << (63 - bits.LeadingZeros64(n-1))
	if m < k {
		return append(lv.path(m, lo, k), lv.mth(lo+k, n-k))
	}
	return append(lv.path(m-k, lo+k, n-k), lv.mth(lo, k))
}

// gateRequest is a gate_request record the view has verified.
type gateRequest struct {
	index uint64
	entry []byte // json.Marshal(store.Entry): the leaf preimage
	ts    time.Time
}

// Retained gate records. The breaker's trips and resets are kept for the
// life of the process regardless of Lookback, because a restart rebuilds
// the breaker from them and a reset older than the lookback must still
// count (gate-arch.md C14). They are rare by construction.
var retainedGateEvents = map[string]bool{"breaker_trip": true, "breaker_reset": true}

func (v *View) indexGate(e store.Entry, index uint64) {
	if e.Source != "gate" {
		return
	}
	if retainedGateEvents[e.Event] {
		v.gateEvents = append(v.gateEvents, Signal{Seq: e.Seq, TS: e.Timestamp, Level: e.Level,
			Source: e.Source, Event: e.Event, Kind: KindGate, Data: e.Data})
		return
	}
	if e.Event != "gate_request" {
		return
	}
	var d struct {
		ActionHash string `json:"action_hash"`
	}
	if json.Unmarshal(e.Data, &d) != nil || d.ActionHash == "" {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, seen := v.requests[d.ActionHash]; !seen {
		v.requests[d.ActionHash] = gateRequest{index: index, entry: raw, ts: e.Timestamp}
	}
}

func (v *View) pruneRequests(now time.Time) {
	for h, r := range v.requests {
		if now.Sub(r.ts) > v.cfg.Lookback {
			delete(v.requests, h)
		}
	}
}

// GateEvents returns the gate's breaker_trip and breaker_reset records from
// the verified log, oldest first.
func (v *View) GateEvents() []Signal {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]Signal(nil), v.gateEvents...)
}

// ErrNotWitnessed means the record is not (yet) in the verified log.
var ErrNotWitnessed = errors.New("evidence: gate_request not yet in the verified log")

// Inclusion returns commit-wait evidence for the gate_request record with
// actionHash: the newest verified head, the record's leaf index, the record
// exactly as the witness hashed it, and the audit path. It is what a token's
// witnessed block carries (gate-arch.md C17).
func (v *View) Inclusion(actionHash string) (proto.Witnessed, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.failure != nil {
		return proto.Witnessed{}, v.failure
	}
	r, ok := v.requests[actionHash]
	if !ok || r.index >= v.head.Size {
		return proto.Witnessed{}, ErrNotWitnessed
	}
	p := v.lv.path(r.index, 0, v.head.Size)
	hp := make([]string, len(p))
	for i, h := range p {
		hp[i] = hex.EncodeToString(h[:])
	}
	return proto.Witnessed{
		Head:      proto.WitnessHead{Size: v.head.Size, Root: v.head.Root, Sig: v.head.Signature, SignerKey: v.head.SignerKey},
		LeafIndex: r.index,
		Entry:     string(r.entry),
		Proof:     hp,
	}, nil
}
