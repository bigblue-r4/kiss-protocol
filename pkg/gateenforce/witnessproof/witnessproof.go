// Package witnessproof verifies a gate token's commit-wait evidence: that the
// gate's gate_request record for this exact action is in the witness log, under
// a tree head signed by a pinned witness key.
//
// It is split from gateenforce because the witness Merkle tree hashes with
// BLAKE3, which is not in the standard library (docs/gate-arch.md C11). A
// service with no commit-wait classes never imports it.
package witnessproof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// GateSource is the witness event-feed source the gate's records carry, and
// RequestEvent the event name (the line's kind) of the record that commits a
// request before its token is signed.
const (
	GateSource   = "gate"
	RequestEvent = "gate_request"
)

// MaxLogSize bounds the head size accepted from a token. A witness appending
// a million records a second would need nine years to reach it.
const MaxLogSize = 1 << 48

// New returns a verifier for gateenforce.Config.Witness that accepts heads
// signed by one of witnessKeys.
func New(witnessKeys []ed25519.PublicKey) (func(proto.Witnessed, string) error, error) {
	if len(witnessKeys) == 0 {
		return nil, errors.New("witnessproof: at least one pinned witness key is required")
	}
	keys := append([]ed25519.PublicKey(nil), witnessKeys...)
	return func(w proto.Witnessed, actionHash string) error { return Verify(w, actionHash, keys) }, nil
}

// entry is the part of a witness log entry this package reads.
type entry struct {
	Event  string          `json:"event"`
	Source string          `json:"source"`
	Data   json.RawMessage `json:"data"`
}

// Verify checks w for the action with hash actionHash (hex):
//
//  1. the head is signed by a pinned witness key, over size_be8 || root
//     exactly as the witness signs it;
//  2. w.Entry hashes (RFC 6962 leaf, BLAKE3) to a leaf that the proof places
//     at w.LeafIndex under the head's root;
//  3. that entry is the gate's own gate_request record, and its action_hash is
//     actionHash.
func Verify(w proto.Witnessed, actionHash string, witnessKeys []ed25519.PublicKey) error {
	root, err := verifyHead(w.Head, witnessKeys)
	if err != nil {
		return err
	}
	// internal/merkle.Verify indexes the path without bounds checks and panics
	// on a short one; a token is attacker-supplied, so check the length here.
	// internal/merkle's split-point loop also never ends for sizes near 2^62,
	// so absurd sizes are refused before anything reaches it.
	if w.Head.Size > MaxLogSize {
		return fmt.Errorf("witnessproof: head size %d exceeds %d", w.Head.Size, uint64(MaxLogSize))
	}
	if w.LeafIndex >= w.Head.Size {
		return fmt.Errorf("witnessproof: leaf %d outside head size %d", w.LeafIndex, w.Head.Size)
	}
	if want := auditPathLen(w.LeafIndex, w.Head.Size); len(w.Proof) != want {
		return fmt.Errorf("witnessproof: proof has %d hashes, leaf %d of %d needs %d", len(w.Proof), w.LeafIndex, w.Head.Size, want)
	}
	path := make([][32]byte, len(w.Proof))
	for i, h := range w.Proof {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("witnessproof: proof hash %d malformed", i)
		}
		copy(path[i][:], b)
	}
	leaf := merkle.HashLeaf([]byte(w.Entry))
	if err := merkle.Verify(root, leaf, merkle.Proof{Index: w.LeafIndex, Size: w.Head.Size, Path: path}); err != nil {
		return fmt.Errorf("witnessproof: %w", err)
	}
	var e entry
	if err := json.Unmarshal([]byte(w.Entry), &e); err != nil {
		return fmt.Errorf("witnessproof: entry: %w", err)
	}
	if e.Source != GateSource || e.Event != RequestEvent {
		return fmt.Errorf("witnessproof: entry is %s/%s, want %s/%s", e.Source, e.Event, GateSource, RequestEvent)
	}
	var d struct {
		ActionHash string `json:"action_hash"`
	}
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return fmt.Errorf("witnessproof: entry data: %w", err)
	}
	if d.ActionHash != actionHash {
		return errors.New("witnessproof: witnessed record is for a different action")
	}
	return nil
}

// auditPathLen is the RFC 6962 audit path length for leaf index of a tree of
// size leaves (size > index): one hash per level of the split the leaf sits under.
func auditPathLen(index, size uint64) int {
	n := 0
	for size > 1 {
		k := uint64(1)
		for k < size-k { // doubling while 2k < size, without overflowing
			k <<= 1
		}
		if index < k {
			size = k
		} else {
			index, size = index-k, size-k
		}
		n++
	}
	return n
}

func verifyHead(h proto.WitnessHead, pins []ed25519.PublicKey) ([32]byte, error) {
	var root [32]byte
	r, err := hex.DecodeString(h.Root)
	if err != nil || len(r) != 32 {
		return root, errors.New("witnessproof: head root malformed")
	}
	copy(root[:], r)
	pub, err := hex.DecodeString(h.SignerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return root, errors.New("witnessproof: head signer_key malformed")
	}
	pinned := false
	for _, p := range pins {
		if bytes.Equal(pub, p) {
			pinned = true
		}
	}
	if !pinned {
		return root, errors.New("witnessproof: head signed by a key that is not a pinned witness key")
	}
	sig, err := hex.DecodeString(h.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return root, errors.New("witnessproof: head signature malformed")
	}
	// The witness's tree-head signature input (internal/store treeHeadSigInput).
	msg := make([]byte, 8+32)
	binary.BigEndian.PutUint64(msg[:8], h.Size)
	copy(msg[8:], root[:])
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return root, errors.New("witnessproof: head signature does not verify")
	}
	return root, nil
}
