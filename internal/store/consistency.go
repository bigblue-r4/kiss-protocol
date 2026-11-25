package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// ConsistencyFormat names the JSON consistency-proof document.
const ConsistencyFormat = "harborlight-consistency/1"

// ErrInconsistent means the newer head does not extend the older one: the log
// was rewritten or truncated between the two heads (or the proof is forged).
var ErrInconsistent = errors.New("heads are not consistent")

// ConsistencyDoc is a consistency proof between two tree sizes, in a form a
// third party can check with the two signed heads and the signer's public key.
type ConsistencyDoc struct {
	Format  string   `json:"format"`
	OldSize uint64   `json:"old_size"`
	OldRoot string   `json:"old_root"`
	NewSize uint64   `json:"new_size"`
	NewRoot string   `json:"new_root"`
	Path    []string `json:"path"` // hex hashes, RFC 6962 §2.1.2 order
}

// ConsistencyProof proves that the log's first oldSize records are unchanged
// in the log this store holds (for OpenPinned, the records its head covers).
func (s *Store) ConsistencyProof(oldSize uint64) (ConsistencyDoc, error) {
	s.mu.Lock()
	leaves := append([][32]byte(nil), s.leaves...)
	s.mu.Unlock()
	return ConsistencyFromLeaves(leaves, oldSize)
}

// ConsistencyFromLeaves builds the proof from leaf hashes alone (for example
// a mirror's leaf feed), with no access to records or keys.
func ConsistencyFromLeaves(leaves [][32]byte, oldSize uint64) (ConsistencyDoc, error) {
	p, err := merkle.ProveConsistency(leaves, oldSize)
	if err != nil {
		return ConsistencyDoc{}, fmt.Errorf("old size %d, log size %d: %w", oldSize, len(leaves), err)
	}
	oldRoot, newRoot := merkle.Root(leaves[:oldSize]), merkle.Root(leaves)
	d := ConsistencyDoc{
		Format:  ConsistencyFormat,
		OldSize: oldSize,
		OldRoot: hex.EncodeToString(oldRoot[:]),
		NewSize: uint64(len(leaves)),
		NewRoot: hex.EncodeToString(newRoot[:]),
		Path:    make([]string, len(p.Path)),
	}
	for i, h := range p.Path {
		d.Path[i] = hex.EncodeToString(h[:])
	}
	return d, nil
}

// VerifyConsistency checks, with only public material, that newHead extends
// oldHead: both heads must carry a valid signature from a pinned key, and the
// proof must show the old tree is a prefix of the new one. Sizes are bound to
// roots by the head signatures (size_be8 || root), not by the proof.
func VerifyConsistency(oldHead, newHead TreeHead, d ConsistencyDoc, pins []ed25519.PublicKey) error {
	if d.Format != ConsistencyFormat {
		return fmt.Errorf("unknown consistency proof format %q", d.Format)
	}
	if len(pins) == 0 {
		return errors.New("verify-consistency needs the signer's public key (--pubkey)")
	}
	if oldHead.Size == 0 {
		return errors.New("old head is empty: nothing to be consistent with")
	}
	if d.OldSize != oldHead.Size || d.OldRoot != oldHead.Root {
		return errors.New("proof is for a different old head")
	}
	if d.NewSize != newHead.Size || d.NewRoot != newHead.Root {
		return errors.New("proof is for a different new head")
	}
	oldRoot, err := decodeHash(oldHead.Root)
	if err != nil {
		return fmt.Errorf("old head: %w", err)
	}
	newRoot, err := decodeHash(newHead.Root)
	if err != nil {
		return fmt.Errorf("new head: %w", err)
	}
	if err := verifyHeadSignature(oldHead, oldRoot, pins); err != nil {
		return fmt.Errorf("old head: %w", err)
	}
	if err := verifyHeadSignature(newHead, newRoot, pins); err != nil {
		return fmt.Errorf("new head: %w", err)
	}
	if newHead.Size < oldHead.Size {
		return fmt.Errorf("%w: new head (size %d) is shorter than old head (size %d): log truncated or rolled back", ErrInconsistent, newHead.Size, oldHead.Size)
	}
	p := merkle.ConsistencyProof{OldSize: d.OldSize, NewSize: d.NewSize, Path: make([][32]byte, len(d.Path))}
	for i, h := range d.Path {
		if p.Path[i], err = decodeHash(h); err != nil {
			return fmt.Errorf("proof path %d: %w", i, err)
		}
	}
	if err := merkle.VerifyConsistency(oldRoot, newRoot, p); err != nil {
		return fmt.Errorf("%w: %v", ErrInconsistent, err)
	}
	return nil
}

func decodeHash(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, errors.New("malformed hash (want 64 hex characters)")
	}
	copy(h[:], b)
	return h, nil
}
