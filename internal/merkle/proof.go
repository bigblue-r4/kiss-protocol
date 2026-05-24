package merkle

import "errors"

// Proof is an inclusion proof for one leaf in a Merkle tree.
type Proof struct {
	Index uint64     `json:"index"` // 0-based leaf index
	Size  uint64     `json:"size"`  // total leaves when proof was generated
	Path  [][32]byte `json:"path"`  // sibling hashes, leaf-to-root order
}

// Prove generates an inclusion proof for the leaf at index.
func Prove(leaves [][32]byte, index uint64) (Proof, error) {
	n := uint64(len(leaves))
	if n == 0 || index >= n {
		return Proof{}, errors.New("merkle: index out of range")
	}
	return Proof{
		Index: index,
		Size:  n,
		Path:  auditPath(leaves, index, n),
	}, nil
}

// Verify checks that leafHash is the leaf at proof.Index in the tree with root.
func Verify(root [32]byte, leafHash [32]byte, proof Proof) error {
	if proof.Size == 0 {
		return errors.New("merkle: empty proof")
	}
	if proof.Index >= proof.Size {
		return errors.New("merkle: index out of range in proof")
	}
	if recompute(leafHash, proof.Index, proof.Size, proof.Path) != root {
		return errors.New("merkle: inclusion proof does not match root")
	}
	return nil
}

// auditPath returns the sibling hashes needed to reconstruct the root
// from the leaf at index, ordered from the leaf's level up to the root.
func auditPath(leaves [][32]byte, index, n uint64) [][32]byte {
	if n == 1 {
		return nil
	}
	k := uint64(splitPoint(int(n)))
	if index < k {
		sibling := subtreeRoot(leaves[k:])
		return append(auditPath(leaves[:k], index, k), sibling)
	}
	sibling := subtreeRoot(leaves[:k])
	return append(auditPath(leaves[k:], index-k, n-k), sibling)
}

// recompute reconstructs the root from a leaf hash and its audit path.
// path is in leaf-to-root order, so the outermost sibling is last.
// We recurse top-down, consuming path from the back.
func recompute(h [32]byte, index, size uint64, path [][32]byte) [32]byte {
	if size == 1 {
		return h
	}
	k := uint64(splitPoint(int(size)))
	outer := path[len(path)-1]
	inner := path[:len(path)-1]
	if index < k {
		return HashNode(recompute(h, index, k, inner), outer)
	}
	return HashNode(outer, recompute(h, index-k, size-k, inner))
}
