package merkle

import "errors"

// ConsistencyProof shows that the tree of OldSize leaves is a prefix of the
// tree of NewSize leaves (RFC 6962 §2.1.2; verification per RFC 9162 §2.1.4.2).
// A verifier that holds only the two roots and this proof can detect a
// rewritten or truncated history without holding any leaves.
type ConsistencyProof struct {
	OldSize uint64     `json:"old_size"`
	NewSize uint64     `json:"new_size"`
	Path    [][32]byte `json:"path"`
}

// ProveConsistency generates a consistency proof from the first oldSize leaves
// to all of leaves. oldSize must satisfy 0 < oldSize <= len(leaves).
func ProveConsistency(leaves [][32]byte, oldSize uint64) (ConsistencyProof, error) {
	n := uint64(len(leaves))
	if oldSize == 0 || oldSize > n {
		return ConsistencyProof{}, errors.New("merkle: consistency old size out of range")
	}
	return ConsistencyProof{
		OldSize: oldSize,
		NewSize: n,
		Path:    subproof(oldSize, leaves, true),
	}, nil
}

// subproof is SUBPROOF(m, D[n], b) from RFC 6962 §2.1.2. complete is true
// while the subtree being descended is exactly the old tree's left edge, so
// its hash is known to the verifier and is omitted.
func subproof(m uint64, leaves [][32]byte, complete bool) [][32]byte {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return [][32]byte{subtreeRoot(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(m, leaves[:k], complete), subtreeRoot(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), subtreeRoot(leaves[:k]))
}

// VerifyConsistency checks that oldRoot (tree size proof.OldSize) is a prefix
// of newRoot (tree size proof.NewSize). It never panics on untrusted input.
func VerifyConsistency(oldRoot, newRoot [32]byte, proof ConsistencyProof) error {
	m, n, path := proof.OldSize, proof.NewSize, proof.Path
	switch {
	case m == 0:
		return errors.New("merkle: consistency proof from an empty tree is not supported")
	case m > n:
		return errors.New("merkle: consistency old size exceeds new size")
	case m == n:
		if len(path) != 0 {
			return errors.New("merkle: consistency proof for equal sizes must be empty")
		}
		if oldRoot != newRoot {
			return errors.New("merkle: equal sizes but different roots")
		}
		return nil
	}
	if len(path) == 0 {
		return errors.New("merkle: empty consistency proof")
	}
	if want := consistencyPathLen(m, n); len(path) != want {
		return errors.New("merkle: invalid consistency proof length")
	}

	// RFC 9162 §2.1.4.2.
	if m&(m-1) == 0 { // m is an exact power of 2
		path = append([][32]byte{oldRoot}, path...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return errors.New("merkle: consistency proof too long")
		}
		if fn&1 == 1 || fn == sn {
			fr = HashNode(c, fr)
			sr = HashNode(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashNode(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("merkle: consistency proof too short")
	}
	if fr != oldRoot {
		return errors.New("merkle: consistency proof does not match old root")
	}
	if sr != newRoot {
		return errors.New("merkle: consistency proof does not match new root")
	}
	return nil
}

// consistencyPathLen is the exact number of hashes SUBPROOF emits for
// 0 < m < n. Checking it up front rejects padded or truncated proofs early.
func consistencyPathLen(m, n uint64) int {
	l, complete := 0, true
	for m != n {
		k := splitPoint(n)
		if m <= k {
			n = k
		} else {
			m -= k
			n -= k
			complete = false
		}
		l++
	}
	if !complete {
		l++
	}
	return l
}
