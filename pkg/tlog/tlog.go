// Package tlog implements an RFC 6962 Merkle tree over SHA-256: leaf and node
// hashes, the tree root, and inclusion and consistency proofs.
//
// It is the tree the C2SP tlog-checkpoint, tlog-witness and tlog-cosignature
// specifications assume, so checkpoints built from it can be cosigned by
// existing witnesses. The algorithms are those of internal/merkle (which
// keeps BLAKE3 for existing Witness logs), with two differences required by
// the C2SP specifications: the empty tree's root is SHA-256 of the empty
// string, and a consistency proof from size 0 is the empty proof.
//
//	leaf hash: SHA-256(0x00 || data)
//	node hash: SHA-256(0x01 || left || right)
package tlog

import (
	"crypto/sha256"
	"errors"
	"math/bits"
)

// Hash is a SHA-256 tree hash.
type Hash = [32]byte

// EmptyRoot is the root of the tree with no leaves (RFC 6962 §2.1).
var EmptyRoot = Hash(sha256.Sum256(nil))

// HashLeaf returns the leaf hash of data.
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// HashNode returns the hash of an internal node.
func HashNode(left, right Hash) Hash {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[33:], right[:])
	return sha256.Sum256(buf[:])
}

// Root returns the tree root over leaf hashes.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot
	}
	return subtreeRoot(leaves)
}

func subtreeRoot(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(uint64(len(leaves)))
	return HashNode(subtreeRoot(leaves[:k]), subtreeRoot(leaves[k:]))
}

// splitPoint returns the largest power of 2 strictly less than n (n > 1).
func splitPoint(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// ProveInclusion returns the audit path for leaf index in the tree of all
// leaves, ordered from the leaf's level up.
func ProveInclusion(leaves []Hash, index uint64) ([]Hash, error) {
	n := uint64(len(leaves))
	if index >= n {
		return nil, errors.New("tlog: inclusion index out of range")
	}
	return auditPath(leaves, index), nil
}

func auditPath(leaves []Hash, index uint64) []Hash {
	n := uint64(len(leaves))
	if n == 1 {
		return nil
	}
	k := splitPoint(n)
	if index < k {
		return append(auditPath(leaves[:k], index), subtreeRoot(leaves[k:]))
	}
	return append(auditPath(leaves[k:], index-k), subtreeRoot(leaves[:k]))
}

// VerifyInclusion checks that leaf is at index in the tree of size with root.
// It never panics on untrusted input.
func VerifyInclusion(root, leaf Hash, index, size uint64, path []Hash) error {
	if index >= size {
		return errors.New("tlog: inclusion index out of range")
	}
	depth := 0
	for i, s := index, size; s > 1; depth++ {
		k := splitPoint(s)
		if i < k {
			s = k
		} else {
			i, s = i-k, s-k
		}
	}
	if len(path) != depth {
		return errors.New("tlog: inclusion proof has the wrong length")
	}
	if recompute(leaf, index, size, path) != root {
		return errors.New("tlog: inclusion proof does not match root")
	}
	return nil
}

func recompute(h Hash, index, size uint64, path []Hash) Hash {
	if size == 1 {
		return h
	}
	k := splitPoint(size)
	outer, inner := path[len(path)-1], path[:len(path)-1]
	if index < k {
		return HashNode(recompute(h, index, k, inner), outer)
	}
	return HashNode(outer, recompute(h, index-k, size-k, inner))
}

// ProveConsistency returns the RFC 6962 §2.1.2 consistency proof from the
// first oldSize leaves to all of leaves. For oldSize 0 or oldSize ==
// len(leaves) the proof is empty.
func ProveConsistency(leaves []Hash, oldSize uint64) ([]Hash, error) {
	n := uint64(len(leaves))
	if oldSize > n {
		return nil, errors.New("tlog: consistency old size exceeds tree size")
	}
	if oldSize == 0 || oldSize == n {
		return nil, nil
	}
	return subproof(oldSize, leaves, true), nil
}

func subproof(m uint64, leaves []Hash, complete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return []Hash{subtreeRoot(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(m, leaves[:k], complete), subtreeRoot(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), subtreeRoot(leaves[:k]))
}

// VerifyConsistency checks that the tree (oldSize, oldRoot) is a prefix of
// the tree (newSize, newRoot), per RFC 9162 §2.1.4.2 and the size-0 and
// equal-size rules of C2SP tlog-witness. It never panics on untrusted input.
//
// The proof binds the two roots, not the two sizes: the caller must take
// both sizes from signed checkpoints.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot Hash, path []Hash) error {
	m, n := oldSize, newSize
	switch {
	case m > n:
		return errors.New("tlog: consistency old size exceeds new size")
	case m == 0:
		if len(path) != 0 {
			return errors.New("tlog: consistency proof from size 0 must be empty")
		}
		if oldRoot != EmptyRoot {
			return errors.New("tlog: size 0 with a root that is not the empty-tree root")
		}
		return nil
	case m == n:
		if len(path) != 0 {
			return errors.New("tlog: consistency proof for equal sizes must be empty")
		}
		if oldRoot != newRoot {
			return errors.New("tlog: equal sizes but different roots")
		}
		return nil
	}
	if want := consistencyPathLen(m, n); len(path) != want {
		return errors.New("tlog: consistency proof has the wrong length")
	}
	if m&(m-1) == 0 {
		path = append([]Hash{oldRoot}, path...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return errors.New("tlog: consistency proof too long")
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
		return errors.New("tlog: consistency proof too short")
	}
	if fr != oldRoot {
		return errors.New("tlog: consistency proof does not match the old root")
	}
	if sr != newRoot {
		return errors.New("tlog: consistency proof does not match the new root")
	}
	return nil
}

func consistencyPathLen(m, n uint64) int {
	l, complete := 0, true
	for m != n {
		k := splitPoint(n)
		if m <= k {
			n = k
		} else {
			m, n = m-k, n-k
			complete = false
		}
		l++
	}
	if !complete {
		l++
	}
	return l
}
