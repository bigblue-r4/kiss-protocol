// Package merkle implements an RFC 6962-style append-only Merkle tree
// using BLAKE3 as the hash function.
//
// Leaf hash:     BLAKE3(0x00 || data)
// Internal hash: BLAKE3(0x01 || left || right)
//
// The split point for a subtree of n leaves is the largest power of 2
// strictly less than n, matching RFC 6962 §2.1.
package merkle

import "lukechampine.com/blake3"

const (
	leafPrefix = byte(0x00)
	nodePrefix = byte(0x01)
)

// HashLeaf returns the RFC 6962 leaf hash of data.
func HashLeaf(data []byte) [32]byte {
	h := blake3.New(32, nil)
	// blake3's Write never returns an error; discard explicitly.
	_, _ = h.Write([]byte{leafPrefix})
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashNode returns the RFC 6962 internal node hash of two child hashes.
func HashNode(left, right [32]byte) [32]byte {
	h := blake3.New(32, nil)
	// blake3's Write never returns an error; discard explicitly.
	_, _ = h.Write([]byte{nodePrefix})
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Root computes the Merkle root of a slice of leaf hashes.
// Returns a zero value for an empty slice.
func Root(leaves [][32]byte) [32]byte {
	return subtreeRoot(leaves)
}

func subtreeRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return [32]byte{}
	case 1:
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return HashNode(subtreeRoot(leaves[:k]), subtreeRoot(leaves[k:]))
}

// splitPoint returns the largest power of 2 strictly less than n.
func splitPoint(n int) int {
	k := 1
	for k < n {
		k <<= 1
	}
	return k >> 1
}
