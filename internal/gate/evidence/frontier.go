package evidence

import "github.com/bigblue-r4/kiss-protocol/internal/merkle"

// frontier keeps the roots of the perfect subtrees along the right edge of
// the witness's RFC 6962 Merkle tree, so the root after each appended leaf
// costs O(log n), not a rehash of the whole log. Sizes strictly decrease from
// the left; the tree root folds them from the right:
//
//	MTH(n) = H(s1, H(s2, ... H(s_{k-1}, s_k)))
//
// which is RFC 6962's split at the largest power of two below n, applied
// recursively. TestFrontierMatchesMerkle checks it against internal/merkle.
type frontier struct {
	nodes [][32]byte
	sizes []uint64
	n     uint64
}

func (f *frontier) push(leaf [32]byte) {
	node, size := leaf, uint64(1)
	for k := len(f.nodes) - 1; k >= 0 && f.sizes[k] == size; k-- {
		node = merkle.HashNode(f.nodes[k], node)
		size *= 2
		f.nodes, f.sizes = f.nodes[:k], f.sizes[:k]
	}
	f.nodes = append(f.nodes, node)
	f.sizes = append(f.sizes, size)
	f.n++
}

func (f *frontier) root() [32]byte {
	if len(f.nodes) == 0 {
		return merkle.Root(nil)
	}
	acc := f.nodes[len(f.nodes)-1]
	for k := len(f.nodes) - 2; k >= 0; k-- {
		acc = merkle.HashNode(f.nodes[k], acc)
	}
	return acc
}

func (f *frontier) clone() frontier {
	return frontier{
		nodes: append([][32]byte(nil), f.nodes...),
		sizes: append([]uint64(nil), f.sizes...),
		n:     f.n,
	}
}
