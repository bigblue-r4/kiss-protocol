package merkle

// Frontier computes the root of a growing tree in O(log n) per leaf, instead
// of rehashing every leaf the way Root does. It keeps the roots of the perfect
// subtrees along the tree's right edge (sizes strictly decreasing from the
// left). The tree root folds them from the right,
//
//	root = HashNode(s1, HashNode(s2, ... HashNode(s_{k-1}, s_k)))
//
// which is the RFC 6962 split at the largest power of two below n, applied
// recursively, so Frontier.Root() == Root(leaves) for every size
// (TestFrontierMatchesRoot). The zero value is an empty tree.
type Frontier struct {
	nodes [][32]byte
	sizes []uint64
	n     uint64
}

// NewFrontier returns the frontier of leaves.
func NewFrontier(leaves [][32]byte) Frontier {
	var f Frontier
	for _, l := range leaves {
		f.Push(l)
	}
	return f
}

// Push appends a leaf hash.
func (f *Frontier) Push(leaf [32]byte) {
	node, size := leaf, uint64(1)
	for k := len(f.nodes) - 1; k >= 0 && f.sizes[k] == size; k-- {
		node = HashNode(f.nodes[k], node)
		size *= 2
		f.nodes, f.sizes = f.nodes[:k], f.sizes[:k]
	}
	f.nodes = append(f.nodes, node)
	f.sizes = append(f.sizes, size)
	f.n++
}

// Size is the number of leaves pushed.
func (f *Frontier) Size() uint64 { return f.n }

// Root returns the tree root, equal to Root of every leaf pushed.
func (f *Frontier) Root() [32]byte {
	if len(f.nodes) == 0 {
		return Root(nil)
	}
	acc := f.nodes[len(f.nodes)-1]
	for k := len(f.nodes) - 2; k >= 0; k-- {
		acc = HashNode(f.nodes[k], acc)
	}
	return acc
}
