package merkle

import (
	"encoding/binary"
	"testing"
)

// FuzzProveVerify fuzzes the full prove→verify round-trip with arbitrary leaf
// data and indices. The invariant: if Prove succeeds, Verify must succeed
// against the matching root; neither function may panic on any input.
func FuzzProveVerify(f *testing.F) {
	// Seed corpus: small trees, edge-case sizes, power-of-two boundaries.
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17} {
		for idx := 0; idx < n; idx++ {
			// Encode n and idx as 4 bytes each, data as the leaf content.
			seed := make([]byte, 8+n)
			binary.BigEndian.PutUint32(seed[0:4], uint32(n))
			binary.BigEndian.PutUint32(seed[4:8], uint32(idx))
			for i := range seed[8:] {
				seed[8+i] = byte(i)
			}
			f.Add(seed)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}
		n := int(binary.BigEndian.Uint32(data[0:4]))
		idx := int(binary.BigEndian.Uint32(data[4:8]))
		leafData := data[8:]

		// Clamp to prevent OOM in corpus-generated cases.
		if n <= 0 || n > 1024 {
			return
		}

		leaves := make([][32]byte, n)
		for i := range leaves {
			// Derive each leaf from the fuzz input by hashing index + data.
			segment := append([]byte{byte(i), byte(i >> 8)}, leafData...)
			leaves[i] = HashLeaf(segment)
		}

		root := Root(leaves)

		// Clamp idx to valid range.
		if idx < 0 {
			idx = -idx
		}
		idx = idx % n

		proof, err := Prove(leaves, uint64(idx))
		if err != nil {
			// Prove must only fail for out-of-range — which we've ruled out.
			t.Errorf("Prove(%d leaves, idx=%d) unexpected error: %v", n, idx, err)
			return
		}
		if err := Verify(root, leaves[idx], proof); err != nil {
			t.Errorf("Verify failed for valid proof (n=%d, idx=%d): %v", n, idx, err)
		}
	})
}

// FuzzVerifyAdversarial fuzzes Verify directly with arbitrary proof bytes.
// Verify must never panic regardless of what it receives.
func FuzzVerifyAdversarial(f *testing.F) {
	// Build a real proof as a seed.
	leaves := makeLeaves(8)
	root := Root(leaves)
	proof, _ := Prove(leaves, 3)

	// Encode: root (32) + leafHash (32) + index (8) + size (8) + pathLen (4) + path (n*32)
	seed := make([]byte, 32+32+8+8+4+len(proof.Path)*32)
	copy(seed[0:32], root[:])
	copy(seed[32:64], leaves[3][:])
	binary.BigEndian.PutUint64(seed[64:72], proof.Index)
	binary.BigEndian.PutUint64(seed[72:80], proof.Size)
	binary.BigEndian.PutUint32(seed[80:84], uint32(len(proof.Path)))
	for i, h := range proof.Path {
		copy(seed[84+i*32:], h[:])
	}
	f.Add(seed)
	f.Add([]byte{}) // empty
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 84 {
			return
		}
		var root [32]byte
		copy(root[:], data[0:32])
		var leafHash [32]byte
		copy(leafHash[:], data[32:64])
		index := binary.BigEndian.Uint64(data[64:72])
		size := binary.BigEndian.Uint64(data[72:80])
		pathLen := int(binary.BigEndian.Uint32(data[80:84]))

		// Clamp path length to prevent OOM.
		if pathLen < 0 || pathLen > 64 {
			return
		}
		if len(data) < 84+pathLen*32 {
			return
		}

		path := make([][32]byte, pathLen)
		for i := range path {
			copy(path[i][:], data[84+i*32:])
		}

		p := Proof{Index: index, Size: size, Path: path}
		// Must not panic; result is discarded.
		_ = Verify(root, leafHash, p)
	})
}

// FuzzHashLeaf fuzzes HashLeaf with arbitrary inputs — must never panic.
func FuzzHashLeaf(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte("\xff\xfe\xfd"))
	f.Add(make([]byte, 4096))

	f.Fuzz(func(t *testing.T, data []byte) {
		h := HashLeaf(data)
		if h == ([32]byte{}) && len(data) > 0 {
			// Zero hash from non-empty input is astronomically unlikely — flag it.
			t.Error("HashLeaf returned zero hash for non-empty input")
		}
	})
}

// FuzzRoot fuzzes Root with varying numbers of adversarially-constructed leaves.
func FuzzRoot(f *testing.F) {
	// Single leaf, two leaves, odd count, large count.
	f.Add(uint32(1), []byte("a"))
	f.Add(uint32(7), []byte("seed"))
	f.Add(uint32(16), []byte("boundary"))
	f.Add(uint32(0), []byte{})

	f.Fuzz(func(t *testing.T, count uint32, seed []byte) {
		if count > 512 {
			return
		}
		leaves := make([][32]byte, count)
		for i := range leaves {
			leaves[i] = HashLeaf(append(seed, byte(i)))
		}
		// Must not panic.
		_ = Root(leaves)
	})
}
