package merkle

import (
	"testing"
)

func makeLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range leaves {
		leaves[i] = HashLeaf([]byte{byte(i)})
	}
	return leaves
}

func TestInclusionProofAllSizes(t *testing.T) {
	for n := 1; n <= 17; n++ {
		leaves := makeLeaves(n)
		root := Root(leaves)
		for idx := range leaves {
			proof, err := Prove(leaves, uint64(idx))
			if err != nil {
				t.Fatalf("n=%d idx=%d: Prove: %v", n, idx, err)
			}
			if err := Verify(root, leaves[idx], proof); err != nil {
				t.Fatalf("n=%d idx=%d: Verify: %v", n, idx, err)
			}
		}
	}
}

func TestInclusionProofWrongLeaf(t *testing.T) {
	leaves := makeLeaves(8)
	root := Root(leaves)
	proof, _ := Prove(leaves, 3)

	// Verify with a different leaf hash must fail.
	wrong := HashLeaf([]byte("wrong"))
	if err := Verify(root, wrong, proof); err == nil {
		t.Fatal("expected error verifying wrong leaf hash, got nil")
	}
}

func TestInclusionProofWrongRoot(t *testing.T) {
	leaves := makeLeaves(8)
	root := Root(leaves)
	proof, _ := Prove(leaves, 3)

	// Tamper root.
	root[0] ^= 0xff
	if err := Verify(root, leaves[3], proof); err == nil {
		t.Fatal("expected error verifying against wrong root, got nil")
	}
}

func TestInclusionProofTamperedPath(t *testing.T) {
	leaves := makeLeaves(8)
	root := Root(leaves)
	proof, _ := Prove(leaves, 3)

	// Flip a bit in the audit path.
	proof.Path[0][0] ^= 0xff
	if err := Verify(root, leaves[3], proof); err == nil {
		t.Fatal("expected error with tampered proof path, got nil")
	}
}

func TestInclusionProofOutOfRange(t *testing.T) {
	leaves := makeLeaves(4)
	if _, err := Prove(leaves, 4); err == nil {
		t.Fatal("expected error for out-of-range index")
	}
	if _, err := Prove(nil, 0); err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestProofConsistencyAfterAppend(t *testing.T) {
	// A proof generated at size N must still be verifiable against the
	// root at size N even after more leaves are added.
	leaves := makeLeaves(4)
	root4 := Root(leaves)
	proof, _ := Prove(leaves, 2)

	// Add more leaves — proof should still verify against root4.
	if err := Verify(root4, leaves[2], proof); err != nil {
		t.Fatalf("proof no longer valid after leaves appended: %v", err)
	}
}
