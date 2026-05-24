package merkle

import (
	"encoding/hex"
	"testing"
)

func TestHashLeafDeterministic(t *testing.T) {
	data := []byte("hello")
	h1 := HashLeaf(data)
	h2 := HashLeaf(data)
	if h1 != h2 {
		t.Fatal("HashLeaf is not deterministic")
	}
}

func TestHashLeafDomain(t *testing.T) {
	// Leaf and node hashes of the same input must differ.
	data := []byte("test")
	leaf := HashLeaf(data)

	// Construct a node hash from two identical leaves.
	node := HashNode(leaf, leaf)
	if leaf == node {
		t.Fatal("leaf and node hash of same data must differ")
	}
}

func TestRootSingleLeaf(t *testing.T) {
	h := HashLeaf([]byte("a"))
	r := Root([][32]byte{h})
	if r != h {
		t.Fatal("root of single leaf must equal the leaf hash")
	}
}

func TestRootEmpty(t *testing.T) {
	r := Root(nil)
	var zero [32]byte
	if r != zero {
		t.Fatal("root of empty tree must be zero")
	}
}

func TestRootTwoLeaves(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	want := HashNode(a, b)
	got := Root([][32]byte{a, b})
	if got != want {
		t.Fatalf("two-leaf root mismatch:\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
}

func TestRootThreeLeaves(t *testing.T) {
	// For 3 leaves: k=2, root = HashNode(HashNode(0,1), 2)
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	c := HashLeaf([]byte("c"))
	want := HashNode(HashNode(a, b), c)
	got := Root([][32]byte{a, b, c})
	if got != want {
		t.Fatalf("three-leaf root mismatch:\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
}

func TestRootFourLeaves(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	c := HashLeaf([]byte("c"))
	d := HashLeaf([]byte("d"))
	want := HashNode(HashNode(a, b), HashNode(c, d))
	got := Root([][32]byte{a, b, c, d})
	if got != want {
		t.Fatalf("four-leaf root mismatch:\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
}

func TestRootChangesOnTamper(t *testing.T) {
	leaves := make([][32]byte, 5)
	for i := range leaves {
		leaves[i] = HashLeaf([]byte{byte(i)})
	}
	r1 := Root(leaves)

	// Flip a byte in leaf 2.
	leaves[2][0] ^= 0xff
	r2 := Root(leaves)

	if r1 == r2 {
		t.Fatal("root must change when a leaf is tampered")
	}
}

func TestSplitPoint(t *testing.T) {
	cases := []struct{ n, want int }{
		{2, 1}, {3, 2}, {4, 2}, {5, 4}, {6, 4}, {7, 4}, {8, 4},
		{9, 8}, {15, 8}, {16, 8}, {17, 16},
	}
	for _, tc := range cases {
		got := splitPoint(tc.n)
		if got != tc.want {
			t.Errorf("splitPoint(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}
