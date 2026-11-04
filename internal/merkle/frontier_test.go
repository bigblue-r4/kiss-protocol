package merkle

import (
	"fmt"
	"testing"
)

// TestFrontierMatchesRoot: the incremental root equals the full recomputation
// at every size, so a head written from a Frontier is byte-identical to one
// written from Root.
func TestFrontierMatchesRoot(t *testing.T) {
	var f Frontier
	if f.Root() != Root(nil) || f.Size() != 0 {
		t.Fatal("empty frontier differs from an empty tree")
	}
	var leaves [][32]byte
	for i := 0; i < 1100; i++ {
		l := HashLeaf([]byte(fmt.Sprint(i)))
		leaves = append(leaves, l)
		f.Push(l)
		if f.Root() != Root(leaves) {
			t.Fatalf("size %d: frontier root differs from Root", i+1)
		}
		if f.Size() != uint64(len(leaves)) {
			t.Fatalf("size %d: Size() = %d", i+1, f.Size())
		}
	}
	for _, n := range []int{0, 1, 2, 3, 64, 65, 1023, 1024, 1025, 1100} {
		g := NewFrontier(leaves[:n])
		if g.Root() != Root(leaves[:n]) {
			t.Fatalf("NewFrontier(%d) root differs", n)
		}
	}
}

func BenchmarkRootFull(b *testing.B) {
	leaves := make([][32]byte, 100_000)
	for i := range leaves {
		leaves[i] = HashLeaf([]byte(fmt.Sprint(i)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Root(leaves)
	}
}

func BenchmarkFrontierPushRoot(b *testing.B) {
	f := NewFrontier(nil)
	for i := 0; i < 100_000; i++ {
		f.Push(HashLeaf([]byte(fmt.Sprint(i))))
	}
	l := HashLeaf([]byte("next"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Push(l)
		_ = f.Root()
	}
}
