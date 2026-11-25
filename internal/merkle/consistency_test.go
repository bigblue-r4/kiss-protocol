package merkle

import (
	"encoding/binary"
	"testing"
)

func TestConsistencyAllSizes(t *testing.T) {
	const max = 70
	leaves := makeLeaves(max)
	for n := 1; n <= max; n++ {
		newRoot := Root(leaves[:n])
		for m := 1; m <= n; m++ {
			p, err := ProveConsistency(leaves[:n], uint64(m))
			if err != nil {
				t.Fatalf("m=%d n=%d: prove: %v", m, n, err)
			}
			if got, want := len(p.Path), consistencyPathLen(uint64(m), uint64(n)); m < n && got != want {
				t.Fatalf("m=%d n=%d: path len %d, want %d", m, n, got, want)
			}
			if err := VerifyConsistency(Root(leaves[:m]), newRoot, p); err != nil {
				t.Fatalf("m=%d n=%d: verify: %v", m, n, err)
			}
		}
	}
}

// RFC 6962 §2.1.3 worked example: the proofs for a 7-leaf tree.
func TestConsistencyRFC6962Example(t *testing.T) {
	d := makeLeaves(7)
	h := func(a, b [32]byte) [32]byte { return HashNode(a, b) }
	a, b, c := h(d[0], d[1]), h(d[2], d[3]), h(d[4], d[5])
	g, j := h(a, b), d[6]
	i := h(c, j)
	cases := []struct {
		m    uint64
		want [][32]byte
	}{
		{3, [][32]byte{d[2], d[3], a, i}}, // PROOF(3, D[7]) = [c, d, g, l]
		{4, [][32]byte{i}},                // PROOF(4, D[7]) = [l]
		{6, [][32]byte{c, j, g}},          // PROOF(6, D[7]) = [i, j, k]
	}
	for _, tc := range cases {
		p, err := ProveConsistency(d, tc.m)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Path) != len(tc.want) {
			t.Fatalf("m=%d: path %d hashes, want %d", tc.m, len(p.Path), len(tc.want))
		}
		for k := range p.Path {
			if p.Path[k] != tc.want[k] {
				t.Fatalf("m=%d: path[%d] differs from RFC 6962 §2.1.3", tc.m, k)
			}
		}
	}
}

func TestConsistencyRejectsTampering(t *testing.T) {
	const max = 33
	leaves := makeLeaves(max)
	for n := 2; n <= max; n++ {
		newRoot := Root(leaves[:n])
		for m := 1; m < n; m++ {
			oldRoot := Root(leaves[:m])
			p, _ := ProveConsistency(leaves[:n], uint64(m))
			reject := func(what string, o, nr [32]byte, q ConsistencyProof) {
				t.Helper()
				if VerifyConsistency(o, nr, q) == nil {
					t.Fatalf("m=%d n=%d: accepted %s", m, n, what)
				}
			}
			for k := range p.Path {
				q := cloneProof(p)
				q.Path[k][0] ^= 1
				reject("a flipped path hash", oldRoot, newRoot, q)
			}
			q := cloneProof(p)
			q.Path = append(q.Path, oldRoot)
			reject("a padded path", oldRoot, newRoot, q)
			q = cloneProof(p)
			q.Path = q.Path[:len(q.Path)-1]
			reject("a truncated path", oldRoot, newRoot, q)
			q = cloneProof(p)
			q.Path = nil
			reject("an empty path", oldRoot, newRoot, q)

			wrong := oldRoot
			wrong[31] ^= 1
			reject("a wrong old root", wrong, newRoot, p)
			wrong = newRoot
			wrong[31] ^= 1
			reject("a wrong new root", oldRoot, wrong, p)

			// Sizes are bound to roots by the signed head (size_be8 || root),
			// not by the proof: as in RFC 9162, a proof may also verify for a
			// different size with the same path length. A size change that
			// changes the expected path length must be rejected outright.
			for _, sz := range [][2]uint64{{uint64(m), uint64(n + 1)}, {uint64(m - 1), uint64(n)}, {uint64(m), uint64(n - 1)}} {
				if sz[0] == 0 || sz[0] >= sz[1] || consistencyPathLen(sz[0], sz[1]) == len(p.Path) {
					continue
				}
				q = cloneProof(p)
				q.OldSize, q.NewSize = sz[0], sz[1]
				reject("sizes that change the path length", oldRoot, newRoot, q)
			}
		}
	}
}

// A history rewritten after the old checkpoint was published (A9) must not
// be provably consistent with it, however the operator builds the proof.
func TestConsistencyDetectsRewrittenHistory(t *testing.T) {
	const n = 20
	honest := makeLeaves(n)
	for m := 1; m < n; m++ {
		oldRoot := Root(honest[:m])
		for victim := 0; victim < m; victim++ {
			forged := append([][32]byte(nil), honest...)
			forged[victim] = HashLeaf([]byte("rewritten"))
			p, _ := ProveConsistency(forged, uint64(m))
			if VerifyConsistency(oldRoot, Root(forged), p) == nil {
				t.Fatalf("m=%d: rewrite of leaf %d proved consistent", m, victim)
			}
		}
	}
}

func TestConsistencyEdgeCases(t *testing.T) {
	leaves := makeLeaves(5)
	r := Root(leaves)
	if _, err := ProveConsistency(leaves, 0); err == nil {
		t.Fatal("prove from size 0 accepted")
	}
	if _, err := ProveConsistency(leaves, 6); err == nil {
		t.Fatal("prove beyond tree size accepted")
	}
	if err := VerifyConsistency(r, r, ConsistencyProof{OldSize: 5, NewSize: 5}); err != nil {
		t.Fatalf("equal trees: %v", err)
	}
	if VerifyConsistency(r, r, ConsistencyProof{OldSize: 5, NewSize: 5, Path: [][32]byte{r}}) == nil {
		t.Fatal("equal sizes with a non-empty path accepted")
	}
	if VerifyConsistency(Root(leaves[:4]), r, ConsistencyProof{OldSize: 4, NewSize: 4}) == nil {
		t.Fatal("equal sizes with different roots accepted")
	}
	if VerifyConsistency(r, r, ConsistencyProof{OldSize: 6, NewSize: 5, Path: [][32]byte{r}}) == nil {
		t.Fatal("old size > new size accepted")
	}
	huge := ConsistencyProof{OldSize: 1<<63 + 1, NewSize: ^uint64(0), Path: [][32]byte{r}}
	if VerifyConsistency(r, r, huge) == nil {
		t.Fatal("wrong-length proof for huge sizes accepted")
	}
}

func cloneProof(p ConsistencyProof) ConsistencyProof {
	q := p
	q.Path = append([][32]byte(nil), p.Path...)
	return q
}

// FuzzConsistency: proofs from ProveConsistency always verify; arbitrary
// proofs never panic and never verify unless they equal the honest proof.
func FuzzConsistency(f *testing.F) {
	for _, s := range [][2]uint32{{1, 2}, {3, 7}, {4, 7}, {6, 7}, {8, 9}, {15, 16}, {16, 33}} {
		seed := binary.BigEndian.AppendUint32(nil, s[0])
		seed = binary.BigEndian.AppendUint32(seed, s[1])
		f.Add(append(seed, 0, 1, 2, 3))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 8 {
			return
		}
		m := uint64(binary.BigEndian.Uint32(data[0:4]))
		n := uint64(binary.BigEndian.Uint32(data[4:8]))
		if n == 0 || n > 512 || m == 0 || m > n {
			return
		}
		leaves := makeLeavesSeeded(int(n), data[8:])
		oldRoot, newRoot := Root(leaves[:m]), Root(leaves)
		p, err := ProveConsistency(leaves, m)
		if err != nil {
			t.Fatalf("prove m=%d n=%d: %v", m, n, err)
		}
		if err := VerifyConsistency(oldRoot, newRoot, p); err != nil {
			t.Fatalf("verify m=%d n=%d: %v", m, n, err)
		}
		// Build a mutated proof from the fuzz bytes; it must not panic and
		// must not verify unless it is byte-identical to the honest one.
		q := cloneProof(p)
		for i, b := range data[8:] {
			if len(q.Path) == 0 {
				break
			}
			q.Path[i%len(q.Path)][int(b)%32] ^= b
		}
		if VerifyConsistency(oldRoot, newRoot, q) == nil && !sameProof(p, q) {
			t.Fatalf("m=%d n=%d: mutated proof verified", m, n)
		}
	})
}

func makeLeavesSeeded(n int, seed []byte) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = HashLeaf(append(binary.BigEndian.AppendUint32(nil, uint32(i)), seed...))
	}
	return out
}

func sameProof(a, b ConsistencyProof) bool {
	if a.OldSize != b.OldSize || a.NewSize != b.NewSize || len(a.Path) != len(b.Path) {
		return false
	}
	for i := range a.Path {
		if a.Path[i] != b.Path[i] {
			return false
		}
	}
	return true
}

// FuzzVerifyConsistencyAdversarial feeds fully attacker-chosen sizes, roots
// and paths. VerifyConsistency must never panic, and must never accept a
// proof unless the sizes are a real (old < new) pair or the roots match.
func FuzzVerifyConsistencyAdversarial(f *testing.F) {
	f.Add(uint64(3), uint64(7), []byte{0, 1, 2, 3}, uint8(4))
	f.Add(uint64(1<<63+1), ^uint64(0), []byte{9}, uint8(70))
	f.Add(uint64(0), uint64(0), []byte{}, uint8(0))
	f.Fuzz(func(t *testing.T, m, n uint64, seed []byte, pathLen uint8) {
		var oldRoot, newRoot [32]byte
		copy(oldRoot[:], seed)
		for i := range newRoot {
			newRoot[i] = oldRoot[i] ^ 0xff
		}
		p := ConsistencyProof{OldSize: m, NewSize: n, Path: make([][32]byte, int(pathLen))}
		for i := range p.Path {
			p.Path[i] = HashLeaf(append([]byte{byte(i)}, seed...))
		}
		if VerifyConsistency(oldRoot, newRoot, p) == nil {
			t.Fatalf("accepted unrelated roots m=%d n=%d len=%d", m, n, pathLen)
		}
	})
}
