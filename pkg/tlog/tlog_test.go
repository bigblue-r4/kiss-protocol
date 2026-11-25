package tlog

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

func leafData(i int) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return b[:]
}

// oracle builds the Go checksum database's tree (golang.org/x/mod/sumdb/tlog,
// an independent RFC 6962 SHA-256 implementation) over the same leaves.
type oracle struct{ stored []xtlog.Hash }

func (o *oracle) ReadHashes(idx []int64) ([]xtlog.Hash, error) {
	out := make([]xtlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = o.stored[x]
	}
	return out, nil
}

func (o *oracle) add(n int64, data []byte) {
	h, err := xtlog.StoredHashes(n, data, o)
	if err != nil {
		panic(err)
	}
	o.stored = append(o.stored, h...)
}

func TestAgainstXModOracle(t *testing.T) {
	const max = 80
	o := &oracle{}
	var leaves []Hash
	for i := 0; i < max; i++ {
		d := leafData(i)
		if HashLeaf(d) != Hash(xtlog.RecordHash(d)) {
			t.Fatalf("leaf %d: hash differs from x/mod", i)
		}
		o.add(int64(i), d)
		leaves = append(leaves, HashLeaf(d))
	}
	for n := 1; n <= max; n++ {
		want, err := xtlog.TreeHash(int64(n), o)
		if err != nil {
			t.Fatal(err)
		}
		if got := Root(leaves[:n]); got != Hash(want) {
			t.Fatalf("root(%d) differs from x/mod", n)
		}
		for i := 0; i < n; i++ {
			p, _ := ProveInclusion(leaves[:n], uint64(i))
			xp := make(xtlog.RecordProof, len(p))
			for j := range p {
				xp[j] = xtlog.Hash(p[j])
			}
			if err := xtlog.CheckRecord(xp, int64(n), want, int64(i), xtlog.Hash(leaves[i])); err != nil {
				t.Fatalf("x/mod rejects our inclusion proof %d/%d: %v", i, n, err)
			}
			if err := VerifyInclusion(Root(leaves[:n]), leaves[i], uint64(i), uint64(n), p); err != nil {
				t.Fatalf("own inclusion %d/%d: %v", i, n, err)
			}
		}
		for m := 0; m <= n; m++ {
			p, err := ProveConsistency(leaves[:n], uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			oldRoot := Root(leaves[:m])
			if err := VerifyConsistency(uint64(m), uint64(n), oldRoot, Root(leaves[:n]), p); err != nil {
				t.Fatalf("own consistency %d->%d: %v", m, n, err)
			}
			if m == 0 {
				continue
			}
			xp, err := xtlog.ProveTree(int64(n), int64(m), o)
			if err != nil {
				t.Fatal(err)
			}
			if len(xp) != len(p) {
				t.Fatalf("consistency %d->%d: length %d, x/mod %d", m, n, len(p), len(xp))
			}
			for j := range p {
				if p[j] != Hash(xp[j]) {
					t.Fatalf("consistency %d->%d differs from x/mod at %d", m, n, j)
				}
			}
		}
	}
}

func TestEmptyTree(t *testing.T) {
	if EmptyRoot != sha256.Sum256(nil) || Root(nil) != EmptyRoot {
		t.Fatal("empty root is not SHA-256 of the empty string")
	}
	leaves := []Hash{HashLeaf([]byte("a"))}
	if err := VerifyConsistency(0, 1, EmptyRoot, Root(leaves), nil); err != nil {
		t.Fatal(err)
	}
	if VerifyConsistency(0, 1, EmptyRoot, Root(leaves), []Hash{{}}) == nil {
		t.Fatal("accepted a non-empty proof from size 0")
	}
	if VerifyConsistency(0, 1, Hash{}, Root(leaves), nil) == nil {
		t.Fatal("accepted size 0 with a non-empty-tree root")
	}
}

func TestRewriteDetected(t *testing.T) {
	var a, b []Hash
	for i := 0; i < 20; i++ {
		a = append(a, HashLeaf(leafData(i)))
		b = append(b, HashLeaf(leafData(i)))
	}
	b[3] = HashLeaf([]byte("rewritten"))
	for m := 1; m < 20; m++ {
		p, _ := ProveConsistency(b, uint64(m))
		err := VerifyConsistency(uint64(m), 20, Root(a[:m]), Root(b), p)
		if m > 3 && err == nil {
			t.Fatalf("rewrite at leaf 3 not detected from size %d", m)
		}
	}
	if VerifyConsistency(5, 5, Root(a[:5]), Root(b[:5]), nil) == nil {
		t.Fatal("equal sizes with different roots accepted")
	}
	if VerifyConsistency(6, 5, Root(a[:6]), Root(a[:5]), nil) == nil {
		t.Fatal("shrinking tree accepted")
	}
}

func TestTamperedProofs(t *testing.T) {
	var l []Hash
	for i := 0; i < 37; i++ {
		l = append(l, HashLeaf(leafData(i)))
	}
	root := Root(l)
	for m := 1; m < 37; m++ {
		p, _ := ProveConsistency(l, uint64(m))
		for j := range p {
			q := append([]Hash(nil), p...)
			q[j][0] ^= 1
			if VerifyConsistency(uint64(m), 37, Root(l[:m]), root, q) == nil {
				t.Fatalf("flipped hash %d in proof %d->37 accepted", j, m)
			}
		}
		if VerifyConsistency(uint64(m), 37, Root(l[:m]), root, append(p, Hash{})) == nil {
			t.Fatalf("padded proof %d->37 accepted", m)
		}
		if len(p) > 0 && VerifyConsistency(uint64(m), 37, Root(l[:m]), root, p[:len(p)-1]) == nil {
			t.Fatalf("truncated proof %d->37 accepted", m)
		}
	}
	p, _ := ProveInclusion(l, 5)
	if VerifyInclusion(root, l[6], 5, 37, p) == nil {
		t.Fatal("wrong leaf accepted")
	}
	if VerifyInclusion(root, l[5], 37, 37, p) == nil {
		t.Fatal("index out of range accepted")
	}
}

func FuzzVerifyConsistency(f *testing.F) {
	f.Add(uint64(3), uint64(7), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, m, n uint64, raw []byte) {
		var path []Hash
		for len(raw) >= 32 && len(path) < 70 {
			var h Hash
			copy(h[:], raw)
			path = append(path, h)
			raw = raw[32:]
		}
		_ = VerifyConsistency(m, n, Hash{}, Hash{1}, path)
		_ = VerifyInclusion(Hash{}, Hash{1}, m, n, path)
	})
}
