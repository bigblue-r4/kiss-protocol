package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
)

// A verifier that kept an earlier signed head needs only the newer head, a
// consistency proof and the public key to tell an extended log from a
// rewritten, re-signed or rolled-back one (spec C7.3.5, attack A9).

func headAfter(t *testing.T, st *Store, events ...string) TreeHead {
	t.Helper()
	for _, ev := range events {
		if err := st.Append("INFO", ev, "src", nil); err != nil {
			t.Fatal(err)
		}
	}
	return signedHead(t, st)
}

// signedHead is the head as published: tree-head.json, signed.
func signedHead(t *testing.T, st *Store) TreeHead {
	t.Helper()
	h, err := readStoredHead(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func jsonRoundTrip[T any](t *testing.T, v T) T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConsistencyHonestExtension(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s)
	var heads []TreeHead
	for i := 0; i < 9; i++ {
		heads = append(heads, headAfter(t, st, "e"))
	}
	for i, old := range heads {
		d, err := st.ConsistencyProof(old.Size)
		if err != nil {
			t.Fatal(err)
		}
		d = jsonRoundTrip(t, d)
		if err := VerifyConsistency(jsonRoundTrip(t, old), jsonRoundTrip(t, signedHead(t, st)), d, pins(s)); err != nil {
			t.Fatalf("head %d (size %d): %v", i, old.Size, err)
		}
	}
}

func TestConsistencyDetectsReSignedRewrite(t *testing.T) {
	s := newTestDevSigner(t)
	honest := exportStore(t, s, "a", "b", "c", "d")
	published := signedHead(t, honest)

	// The operator (holding the key) rebuilds the log with record 2 changed
	// and more records after it, and signs every head with the real key.
	forged := exportStore(t, s, "a", "B!", "c", "d", "e", "f")
	d, err := forged.ConsistencyProof(published.Size)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyConsistency(published, signedHead(t, forged), d, pins(s))
	if err == nil {
		t.Fatal("re-signed rewrite passed")
	}
	// Lying in the proof's old root to match the forged prefix doesn't help.
	d.OldRoot = published.Root
	if err := VerifyConsistency(published, signedHead(t, forged), d, pins(s)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("forged proof with the published old root: %v, want ErrInconsistent", err)
	}
}

func TestConsistencyDetectsRollback(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s, "a", "b", "c", "d")
	early := signedHead(t, st)
	later := headAfter(t, st, "e", "f", "g", "h")
	d, err := st.ConsistencyProof(early.Size)
	if err != nil {
		t.Fatal(err)
	}
	// Presenting the early head as "current" to a verifier that holds the later one.
	d.OldSize, d.OldRoot, d.NewSize, d.NewRoot = later.Size, later.Root, early.Size, early.Root
	if err := VerifyConsistency(later, early, d, pins(s)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("rollback: %v, want ErrInconsistent", err)
	}
}

func TestConsistencyRejectsBadInputs(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s, "a", "b", "c")
	old := signedHead(t, st)
	cur := headAfter(t, st, "d", "e")
	good, _ := st.ConsistencyProof(old.Size)
	other := newTestDevSigner(t)

	for _, tc := range []struct {
		name string
		mut  func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey)
	}{
		{"unknown format", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { d.Format = "x" }},
		{"no pins", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { *p = nil }},
		{"wrong signer pinned", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { *p = pins(other) }},
		{"unsigned new head", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { n.Signature = "" }},
		{"bad old signature", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) {
			b := []byte(o.Signature)
			b[0] ^= 1
			o.Signature = string(b)
		}},
		{"proof for another old head", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { d.OldSize-- }},
		{"proof for another new head", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { d.NewRoot = d.OldRoot }},
		{"malformed path hash", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { d.Path[0] = "zz" }},
		{"altered path hash", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) {
			d.Path[0] = d.NewRoot
		}},
		{"empty old head", func(o, n *TreeHead, d *ConsistencyDoc, p *[]ed25519.PublicKey) { *o = TreeHead{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, n, d, p := old, cur, jsonRoundTrip(t, good), pins(s)
			tc.mut(&o, &n, &d, &p)
			if err := VerifyConsistency(o, n, d, p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if err := VerifyConsistency(old, cur, good, pins(s)); err != nil {
		t.Fatalf("control: %v", err)
	}
}
