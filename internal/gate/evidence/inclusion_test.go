package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce/witnessproof"
)

func TestLevelsPathMatchesMerkleProve(t *testing.T) {
	var lv levels
	var leaves [][32]byte
	for n := 1; n <= 130; n++ {
		h := merkle.HashLeaf([]byte(fmt.Sprint(n)))
		leaves = append(leaves, h)
		lv.push(h)
		if got, want := lv.mth(0, uint64(n)), merkle.Root(leaves); got != want {
			t.Fatalf("n=%d: root mismatch", n)
		}
		for m := 0; m < n; m++ {
			p, err := merkle.Prove(leaves, uint64(m))
			if err != nil {
				t.Fatal(err)
			}
			got := lv.path(uint64(m), 0, uint64(n))
			if len(got) != len(p.Path) {
				t.Fatalf("n=%d m=%d: path len %d want %d", n, m, len(got), len(p.Path))
			}
			for i := range got {
				if got[i] != p.Path[i] {
					t.Fatalf("n=%d m=%d: path[%d] differs", n, m, i)
				}
			}
		}
	}
}

// The view's commit-wait evidence verifies with the enforcement point's own
// checker (acceptance 16, view side), and fails against another witness key.
func TestInclusionVerifiesWithWitnessproof(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 3, "pre")
	defer st.Close()
	hash := fmt.Sprintf("ab%062x", 7)
	app := func(event, source string, data any) {
		if err := st.Append("INFO", event, source, data); err != nil {
			t.Fatal(err)
		}
	}
	app("gate_request", "gate", map[string]any{"kind": "gate_request", "action_hash": hash})
	app("drift_clean", "drift", nil)
	app("breaker_trip", "gate", map[string]any{"kind": "breaker_trip", "epoch": "1"})
	pins := []ed25519.PublicKey{wk.PublicKey()}
	v := newView(t, dir, pins, &clock{t: time.Now()})
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Inclusion(fmt.Sprintf("cd%062x", 7)); err != ErrNotWitnessed {
		t.Fatalf("unknown hash: %v", err)
	}
	w, err := v.Inclusion(hash)
	if err != nil {
		t.Fatal(err)
	}
	if w.LeafIndex != 3 || w.Head.Size != 6 {
		t.Fatalf("index %d size %d", w.LeafIndex, w.Head.Size)
	}
	if err := witnessproof.Verify(w, hash, pins); err != nil {
		t.Fatalf("witnessproof rejects the view's evidence: %v", err)
	}
	if err := witnessproof.Verify(w, hash, []ed25519.PublicKey{newSigner(9).PublicKey()}); err == nil {
		t.Fatal("evidence must not verify against an unpinned witness key")
	}
	// Still valid after the log grows (proof against the newer head).
	for i := 0; i < 37; i++ {
		app("drift_clean", "drift", map[string]int{"i": i})
	}
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	w, _ = v.Inclusion(hash)
	if w.Head.Size != 43 || witnessproof.Verify(w, hash, pins) != nil {
		t.Fatalf("after growth: size %d", w.Head.Size)
	}
	g := v.GateEvents()
	if len(g) != 1 || g[0].Event != "breaker_trip" {
		t.Fatalf("gate events %+v", g)
	}
	var d map[string]any
	if err := json.Unmarshal(g[0].Data, &d); err != nil {
		t.Fatal(err)
	}
	if d["epoch"] != "1" {
		t.Fatalf("data %v", d)
	}
}
