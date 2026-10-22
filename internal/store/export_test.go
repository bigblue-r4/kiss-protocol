package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// An export must verify with nothing but the signer's public key, and every
// way of lying about the log after the fact must fail: altered entries, a
// rewritten history, a truncation, a forged signer.

func exportStore(t *testing.T, s *testDevSigner, events ...string) *Store {
	t.Helper()
	st, err := Open(t.TempDir(), testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	for _, ev := range events {
		if err := st.Append("INFO", ev, "src-"+ev, map[string]any{"trial": "T-A-0001", "note": "<html> & é"}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// roundTrip sends the export through JSON, as it travels between machines.
func roundTrip(t *testing.T, x Export) Export {
	t.Helper()
	b, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	y, err := ReadExport(b)
	if err != nil {
		t.Fatal(err)
	}
	return y
}

func pins(s *testDevSigner) []ed25519.PublicKey { return []ed25519.PublicKey{s.PublicKey()} }

func TestExportVerifiesOffline(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s, "a", "b", "c")
	x, err := st.Export(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyExport(roundTrip(t, x), pins(s), nil)
	if err != nil {
		t.Fatalf("clean export failed: %v", err)
	}
	if r.Size != 3 || r.EntriesSeen != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestExportFilterStillProvesEntries(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s, "a", "b", "c")
	x, err := st.Export(Filter{Sources: []string{"src-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Entries) != 1 || x.Entries[0].Event != "b" || len(x.LeafHashes) != 3 {
		t.Fatalf("filter: %d entries, %d leaves", len(x.Entries), len(x.LeafHashes))
	}
	if _, err := VerifyExport(roundTrip(t, x), pins(s), nil); err != nil {
		t.Fatal(err)
	}
	future, err := st.Export(Filter{Since: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(future.Entries) != 0 {
		t.Fatalf("since filter kept %d entries", len(future.Entries))
	}
}

func TestExportDetectsAlteredEntry(t *testing.T) {
	s := newTestDevSigner(t)
	x, _ := exportStore(t, s, "a", "b").Export(Filter{})
	x = roundTrip(t, x)
	x.Entries[1].Level = "WARN"
	if _, err := VerifyExport(x, pins(s), nil); err == nil || !strings.Contains(err.Error(), "does not match its leaf") {
		t.Fatalf("altered entry passed: %v", err)
	}
}

func TestExportDetectsDroppedLeaf(t *testing.T) {
	s := newTestDevSigner(t)
	x, _ := exportStore(t, s, "a", "b", "c").Export(Filter{})
	x.LeafHashes = x.LeafHashes[:2]
	if _, err := VerifyExport(x, pins(s), nil); err == nil {
		t.Fatal("dropped leaf passed")
	}
}

func TestExportNeedsAPinnedSigner(t *testing.T) {
	s := newTestDevSigner(t)
	x, _ := exportStore(t, s, "a").Export(Filter{})
	if _, err := VerifyExport(x, nil, nil); err == nil {
		t.Fatal("verified with no pin")
	}
	other := newTestDevSigner(t)
	if _, err := VerifyExport(x, pins(other), nil); !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("wrong signer: %v", err)
	}
}

func TestExportForgedHeadSignatureFails(t *testing.T) {
	s := newTestDevSigner(t)
	x, _ := exportStore(t, s, "a", "b").Export(Filter{})
	x.Head.Signature = strings.Repeat("00", ed25519.SignatureSize)
	if _, err := VerifyExport(x, pins(s), nil); err == nil {
		t.Fatal("forged signature passed")
	}
}

// The append-only check: heads pulled off the host earlier must be prefixes of
// the log exported now.
func TestExportPriorHeads(t *testing.T) {
	s := newTestDevSigner(t)
	st := exportStore(t, s, "a", "b")
	early, _ := st.Export(Filter{})
	for _, ev := range []string{"c", "d", "e"} {
		_ = st.Append("INFO", ev, "x", nil)
	}
	late, _ := st.Export(Filter{})
	if r, err := VerifyExport(late, pins(s), []TreeHead{early.Head}); err != nil || r.PriorsOK != 1 {
		t.Fatalf("honest growth failed: %v", err)
	}

	// A rewritten history: same length as the prior, different content.
	other := exportStore(t, s, "a", "B")
	rewritten, _ := other.Export(Filter{})
	if _, err := VerifyExport(rewritten, pins(s), []TreeHead{early.Head}); err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Fatalf("rewrite passed: %v", err)
	}

	// A truncation: shorter than a head already held off-host.
	if _, err := VerifyExport(early, pins(s), []TreeHead{late.Head}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncation passed: %v", err)
	}
}

func TestExportEmptyLog(t *testing.T) {
	s := newTestDevSigner(t)
	x, err := exportStore(t, s).Export(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyExport(roundTrip(t, x), pins(s), nil); err != nil {
		t.Fatal(err)
	}
}
