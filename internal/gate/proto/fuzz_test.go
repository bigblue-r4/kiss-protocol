package proto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// Every decoder must: never panic; accept only input that is its own
// canonical encoding (so a value has exactly one accepted spelling); and leave
// the signature checks safe to call on whatever it returned.

func seedCorpus(f *testing.F, vals ...any) {
	for _, v := range vals {
		c, err := Canonical(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(c)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"v":1,"v":1}`))
	f.Add([]byte(``))
}

func mustCanonical(t *testing.T, in []byte, v any) {
	t.Helper()
	re, err := Canonical(v)
	if err != nil {
		t.Fatalf("decoded value does not re-encode: %v", err)
	}
	if !bytes.Equal(re, in) {
		t.Fatalf("accepted non-canonical input:\n in %q\n re %q", in, re)
	}
}

func FuzzDecodeToken(f *testing.F) {
	gate := newSigner(3)
	tk, _ := SignToken(Token{V: 1, TokenID: "0101010101010101010101010101010" + "1", ActionHash: goldenActionHash,
		IssuedAt: FormatTime(t0), ExpiresAt: FormatTime(t0.Add(30 * time.Second)), BreakerEpoch: 1,
		PolicyHash: goldenActionHash, Witnessed: &Witnessed{Head: WitnessHead{Size: 2, Root: goldenActionHash}, LeafIndex: 1, Entry: `{"seq":2}`, Proof: []string{goldenActionHash}}}, gate)
	seedCorpus(f, tk)
	pins := []ed25519.PublicKey{gate.PublicKey()}
	f.Fuzz(func(t *testing.T, data []byte) {
		x, err := DecodeToken(data)
		if err != nil {
			return
		}
		mustCanonical(t, data, x)
		_ = VerifyTokenSig(x, pins)
		_, _, _ = x.Times()
	})
}

func FuzzDecodeActionRequest(f *testing.F) {
	seedCorpus(f, baseRequest())
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeActionRequest(data)
		if err != nil {
			return
		}
		mustCanonical(t, data, r)
		if _, err := ActionHash(r); err != nil {
			t.Fatalf("valid request has no action_hash: %v", err)
		}
	})
}

func FuzzDecodeApproval(f *testing.F) {
	alice := newSigner(1)
	a, _ := SignApproval(Approval{V: 1, ActionHash: goldenActionHash, ApproverLabel: "alice", ExpiresAt: FormatTime(t0)}, alice)
	seedCorpus(f, a)
	ops := []Operator{{"alice", alice.PublicKey()}}
	f.Fuzz(func(t *testing.T, data []byte) {
		x, err := DecodeApproval(data)
		if err != nil {
			return
		}
		mustCanonical(t, data, x)
		_, _ = VerifyApprovals([]Approval{x}, goldenActionHash, ops, 1, t0)
	})
}

func FuzzDecodeEpoch(f *testing.F) {
	gate := newSigner(3)
	e, _ := SignEpoch(Epoch{V: 1, Epoch: 2, IssuedAt: FormatTime(t0), OpenScopes: []Scope{{ScopeGlobal, ""}}}, gate)
	seedCorpus(f, e)
	pins := []ed25519.PublicKey{gate.PublicKey()}
	f.Fuzz(func(t *testing.T, data []byte) {
		x, err := DecodeEpoch(data)
		if err != nil {
			return
		}
		mustCanonical(t, data, x)
		_, _ = VerifyEpoch(x, pins)
		_, _ = x.Frozen(baseRequest())
	})
}

func FuzzDecodeResetBundle(f *testing.F) {
	a := newSigner(1)
	r := Reset{V: 1, Scope: Scope{ScopeClass, "withdrawal_hot"}, NewEpoch: 3, Reason: "ok", Nonce: "0101010101010101010101010101010" + "1", TS: FormatTime(t0)}
	p, _ := SignReset(r, "alice", a)
	seedCorpus(f, ResetBundle{Reset: r, Partials: []PartialSig{p}})
	ops := []Operator{{"alice", a.PublicKey()}}
	f.Fuzz(func(t *testing.T, data []byte) {
		x, err := DecodeResetBundle(data)
		if err != nil {
			return
		}
		mustCanonical(t, data, x)
		_, _ = VerifyResetQuorum(x, ops, 1)
	})
}

func FuzzParseAmount(f *testing.F) {
	for _, s := range []string{"0", "1", "0.5", "1.230", "1e3", "-1", "99999999999999999999.999999999999999999"} {
		f.Add(s, 8)
	}
	f.Fuzz(func(t *testing.T, s string, decimals int) {
		n, err := ParseAmount(s, decimals)
		if err != nil {
			return
		}
		if n.Sign() < 0 {
			t.Fatalf("ParseAmount(%q) negative: %s", s, n)
		}
	})
}
