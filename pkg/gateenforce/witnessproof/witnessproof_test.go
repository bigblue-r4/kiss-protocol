package witnessproof_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce"
	"github.com/bigblue-r4/kiss-protocol/pkg/gateenforce/witnessproof"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func newSigner(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))}
}

func request() proto.ActionRequest {
	return proto.ActionRequest{
		V: 1, Class: "withdrawal_hot", Target: "wallet-svc", Asset: "BTC", Amount: "0.5",
		Destination: "bc1qexampledestination", RequestNonce: strings.Repeat("ab", 16),
		Principal: "svc-withdrawals", OriginHost: "app-01", TS: proto.FormatTime(time.Now().UTC().Truncate(time.Second)),
	}
}

// fixture writes a real witness log (the same store the daemon uses, signed
// by witnessKey) holding the gate's gate_request record for req among other
// records, and returns commit-wait evidence for it the way the gate builds it.
type fixture struct {
	w      proto.Witnessed
	hash   string
	export store.Export
	index  int
}

func build(t *testing.T, witnessKey keySigner, req proto.ActionRequest) fixture {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	s, err := store.Open(dir, key, witnessKey)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := proto.ActionHashHex(req)
	_ = s.Append("INFO", "daemon_start", "witness", map[string]string{"v": "test"})
	_ = s.Append("INFO", "drift_clean", "drift", nil)
	// A gate feed line as the witness stores it (the feed bridge appends the
	// parsed line map under the configured source).
	_ = s.Append("INFO", "gate_request", "gate", map[string]string{"kind": "gate_request", "action_hash": h, "request_id": "r1"})
	_ = s.Append("WARN", "sbh_decision:stop_and_ask", "sbh", map[string]string{"principal": "someone-else"})
	_ = s.Append("INFO", "drift_clean", "drift", nil)
	_ = s.Close()

	x, err := store.ExportDir(dir, key, store.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{w: witnessedAt(t, x, 2), hash: h, export: x, index: 2}
}

func witnessedAt(t *testing.T, x store.Export, i int) proto.Witnessed {
	t.Helper()
	leaves := make([][32]byte, len(x.LeafHashes))
	for j, lh := range x.LeafHashes {
		b, _ := hex.DecodeString(lh)
		copy(leaves[j][:], b)
	}
	p, err := merkle.Prove(leaves, uint64(i))
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(x.Entries[i])
	path := make([]string, len(p.Path))
	for j, h := range p.Path {
		path[j] = hex.EncodeToString(h[:])
	}
	return proto.Witnessed{
		Head:      proto.WitnessHead{Size: x.Head.Size, Root: x.Head.Root, Sig: x.Head.Signature, SignerKey: x.Head.SignerKey},
		LeafIndex: uint64(i), Entry: string(entry), Proof: path,
	}
}

func TestVerify(t *testing.T) {
	wk := newSigner(5)
	pins := []ed25519.PublicKey{wk.PublicKey()}
	f := build(t, wk, request())
	if err := witnessproof.Verify(f.w, f.hash, pins); err != nil {
		t.Fatalf("genuine evidence refused: %v", err)
	}

	otherReq := request()
	otherReq.Amount = "500"
	otherHash, _ := proto.ActionHashHex(otherReq)

	cases := map[string]func() (proto.Witnessed, string, []ed25519.PublicKey){
		"different action": func() (proto.Witnessed, string, []ed25519.PublicKey) { return f.w, otherHash, pins },
		"unpinned witness key": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			return f.w, f.hash, []ed25519.PublicKey{newSigner(6).PublicKey()}
		},
		// acceptance 16: a head forged by an attacker over a log they built.
		"forged head (attacker log, attacker key)": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			return build(t, newSigner(9), request()).w, f.hash, pins
		},
		"forged head (attacker key named as the real one)": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			w := build(t, newSigner(9), request()).w
			w.Head.SignerKey = hex.EncodeToString(wk.PublicKey())
			return w, f.hash, pins
		},
		"entry rewritten for another action": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			w := f.w
			w.Entry = strings.Replace(w.Entry, f.hash, otherHash, 1)
			return w, otherHash, pins
		},
		"head size edited": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			w := f.w
			w.Head.Size++
			return w, f.hash, pins
		},
		"proof for another leaf": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			w := witnessedAt(t, f.export, 1)
			w.Entry = f.w.Entry
			return w, f.hash, pins
		},
		"not a gate record (sbh line, real proof)": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			return witnessedAt(t, f.export, 3), f.hash, pins
		},
		"truncated proof": func() (proto.Witnessed, string, []ed25519.PublicKey) {
			w := f.w
			w.Proof = w.Proof[:len(w.Proof)-1]
			return w, f.hash, pins
		},
	}
	for name, mk := range cases {
		w, h, p := mk()
		if err := witnessproof.Verify(w, h, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestThroughGateenforce: commit-wait evidence plugged into the enforcement
// point end to end (acceptance 16, enforcement side).
func TestThroughGateenforce(t *testing.T) {
	wk, gate := newSigner(5), newSigner(3)
	req := request()
	f := build(t, wk, req)
	wv, err := witnessproof.New([]ed25519.PublicKey{wk.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	v, err := gateenforce.New(gateenforce.Config{GateKeys: []ed25519.PublicKey{gate.PublicKey()}, Witness: wv})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mint := func(w *proto.Witnessed, id string) []byte {
		tok, err := proto.SignToken(proto.Token{V: 1, TokenID: strings.Repeat(id, 16), ActionHash: f.hash,
			IssuedAt: proto.FormatTime(now), ExpiresAt: proto.FormatTime(now.Add(30 * time.Second)),
			PolicyHash: strings.Repeat("ee", 32), Witnessed: w}, gate)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := proto.Canonical(tok)
		return raw
	}
	opt := gateenforce.Options{CommitWait: true}
	if _, err := v.Check(req, mint(&f.w, "01"), opt); err != nil {
		t.Fatalf("genuine commit-wait token refused: %v", err)
	}
	forged := build(t, newSigner(9), req).w
	_, err = v.Check(req, mint(&forged, "02"), opt)
	var r *gateenforce.Refusal
	if err == nil || !errorsAs(err, &r) || r.Code != gateenforce.CommitWaitInvalid {
		t.Fatalf("forged head: got %v, want COMMIT_WAIT_INVALID", err)
	}
	if _, err := witnessproof.New(nil); err == nil {
		t.Error("witness verifier without pinned keys")
	}
}

func errorsAs(err error, r **gateenforce.Refusal) bool {
	x, ok := err.(*gateenforce.Refusal)
	*r = x
	return ok
}

// TestAuditPathLen checks the length guard against real proofs for every
// leaf of trees of size 1..70, and that no wrong-length proof reaches merkle.
func TestAuditPathLen(t *testing.T) {
	for n := 1; n <= 70; n++ {
		leaves := make([][32]byte, n)
		for i := range leaves {
			leaves[i] = merkle.HashLeaf([]byte{byte(i)})
		}
		for i := 0; i < n; i++ {
			p, err := merkle.Prove(leaves, uint64(i))
			if err != nil {
				t.Fatal(err)
			}
			if got := witnessproof.AuditPathLen(uint64(i), uint64(n)); got != len(p.Path) {
				t.Fatalf("size %d leaf %d: guard says %d, real proof has %d", n, i, got, len(p.Path))
			}
		}
	}
}

// TestHugeSizeRefused: a token claiming a tree of ~2^62 leaves, with a proof
// of the matching length, must be refused, not hang (internal/merkle's
// split-point loop never ends at that size).
func TestHugeSizeRefused(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		size := uint64(1)<<62 + 1
		proof := make([]string, 63)
		for i := range proof {
			proof[i] = strings.Repeat("ab", 32)
		}
		w := proto.Witnessed{Head: proto.WitnessHead{Size: size, Root: strings.Repeat("ab", 32),
			Sig: strings.Repeat("cd", 64), SignerKey: hex.EncodeToString(newSigner(5).PublicKey())},
			LeafIndex: 0, Entry: "{}", Proof: proof}
		done <- witnessproof.Verify(w, strings.Repeat("ab", 32), []ed25519.PublicKey{newSigner(5).PublicKey()})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("huge head accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Verify hung on a huge head size")
	}
}
