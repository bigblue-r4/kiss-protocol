package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func newSigner(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))}
}

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func baseRequest() ActionRequest {
	return ActionRequest{
		V: 1, Class: "withdrawal_hot", Target: "wallet-svc", Asset: "BTC", Amount: "0.5",
		Destination: "bc1qexampledestination", RequestNonce: strings.Repeat("ab", 16),
		Principal: "svc-withdrawals", OriginHost: "app-01", TS: FormatTime(t0),
	}
}

// TestActionHashGolden pins the action_hash of a fixed request. It is the
// interop contract with external signers: if this changes, every deployed
// approval and enforcement point breaks. Change it only with a format version bump.
func TestActionHashGolden(t *testing.T) {
	c, err := Canonical(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	wantCanon := `{"v":1,"class":"withdrawal_hot","target":"wallet-svc","asset":"BTC","amount":"0.5","destination":"bc1qexampledestination","request_nonce":"abababababababababababababababab","principal":"svc-withdrawals","origin_host":"app-01","ts":"2026-11-03T12:00:00Z"}`
	if string(c) != wantCanon {
		t.Fatalf("canonical form changed:\n got %s\nwant %s", c, wantCanon)
	}
	h, err := ActionHashHex(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	if h != goldenActionHash {
		t.Fatalf("action_hash changed: got %s want %s", h, goldenActionHash)
	}
}

func TestActionHashBindsEveryField(t *testing.T) {
	base, _ := ActionHashHex(baseRequest())
	muts := map[string]func(*ActionRequest){
		"class":       func(r *ActionRequest) { r.Class = "withdrawal_cold" },
		"target":      func(r *ActionRequest) { r.Target = "wallet-svc-2" },
		"asset":       func(r *ActionRequest) { r.Asset = "ETH" },
		"amount":      func(r *ActionRequest) { r.Amount = "0.50" },
		"destination": func(r *ActionRequest) { r.Destination = "bc1qattacker" },
		"nonce":       func(r *ActionRequest) { r.RequestNonce = strings.Repeat("cd", 16) },
		"principal":   func(r *ActionRequest) { r.Principal = "svc-other" },
		"origin_host": func(r *ActionRequest) { r.OriginHost = "laptop-07" },
		"ts":          func(r *ActionRequest) { r.TS = FormatTime(t0.Add(time.Second)) },
	}
	for name, m := range muts {
		r := baseRequest()
		m(&r)
		h, err := ActionHashHex(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h == base {
			t.Errorf("%s: changing it did not change action_hash", name)
		}
	}
}

func TestActionRequestValidate(t *testing.T) {
	bad := map[string]func(*ActionRequest){
		"version":           func(r *ActionRequest) { r.V = 2 },
		"empty class":       func(r *ActionRequest) { r.Class = "" },
		"class spaces":      func(r *ActionRequest) { r.Class = "with drawal" },
		"negative amount":   func(r *ActionRequest) { r.Amount = "-1" },
		"exponent amount":   func(r *ActionRequest) { r.Amount = "1e9" },
		"leading zero":      func(r *ActionRequest) { r.Amount = "01" },
		"no asset w/ value": func(r *ActionRequest) { r.Asset = "" },
		"short nonce":       func(r *ActionRequest) { r.RequestNonce = "abcd" },
		"upper nonce":       func(r *ActionRequest) { r.RequestNonce = strings.Repeat("AB", 16) },
		"local ts":          func(r *ActionRequest) { r.TS = "2026-11-03T02:00:00-10:00" },
		"control in dest":   func(r *ActionRequest) { r.Destination = "a\nb" },
		"empty target":      func(r *ActionRequest) { r.Target = "" },
	}
	for name, m := range bad {
		r := baseRequest()
		m(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noValue := baseRequest()
	noValue.Asset, noValue.Amount, noValue.Class = "", "0", "prod_deploy"
	if err := noValue.Validate(); err != nil {
		t.Errorf("value-free action rejected: %v", err)
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	good, _ := Canonical(baseRequest())
	if _, err := DecodeActionRequest(good); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	cases := map[string]string{
		"whitespace":   strings.Replace(string(good), `"v":1,`, `"v": 1,`, 1),
		"reordered":    strings.Replace(string(good), `{"v":1,"class":"withdrawal_hot",`, `{"class":"withdrawal_hot","v":1,`, 1),
		"case folded":  strings.Replace(string(good), `"class"`, `"Class"`, 1),
		"duplicate":    strings.Replace(string(good), `"v":1,`, `"v":1,"v":1,`, 1),
		"unknown":      strings.Replace(string(good), `"v":1,`, `"v":1,"extra":"x",`, 1),
		"trailing":     string(good) + `{}`,
		"trailing nl":  string(good) + "\n",
		"html escaped": strings.Replace(string(good), "wallet-svc", "wallet\\u003csvc", 1),
	}
	for name, in := range cases {
		if _, err := DecodeActionRequest([]byte(in)); err == nil {
			t.Errorf("%s: accepted %s", name, in)
		}
	}
}

func TestParseAmount(t *testing.T) {
	cases := []struct {
		in   string
		dec  int
		want string
		ok   bool
	}{
		{"0", 8, "0", true},
		{"1", 8, "100000000", true},
		{"0.5", 8, "50000000", true},
		{"21000000.00000001", 8, "2100000000000001", true},
		{"1.230", 2, "123", true}, // trailing zero beyond precision is exact
		{"1.231", 2, "", false},   // never rounded
		{"1.5", 0, "", false},
		{"1e3", 2, "", false},
		{"-1", 2, "", false},
		{" 1", 2, "", false},
		{"1.", 2, "", false},
		{".5", 2, "", false},
		{"123456789012345678901234567890", 18, "123456789012345678901234567890000000000000000000", true},
	}
	for _, c := range cases {
		got, err := ParseAmount(c.in, c.dec)
		if c.ok != (err == nil) {
			t.Errorf("ParseAmount(%q,%d) err=%v, want ok=%v", c.in, c.dec, err, c.ok)
			continue
		}
		if c.ok && got.String() != c.want {
			t.Errorf("ParseAmount(%q,%d) = %s, want %s", c.in, c.dec, got, c.want)
		}
	}
}

func approval(t *testing.T, s keySigner, label, hash string, exp time.Time) Approval {
	t.Helper()
	a, err := SignApproval(Approval{V: 1, ActionHash: hash, ApproverLabel: label, ExpiresAt: FormatTime(exp)}, s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestApprovals(t *testing.T) {
	alice, bob, mallory := newSigner(1), newSigner(2), newSigner(9)
	ops := []Operator{{"alice", alice.PublicKey()}, {"bob", bob.PublicKey()}, {"alice-backup", alice.PublicKey()}}
	h, _ := ActionHashHex(baseRequest())
	other, _ := ActionHashHex(func() ActionRequest { r := baseRequest(); r.Amount = "500"; return r }())
	exp := t0.Add(time.Minute)

	if _, err := VerifyApprovals([]Approval{approval(t, alice, "alice", h, exp)}, h, ops, 1, t0); err != nil {
		t.Fatalf("valid approval refused: %v", err)
	}
	tampered := approval(t, alice, "alice", h, exp)
	tampered.ActionHash = other
	forgedLabel := approval(t, mallory, "alice", h, exp)
	relabelled := approval(t, alice, "alice", h, exp)
	relabelled.ApproverLabel = "bob"
	cases := []struct {
		name string
		as   []Approval
		hash string
		req  int
		want error
	}{
		{"wrong key under a real label", []Approval{forgedLabel}, h, 1, ErrApprovalInvalid},
		{"approval for another action", []Approval{approval(t, alice, "alice", other, exp)}, h, 1, ErrApprovalInvalid},
		{"action_hash edited after signing", []Approval{tampered}, other, 1, ErrApprovalInvalid},
		{"label edited after signing", []Approval{relabelled}, h, 1, ErrApprovalInvalid},
		{"expired", []Approval{approval(t, alice, "alice", h, t0)}, h, 1, ErrApprovalExpired},
		{"unknown operator", []Approval{approval(t, mallory, "mallory", h, exp)}, h, 1, ErrApprovalInvalid},
		{"none", nil, h, 1, ErrTooFewApprovals},
		{"one key, two labels, two required", []Approval{approval(t, alice, "alice", h, exp), approval(t, alice, "alice-backup", h, exp)}, h, 2, ErrTooFewApprovals},
		{"same approval twice, two required", []Approval{approval(t, alice, "alice", h, exp), approval(t, alice, "alice", h, exp)}, h, 2, ErrTooFewApprovals},
	}
	for _, c := range cases {
		_, err := VerifyApprovals(c.as, c.hash, ops, c.req, t0)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	labels, err := VerifyApprovals([]Approval{approval(t, alice, "alice", h, exp), forgedLabel, approval(t, bob, "bob", h, exp)}, h, ops, 2, t0)
	if err != nil || len(labels) != 2 {
		t.Fatalf("two distinct operators: labels=%v err=%v", labels, err)
	}
}

func token(t *testing.T, s keySigner, mod func(*Token)) Token {
	t.Helper()
	h, _ := ActionHashHex(baseRequest())
	tk := Token{
		V: 1, TokenID: strings.Repeat("01", 16), ActionHash: h,
		IssuedAt: FormatTime(t0), ExpiresAt: FormatTime(t0.Add(DefaultTokenLifetime)),
		BreakerEpoch: 7, PolicyHash: strings.Repeat("ee", 32),
	}
	if mod != nil {
		mod(&tk)
	}
	out, err := SignToken(tk, s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTokenSignVerify(t *testing.T) {
	gate, attacker := newSigner(3), newSigner(9)
	pins := []ed25519.PublicKey{gate.PublicKey()}
	tk := token(t, gate, nil)
	raw, _ := Canonical(tk)
	dec, err := DecodeToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTokenSig(dec, pins); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if err := VerifyTokenSig(token(t, attacker, nil), pins); err == nil {
		t.Error("token from an unpinned key accepted")
	}
	// Attacker swaps in the real gate_key but keeps their own signature.
	swapped := token(t, attacker, nil)
	swapped.GateKey = hex.EncodeToString(gate.PublicKey())
	if err := VerifyTokenSig(swapped, pins); err == nil {
		t.Error("token with substituted gate_key accepted")
	}
	for name, m := range map[string]func(*Token){
		"epoch":   func(x *Token) { x.BreakerEpoch++ },
		"expiry":  func(x *Token) { x.ExpiresAt = FormatTime(t0.Add(time.Minute)) },
		"action":  func(x *Token) { x.ActionHash = strings.Repeat("00", 32) },
		"policy":  func(x *Token) { x.PolicyHash = strings.Repeat("ff", 32) },
		"tokenid": func(x *Token) { x.TokenID = strings.Repeat("02", 16) },
	} {
		x := tk
		m(&x)
		if err := VerifyTokenSig(x, pins); err == nil {
			t.Errorf("token with %s edited after signing accepted", name)
		}
	}
	if _, err := SignToken(Token{V: 1, TokenID: tk.TokenID, ActionHash: tk.ActionHash, PolicyHash: tk.PolicyHash,
		IssuedAt: FormatTime(t0), ExpiresAt: FormatTime(t0.Add(MaxTokenLifetime + time.Second))}, gate); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("over-long token lifetime: err = %v", err)
	}
	if _, err := SignToken(Token{V: 1, TokenID: tk.TokenID, ActionHash: tk.ActionHash, PolicyHash: tk.PolicyHash,
		IssuedAt: FormatTime(t0), ExpiresAt: FormatTime(t0.Add(time.Second)),
		Witnessed: &Witnessed{Head: WitnessHead{Size: 3}, LeafIndex: 3, Entry: "{}"}}, gate); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("witnessed leaf outside head: err = %v", err)
	}
}

// TestDomainSeparation: a signature made for one message type never verifies
// as another, even over identical bytes.
func TestDomainSeparation(t *testing.T) {
	gate := newSigner(3)
	tk := token(t, gate, nil)
	unsigned := tk
	unsigned.Sig = ""
	c, _ := Canonical(unsigned)
	for _, d := range []string{"", DomainEpoch, DomainApproval, DomainReset, DomainAction} {
		x := tk
		sig, _ := gate.Sign(append([]byte(d), c...))
		x.Sig = hex.EncodeToString(sig)
		if err := VerifyTokenSig(x, []ed25519.PublicKey{gate.PublicKey()}); err == nil {
			t.Errorf("token signed under domain %q verified", d)
		}
	}
}

func TestEpoch(t *testing.T) {
	gate := newSigner(3)
	pins := []ed25519.PublicKey{gate.PublicKey()}
	e, err := SignEpoch(Epoch{V: 1, Epoch: 4, IssuedAt: FormatTime(t0),
		OpenScopes: []Scope{{ScopeClass, "withdrawal_hot"}}}, gate)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := Canonical(e)
	dec, err := DecodeEpoch(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEpoch(dec, pins); err != nil {
		t.Fatalf("valid epoch refused: %v", err)
	}
	if s, ok := dec.Frozen(baseRequest()); !ok || s.String() != "class:withdrawal_hot" {
		t.Errorf("class scope did not freeze its class: %v %v", s, ok)
	}
	other := baseRequest()
	other.Class = "prod_deploy"
	if _, ok := dec.Frozen(other); ok {
		t.Error("class scope froze another class")
	}
	dec.OpenScopes = []Scope{}
	if _, err := VerifyEpoch(dec, pins); err == nil {
		t.Error("epoch with scopes removed after signing accepted")
	}
	if _, err := VerifyEpoch(Epoch{V: 1, Epoch: 4, IssuedAt: FormatTime(t0), GateKey: e.GateKey, Sig: e.Sig}, pins); err == nil {
		t.Error("epoch with null open_scopes accepted")
	}
	empty, _ := SignEpoch(Epoch{V: 1, Epoch: 5, IssuedAt: FormatTime(t0)}, gate)
	if c, _ := Canonical(empty); !bytes.Contains(c, []byte(`"open_scopes":[]`)) {
		t.Errorf("unset scopes not normalised to []: %s", c)
	}
	for _, s := range []Scope{{"global", "x"}, {"nope", "x"}, {"class", ""}} {
		if s.Validate() == nil {
			t.Errorf("scope %+v accepted", s)
		}
	}
	if !(Scope{Kind: "future_kind"}).Covers(other) {
		t.Error("unknown scope kind must freeze everything")
	}
}

func TestResetQuorum(t *testing.T) {
	a, b, c, m := newSigner(1), newSigner(2), newSigner(4), newSigner(9)
	ops := []Operator{{"alice", a.PublicKey()}, {"bob", b.PublicKey()}, {"carol", c.PublicKey()}}
	r := Reset{V: 1, Scope: Scope{ScopeGlobal, ""}, NewEpoch: 8, Reason: "incident 42 contained",
		Nonce: strings.Repeat("5a", 16), TS: FormatTime(t0)}
	sig := func(s keySigner, label string, r Reset) PartialSig {
		p, err := SignReset(r, label, s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name     string
		partials []PartialSig
		ok       bool
	}{
		{"1 of 3", []PartialSig{sig(a, "alice", r)}, false},
		{"same operator twice", []PartialSig{sig(a, "alice", r), sig(a, "alice", r)}, false},
		{"one real, one forged", []PartialSig{sig(a, "alice", r), sig(m, "bob", r)}, false},
		{"signed a different reset", []PartialSig{sig(a, "alice", r), sig(b, "bob", func() Reset { x := r; x.NewEpoch = 9; return x }())}, false},
		{"2 of 3", []PartialSig{sig(a, "alice", r), sig(c, "carol", r)}, true},
		{"2 of 3 plus junk", []PartialSig{{"bob", "zz"}, sig(a, "alice", r), sig(b, "bob", r)}, true},
	}
	for _, tc := range cases {
		labels, err := VerifyResetQuorum(ResetBundle{Reset: r, Partials: tc.partials}, ops, 2)
		if tc.ok != (err == nil) {
			t.Errorf("%s: labels=%v err=%v, want ok=%v", tc.name, labels, err, tc.ok)
		}
		if !tc.ok && !errors.Is(err, ErrQuorumNotMet) {
			t.Errorf("%s: err %v is not ErrQuorumNotMet", tc.name, err)
		}
	}
	bad := r
	bad.Reason = ""
	if _, err := SignReset(bad, "alice", a); err == nil {
		t.Error("reset without a reason signed")
	}
	if _, err := VerifyResetQuorum(ResetBundle{Reset: r}, ops, 0); err == nil {
		t.Error("quorum of 0 accepted")
	}
}
