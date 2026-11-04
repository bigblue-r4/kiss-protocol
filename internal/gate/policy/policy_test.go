package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func newSigner(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(append(make([]byte, 31), seed))}
}

func ops(n int) ([]proto.Operator, []keySigner) {
	var o []proto.Operator
	var s []keySigner
	for i := 0; i < n; i++ {
		k := newSigner(byte(i + 1))
		s = append(s, k)
		o = append(o, proto.Operator{Label: "op" + string(rune('a'+i)), Key: k.PublicKey()})
	}
	return o, s
}

func example(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../../../examples/gate-policy.toml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExampleLoads(t *testing.T) {
	o, s := ops(3)
	data := example(t)
	sig, err := Sign(data, s[0])
	if err != nil {
		t.Fatal(err)
	}
	l, err := LoadBytes(data, sig, o)
	if err != nil {
		t.Fatal(err)
	}
	if l.SignedBy != "opa" || l.Hash != Hash(data) {
		t.Fatalf("loaded %+v", l)
	}
	p := l.Policy
	for _, c := range []string{"withdrawal_manual", "withdrawal_hot"} {
		if got := p.Classes[c].ApprovalsRequired; got != 2 {
			t.Errorf("%s approvals_required = %d, want 2", c, got)
		}
	}
	if p.Classes["bulk_export"].ApprovalsRequired != DefaultApprovals || DefaultApprovals != 2 {
		t.Error("unset approvals_required must default to 2")
	}
	if p.Classes["withdrawal_hot"].Inflight != (Inflight{8, 2, 4}) {
		t.Errorf("high-tier inflight defaults: %+v", p.Classes["withdrawal_hot"].Inflight)
	}
	if p.Classes["bulk_export"].Tighten.Drift != ActionDeny || p.Classes["bulk_export"].Tighten.SBH != ActionEscal {
		t.Errorf("tighten defaults: %+v", p.Classes["bulk_export"].Tighten)
	}
}

func TestSignatureFailures(t *testing.T) {
	o, s := ops(3)
	data := example(t)
	good, _ := Sign(data, s[1])
	outsider, _ := Sign(data, newSigner(99))
	// A soul-style signature: same envelope, raw bytes, no domain prefix (C12).
	raw := ed25519.Sign(s[0].priv, data)
	soulStyle := []byte(`{"algorithm":"ed25519","signer_key":"` + hex.EncodeToString(s[0].PublicKey()) +
		`","signature":"` + hex.EncodeToString(raw) + `","signed_at":"2026-11-03T00:00:00Z"}`)
	tampered := append([]byte(nil), data...)
	tampered = []byte(strings.Replace(string(tampered), `max_value = "25000"`, `max_value = "2500000"`, 1))

	for name, tc := range map[string]struct{ data, sig []byte }{
		"tampered":      {tampered, good},
		"outsider key":  {data, outsider},
		"soul-style":    {data, soulStyle},
		"empty sig":     {data, nil},
		"garbage sig":   {data, []byte("{")},
		"unknown field": {data, []byte(`{"algorithm":"ed25519","x":1}`)},
	} {
		if _, err := LoadBytes(tc.data, tc.sig, o); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := LoadBytes(data, good, o); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestLoadFromDisk(t *testing.T) {
	o, s := ops(2)
	dir := t.TempDir()
	path := filepath.Join(dir, "gate-policy.toml")
	data := example(t)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, o); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("unsigned: %v", err)
	}
	sig, _ := Sign(data, s[0])
	if err := os.WriteFile(SigPath(path), sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, o); err != nil {
		t.Fatal(err)
	}
	opsPath := filepath.Join(dir, "operators.txt")
	os.WriteFile(opsPath, []byte("# c\nopa "+hex.EncodeToString(s[0].PublicKey())+"\nopb "+hex.EncodeToString(s[1].PublicKey())+"\n"), 0o600)
	got, err := LoadOperators(opsPath)
	if err != nil || len(got) != 2 || got[1].Label != "opb" {
		t.Fatalf("LoadOperators = %v, %v", got, err)
	}
}

func TestQuorumAndApprovalsMustBeSatisfiable(t *testing.T) {
	_, s := ops(1)
	one := []proto.Operator{{Label: "solo", Key: s[0].PublicKey()}, {Label: "alias", Key: s[0].PublicKey()}}
	data := example(t)
	sig, _ := Sign(data, s[0])
	_, err := LoadBytes(data, sig, one)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "operator keys") {
		t.Fatalf("two labels for one key must count once: %v", err)
	}
}

const minimal = `
version = 1
[global]
witness_keys = ["` + "1111111111111111111111111111111111111111111111111111111111111111" + `"]
witness_drift_interval_sec = 30
reset_quorum = 1
[classes.c]
tier = "high"
root = "approval"
targets = ["svc"]
`

func TestValidation(t *testing.T) {
	if _, err := Parse([]byte(minimal)); err != nil {
		t.Fatalf("minimal: %v", err)
	}
	for name, tc := range map[string]struct{ old, new string }{
		"unknown key":          {`reset_quorum = 1`, "reset_quorum = 1\nreset_quorom = 2"},
		"version":              {`version = 1`, `version = 2`},
		"no witness key":       {`witness_keys = ["1111111111111111111111111111111111111111111111111111111111111111"]`, `witness_keys = []`},
		"bad witness key":      {`["1111`, `["zz11`},
		"drift too slow":       {`witness_drift_interval_sec = 30`, `witness_drift_interval_sec = 31`},
		"no drift interval":    {`witness_drift_interval_sec = 30`, ``},
		"quorum 0":             {`reset_quorum = 1`, `reset_quorum = 0`},
		"bad tier":             {`tier = "high"`, `tier = "medium"`},
		"bad root":             {`root = "approval"`, `root = "vibes"`},
		"high fail open":       {`tier = "high"`, "tier = \"high\"\nfail_mode = \"open\""},
		"no targets":           {`targets = ["svc"]`, ``},
		"lifetime over max":    {`targets = ["svc"]`, "targets = [\"svc\"]\ntoken_lifetime = \"121s\""},
		"undeclared asset":     {`targets = ["svc"]`, "targets = [\"svc\"]\nassets = [\"BTC\"]"},
		"bad action":           {`targets = ["svc"]`, "targets = [\"svc\"]\ntighten = { drift = \"allow\" }"},
		"bad edge mode":        {`targets = ["svc"]`, "targets = [\"svc\"]\ntighten = { edge_mode = \"guess\" }"},
		"limit without window": {`targets = ["svc"]`, "targets = [\"svc\"]\nbudget = { max_count = 3 }"},
		"float value":          {`targets = ["svc"]`, "targets = [\"svc\"]\nmax_value = \"1e6\""},
		"automated no dests":   {`root = "approval"`, `root = "automated_envelope"`},
		"automated any dest":   {`root = "approval"`, "root = \"automated_envelope\"\ndestinations = [\"*\"]"},
		"unknown trigger":      {`targets = ["svc"]`, "targets = [\"svc\"]\n[breaker.triggers]\nvibes = 1"},
		"chain below halt":     {`targets = ["svc"]`, "targets = [\"svc\"]\n[breaker.triggers]\nchain_unverified = 9"},
		"thresholds unordered": {`targets = ["svc"]`, "targets = [\"svc\"]\n[breaker]\nwarn_at = 5\nescalate_at = 4\nhalt_at = 10"},
		"negative duration":    {`witness_drift_interval_sec = 30`, "witness_drift_interval_sec = 30\nhead_max_age = \"-60s\""},
	} {
		src := strings.Replace(minimal, tc.old, tc.new, 1)
		if src == minimal {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := Parse([]byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestAutomatedValueClassNeedsBudgets(t *testing.T) {
	src := minimal + `
[assets.BTC]
decimals = 8
ref_value = "60000"
[classes.hot]
tier = "high"
root = "automated_envelope"
targets = ["svc"]
assets = ["BTC"]
destinations = ["addr"]
max_value = "100"
budget = { window = "1h", max_value = "1000" }
`
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "global budget") {
		t.Fatalf("missing global budget: %v", err)
	}
	src = strings.Replace(src, "reset_quorum = 1", "reset_quorum = 1\nbudget = { window = \"1h\", max_value = \"5000\" }", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
}

func TestValueIsExact(t *testing.T) {
	o, s := ops(2)
	data := example(t)
	sig, _ := Sign(data, s[0])
	l, err := LoadBytes(data, sig, o)
	if err != nil {
		t.Fatal(err)
	}
	units, ref, err := l.Policy.Value("ETH", "0.000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if units.Cmp(big.NewRat(1, 1e18)) != 0 || ref.Cmp(big.NewRat(3000, 1e18)) != 0 {
		t.Fatalf("units %s ref %s", units, ref)
	}
	if _, _, err := l.Policy.Value("BTC", "0.000000001"); err == nil {
		t.Error("more decimals than the asset has must be refused, not rounded")
	}
	if _, _, err := l.Policy.Value("DOGE", "1"); err == nil {
		t.Error("undeclared asset must be refused")
	}
	if _, _, err := l.Policy.Value("", "1"); err == nil {
		t.Error("value without an asset must be refused")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal))
	if b, err := os.ReadFile("../../../examples/gate-policy.toml"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error not wrapped in ErrInvalid: %v", err)
			}
			return
		}
		// Anything that parses must satisfy the invariants the core relies on.
		if len(p.WitnessKeys()) == 0 || p.Global.ResetQuorum < 1 || p.Breaker.HaltAt < 1 {
			t.Fatalf("accepted policy breaks invariants: %+v", p.Global)
		}
		for name, c := range p.Classes {
			if c.ApprovalsRequired < 1 || c.Tier == TierHigh && c.FailMode != FailClosed ||
				c.TokenLifetime.Duration <= 0 || c.TokenLifetime.Duration > proto.MaxTokenLifetime {
				t.Fatalf("class %s breaks invariants: %+v", name, c)
			}
			if c.Root == RootAutomated && (len(c.Destinations) == 0 || c.AllowsDestination("\x00not-listed")) {
				t.Fatalf("automated class %s has an open envelope", name)
			}
		}
	})
}
