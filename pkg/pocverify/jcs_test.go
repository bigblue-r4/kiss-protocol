package pocverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
)

func canon(t *testing.T, in string) string {
	t.Helper()
	v, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("parse %s: %v", in, err)
	}
	b, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// RFC 8785 §3.2.2 / Appendix examples.
func TestCanonicalRFC8785Examples(t *testing.T) {
	for in, want := range map[string]string{
		`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}`: `{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}`,
		`{"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}`:                    `{"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		`{"literals":[null,true,false]}`:                                                `{"literals":[null,true,false]}`,
		`{ "b" : [ ], "a" : { } }`:                                                      `{"a":{},"b":[]}`,
		`[-0, 0.0, 1e21, 1e20, 1e-6, 1e-7, 123e-2, -5e-324]`:                            `[0,0,1e+21,100000000000000000000,0.000001,1e-7,1.23,-5e-324]`,
	} {
		if got := canon(t, in); got != want {
			t.Errorf("%s\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestESNumberSpecialValues(t *testing.T) {
	for f, want := range map[float64]string{
		math.MaxFloat64:             "1.7976931348623157e+308",
		math.SmallestNonzeroFloat64: "5e-324",
		9007199254740992:            "9007199254740992",
		0.1:                         "0.1",
		123456789012345680000:       "123456789012345680000",
	} {
		if got := esNumber(f); got != want {
			t.Errorf("%v: got %s want %s", f, got, want)
		}
	}
}

func TestKeyOrderIsUTF16(t *testing.T) {
	// U+FF00 sorts after U+1F600 by code point but before it by UTF-16 code
	// unit (0xD83D < 0xFF00).
	got := canon(t, `{"＀":1,"😀":2,"a":3}`)
	if want := `{"a":3,"😀":2,"＀":1}`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestParserStrictness(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`, `{"a":{"b":1,"b":1}}`, `[{"x":1,"x":1}]`,
	} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("%s: %v, want duplicate key", in, err)
		}
	}
	for _, in := range []string{
		``, `{`, `{"a"}`, `{"a":1,}`, `[1,]`, `01`, `1.`, `.5`, `1e`, `+1`, `"\x"`, `"\ud800"`,
		`"\udc00"`, `"\ud800A"`, "\"a\x01\"", `{"a":1} x`, `NaN`, `1e400`, "\xef\xbb\xbf{}", "\"\xff\"",
		strings.Repeat("[", 100) + strings.Repeat("]", 100),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// A token that canonicalizes identically verifies however it is formatted.
func TestSignatureCoversCanonicalForm(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	priv := ed25519.NewKeyFromSeed(seed)
	keys := []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}
	tok := sampleToken(t, priv, "ALLOW", nil)
	if r := Verify(tok, keys); !r.OK() {
		t.Fatalf("%s: %s", r.Code, r.Detail)
	}
	pretty := strings.ReplaceAll(string(tok), ",", ",\n   ")
	if r := Verify([]byte(pretty), keys); !r.OK() {
		t.Fatalf("pretty-printed: %s: %s", r.Code, r.Detail)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	if r := Verify(tok, []ed25519.PublicKey{other.Public().(ed25519.PublicKey)}); r.Code != CodeSignature {
		t.Fatalf("wrong key: %q", r.Code)
	}
	if r := Verify(tok, nil); r.Code != CodeSignature {
		t.Fatalf("no key: %q", r.Code)
	}
}

func TestVerifyRejectionCodes(t *testing.T) {
	seed := make([]byte, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	keys := []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}
	for _, tc := range []struct {
		name string
		mut  map[string]any
		code string
	}{
		{"valid", nil, ""},
		{"ES256 not checkable", map[string]any{"poc_claims.alg": "ES256"}, CodeUnsupportedAlg},
		{"empty reason", map[string]any{"poc_claims.reason": ""}, CodeSchema},
		{"null optional", map[string]any{"poc_claims.dispatched_snapshot_hash": nil}, CodeSchema},
		{"negative step", map[string]any{"poc_claims.step_index": -1}, CodeSchema},
		{"tree size 0", map[string]any{"poc_claims.tree_size": 0}, CodeSchema},
		{"short nonce", map[string]any{"nonce": "n-1"}, CodeSchema},
		{"iss not a URI", map[string]any{"iss": "verifier"}, CodeSchema},
		{"unknown platform", map[string]any{"submods.attestation.platform": "TPM"}, CodeSchema},
		{"sha-384 width ok", map[string]any{"poc_claims.agbom_digest": "sha-384:" + strings.Repeat("ab", 48)}, ""},
		{"uppercase hex in extension array", map[string]any{"ext": []any{"sha3-256:" + strings.Repeat("AB", 32)}}, CodeHexCase},
		{"float in extension", map[string]any{"ext": 1.5}, CodeFloat},
		{"tree too big for root", map[string]any{"poc_claims.tree_size": 2}, ""},
		{"leaf not bound", map[string]any{"poc_claims.merkle_root": "sha-256:" + strings.Repeat("00", 32)}, CodeLeafRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Verify(sampleToken(t, priv, "ALLOW", tc.mut), keys)
			if r.Code != tc.code {
				t.Fatalf("got %q (%s), want %q", r.Code, r.Detail, tc.code)
			}
		})
	}
}

func TestLeafHashMatchesSpecFormula(t *testing.T) {
	// canonical({"snapshot":"ab","verdict":"DENY"}) with the 0x00 prefix.
	want := sha256.Sum256([]byte("\x00" + `{"snapshot":"ab","verdict":"DENY"}`))
	if LeafHash("ab", "DENY") != want {
		t.Fatal("leaf formula")
	}
}
