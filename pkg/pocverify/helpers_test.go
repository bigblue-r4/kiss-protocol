package pocverify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// sampleToken builds a valid tree_size-1 token, applies mutations (dotted
// path → value; nil sets JSON null), then signs it with priv.
func sampleToken(t *testing.T, priv ed25519.PrivateKey, verdict string, mut map[string]any) []byte {
	t.Helper()
	d := func(b byte) string { return "sha-256:" + strings.Repeat(hex.EncodeToString([]byte{b}), 32) }
	snap := d(0x5a)
	leaf := LeafHash(strings.TrimPrefix(snap, "sha-256:"), verdict)
	tok := map[string]any{
		"eat_profile": Profile,
		"iat":         1754400000,
		"iss":         "https://verifier.example/poc",
		"nonce":       "n-00000001",
		"poc_claims": map[string]any{
			"agbom_digest": d(1), "agent_id": "did:web:example.org:a", "alg": "EdDSA",
			"canonical_snapshot_hash": snap, "chain_head": d(2), "initiating_user": "user:x",
			"interception_point": "PRE_CALL_TOOL_INVOCATION", "merkle_root": "sha-256:" + hex.EncodeToString(leaf[:]),
			"path_summary_hash": d(3), "policy_bundle_hash": d(4), "reason": "r", "step_index": 0,
			"target_resource": "customers", "tree_size": 1, "verdict": verdict,
		},
		"submods": map[string]any{"attestation": map[string]any{"measurement": d(5), "platform": "SOFTWARE"}},
	}
	for path, val := range mut {
		parts := strings.Split(path, ".")
		obj := tok
		for _, p := range parts[:len(parts)-1] {
			obj = obj[p].(map[string]any)
		}
		obj[parts[len(parts)-1]] = val
	}
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	tok["signature"] = hex.EncodeToString(ed25519.Sign(priv, msg))
	out, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
