package rekor_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor/rekortest"
)

func load(t *testing.T) (string, json.RawMessage) { t.Helper(); return loadF(t) }

func loadF(t testing.TB) (string, json.RawMessage) {
	t.Helper()
	b, err := os.ReadFile("testdata/public-entry-4132600001.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		return k, v
	}
	t.Fatal("empty fixture")
	return "", nil
}

func publicKey(t *testing.T) []byte { return pubF(t) }

func pubF(t testing.TB) []byte {
	b, err := os.ReadFile("testdata/rekor.sigstore.dev.pub")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The offline checks agree with what the public Sigstore Rekor returns.
func TestVerifyEntryAgainstPublicRekor(t *testing.T) {
	k, err := rekor.ParsePublicKey(publicKey(t))
	if err != nil {
		t.Fatal(err)
	}
	uuid, raw := load(t)
	_, body, res, err := rekor.VerifyEntry(uuid, raw, k)
	if err != nil {
		t.Fatalf("real entry rejected: %v", err)
	}
	if res.LogIndex != 4132600001 || res.TreeID != "1193050959916656506" || res.IntegratedTime <= 0 {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(string(body), `"kind":"hashedrekord"`) {
		t.Fatal("body not decoded")
	}

	// Every field Rekor signs or proves is load-bearing.
	var e map[string]any
	_ = json.Unmarshal(raw, &e)
	mut := func(name string, f func(m map[string]any), wantUUID string) {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			f(m)
			b, _ := json.Marshal(m)
			u := uuid
			if wantUUID != "" {
				u = wantUUID
			}
			if _, _, _, err := rekor.VerifyEntry(u, b, k); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ver := func(m map[string]any) map[string]any { return m["verification"].(map[string]any) }
	ip := func(m map[string]any) map[string]any { return ver(m)["inclusionProof"].(map[string]any) }
	mut("integratedTime", func(m map[string]any) { m["integratedTime"] = m["integratedTime"].(float64) + 1 }, "")
	mut("logIndex", func(m map[string]any) { m["logIndex"] = m["logIndex"].(float64) + 1 }, "")
	mut("body", func(m map[string]any) {
		b, _ := base64.StdEncoding.DecodeString(m["body"].(string))
		b[len(b)-3] ^= 1
		m["body"] = base64.StdEncoding.EncodeToString(b)
	}, "")
	mut("set", func(m map[string]any) {
		b, _ := base64.StdEncoding.DecodeString(ver(m)["signedEntryTimestamp"].(string))
		b[len(b)-1] ^= 1
		ver(m)["signedEntryTimestamp"] = base64.StdEncoding.EncodeToString(b)
	}, "")
	mut("proof hash", func(m map[string]any) {
		h := ip(m)["hashes"].([]any)
		s := []byte(h[0].(string))
		s[0] ^= 1
		h[0] = string(s)
	}, "")
	mut("proof index", func(m map[string]any) { ip(m)["logIndex"] = ip(m)["logIndex"].(float64) + 1 }, "")
	mut("checkpoint", func(m map[string]any) {
		lines := strings.SplitN(ip(m)["checkpoint"].(string), "\n", 3)
		lines[1] += "0"
		ip(m)["checkpoint"] = strings.Join(lines, "\n")
	}, "")
	mut("checkpoint signature", func(m map[string]any) {
		c := ip(m)["checkpoint"].(string)
		i := strings.LastIndex(c, " ")
		b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(c[i+1:]))
		b[len(b)-1] ^= 1
		ip(m)["checkpoint"] = c[:i+1] + base64.StdEncoding.EncodeToString(b) + "\n"
	}, "")
	mut("uuid", func(m map[string]any) {}, uuid[:len(uuid)-1]+"0")
	mut("logID", func(m map[string]any) { m["logID"] = strings.Repeat("0", 64) }, "")

	// A different pinned key rejects it.
	other := rekortest.New()
	if _, _, _, err := rekor.VerifyEntry(uuid, raw, other.Public()); err == nil {
		t.Fatal("accepted under another log key")
	}
}

func TestUploadAndVerifyAnchor(t *testing.T) {
	srv := rekortest.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()
	priv, pub, err := rekor.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := rekor.ParsePrivateKey(priv)
	akey, _ := rekor.ParsePublicKey(pub)
	body := []byte("example.org/log\n5\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	d := rekor.Digest(body)
	ctx := context.Background()
	for range 3 { // a second identical upload is a 409, answered with the same entry
		uuid, raw, err := rekor.Upload(ctx, ts.Client(), ts.URL, d, key)
		if err != nil {
			t.Fatal(err)
		}
		a := rekor.Anchor{Format: rekor.AnchorFormat, Size: 5, Rekor: ts.URL, UUID: uuid, Entry: raw}
		if _, err := rekor.VerifyAnchor(a, d, srv.Public(), akey); err != nil {
			t.Fatal(err)
		}
		if _, err := rekor.VerifyAnchor(a, rekor.Digest([]byte("x")), srv.Public(), akey); err == nil {
			t.Fatal("anchor accepted for another checkpoint")
		}
		_, opub, _ := rekor.GenerateKey()
		ok, _ := rekor.ParsePublicKey(opub)
		if _, err := rekor.VerifyAnchor(a, d, srv.Public(), ok); err == nil {
			t.Fatal("anchor accepted under another anchoring key")
		}
	}
	srv.Down = true
	if _, _, err := rekor.Upload(ctx, ts.Client(), ts.URL, d, key); err == nil {
		t.Fatal("upload to a down server succeeded")
	}
}
