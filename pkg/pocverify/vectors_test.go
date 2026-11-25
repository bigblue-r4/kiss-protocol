package pocverify

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectorDir = "testdata/upstream-54a7bc6"

type manifest struct {
	PublicKey string `json:"public_key"`
	Positive  []struct {
		File string `json:"file"`
	} `json:"positive"`
	Negative []struct {
		File       string `json:"file"`
		ExpectCode string `json:"expect_code"`
	} `json:"negative"`
	Canonical []struct {
		File   string `json:"file"`
		SHA256 string `json:"canonical_sha256"`
	} `json:"canonical"`
}

// knownDisagreements are positive upstream vectors this verifier rejects on
// purpose, with the upstream issue that explains why.
var knownDisagreements = map[string]string{
	// Upstream #170: verdict MODIFY, tree_size 1, but merkle_root is the leaf
	// of verdict ALLOW. The upstream validator does not check leaf-to-root
	// binding and accepts it; PR #169 regenerates the vector.
	"positive/modify-bound.json": CodeLeafRoot,
}

func loadManifest(t *testing.T) (manifest, []ed25519.PublicKey) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	k, err := hex.DecodeString(m.PublicKey)
	if err != nil || len(k) != ed25519.PublicKeySize {
		t.Fatal("manifest public key")
	}
	return m, []ed25519.PublicKey{k}
}

func read(t *testing.T, f string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, f))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUpstreamVectors(t *testing.T) {
	m, keys := loadManifest(t)
	if got := len(m.Positive) + len(m.Negative) + len(m.Canonical); got != 17 {
		t.Fatalf("manifest lists %d vectors, want 17 at 54a7bc6", got)
	}
	agree := 0
	for _, v := range m.Positive {
		t.Run(v.File, func(t *testing.T) {
			r := Verify(read(t, v.File), keys)
			if want, ok := knownDisagreements[v.File]; ok {
				if r.Code != want {
					t.Fatalf("known disagreement changed: got %q (%s), want %q", r.Code, r.Detail, want)
				}
				t.Logf("expected disagreement with upstream: %s: %s", r.Code, r.Detail)
				return
			}
			if !r.OK() {
				t.Fatalf("rejected positive vector: %s: %s", r.Code, r.Detail)
			}
			agree++
		})
	}
	for _, v := range m.Negative {
		t.Run(v.File, func(t *testing.T) {
			r := Verify(read(t, v.File), keys)
			if r.Code != v.ExpectCode {
				t.Fatalf("rejected for %q (%s), manifest says %q: the wrong reason is not a pass", r.Code, r.Detail, v.ExpectCode)
			}
			agree++
		})
	}
	for _, v := range m.Canonical {
		t.Run(v.File, func(t *testing.T) {
			val, err := Parse(read(t, v.File))
			if err != nil {
				t.Fatal(err)
			}
			c, err := Canonical(val)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256.Sum256(c); hex.EncodeToString(got[:]) != v.SHA256 {
				t.Fatalf("canonical bytes differ: %s", c)
			}
			agree++
		})
	}
	t.Logf("%d/17 agree with the manifest; %d known disagreement(s)", agree, len(knownDisagreements))
}

func TestVendoredVectorsUnchanged(t *testing.T) {
	f, err := os.Open(filepath.Join(vectorDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("bad line %q", sc.Text())
		}
		got := sha256.Sum256(read(t, name))
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s differs from the upstream copy", name)
		}
		n++
	}
	if n != 18 {
		t.Fatalf("%d files listed, want 18", n)
	}
}
