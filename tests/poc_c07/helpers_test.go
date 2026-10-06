//go:build poc_c07

// Package poc_c07 self-assesses the Witness against Proof-of-Control 0.1,
// section C07 "Evidence Generation and Properties". See CONFORMANCE_C07.md.
//
// These tests only add files: they import the existing packages and drive the
// real witness binary, and change no Witness source. They are behind the
// poc_c07 build tag because some are gap probes, written to fail while a gap
// is open, and must not turn the repository's normal CI red.
//
//	go test -tags poc_c07 -v ./tests/poc_c07/
//
// Naming: TestC07_<req>_<what> asserts a property the Witness claims and
// should pass. TestC07_<req>_Probe_<what> asserts a property C07 requires
// that the Witness is not expected to have yet; it fails while the gap is
// open, and the failure message is the evidence.
package poc_c07

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// keySigner is an in-memory ed25519 signer satisfying signer.Signer.
type keySigner struct{ priv ed25519.PrivateKey }

func newSigner(t *testing.T) *keySigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &keySigner{priv}
}

func (k *keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k *keySigner) PublicKey() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

func machineKey(t *testing.T) []byte {
	t.Helper()
	k, err := encrypt.DeriveKey("poc-c07-test-machine")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeLog records n events with the real store and returns the directory.
func writeLog(t *testing.T, key []byte, s *keySigner, n int) string {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, key, s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := st.Append("INFO", "action", "gateway", map[string]int{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readEntries(t *testing.T, dir string, key []byte) []store.Entry {
	t.Helper()
	e, err := store.ReadAll(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func readHead(t *testing.T, dir string) store.TreeHead {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "tree-head.json"))
	if err != nil {
		t.Fatal(err)
	}
	var h store.TreeHead
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// ── Attacker toolkit: what someone holding the machine key can do ────────────

// leafHash recomputes a leaf the way the store does (canonical JSON of the entry).
func leafHash(e store.Entry) [32]byte {
	b, _ := json.Marshal(e)
	return merkle.HashLeaf(b)
}

func leaves(entries []store.Entry) [][32]byte {
	out := make([][32]byte, len(entries))
	for i, e := range entries {
		out[i] = leafHash(e)
	}
	return out
}

// rewriteLog replaces witness.log with these entries, encrypted and framed as
// store.Append writes them.
func rewriteLog(t *testing.T, dir string, key []byte, entries []store.Entry) {
	t.Helper()
	var out []byte
	for _, e := range entries {
		plain, _ := json.Marshal(e)
		sealed, err := encrypt.Seal(plain, key)
		if err != nil {
			t.Fatal(err)
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(sealed)))
		out = append(out, sealed...)
	}
	if err := os.WriteFile(filepath.Join(dir, "witness.log"), out, 0600); err != nil {
		t.Fatal(err)
	}
}

// forgeHead writes a fresh, internally valid tree head for the current log:
// MAC with the machine key, signature with s (nil: unsigned).
func forgeHead(t *testing.T, dir string, key []byte, s *keySigner) store.TreeHead {
	t.Helper()
	lv := leaves(readEntries(t, dir, key))
	root := merkle.Root(lv)
	in := sigInput(uint64(len(lv)), root)
	mac := blake3.New(32, key)
	_, _ = mac.Write(in)
	h := store.TreeHead{Size: uint64(len(lv)), Root: hex.EncodeToString(root[:]), MAC: hex.EncodeToString(mac.Sum(nil))}
	if s != nil {
		sig, _ := s.Sign(in)
		h.Signature = hex.EncodeToString(sig)
		h.SignerKey = hex.EncodeToString(s.PublicKey())
	}
	b, _ := json.MarshalIndent(h, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "tree-head.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return h
}

func sigInput(size uint64, root [32]byte) []byte {
	b := binary.BigEndian.AppendUint64(nil, size)
	return append(b, root[:]...)
}

// ── Independent verifier: RFC 6962 written from the RFC, not the Witness code ─

// The T3 question is whether a third party can verify with their own tooling.
// These functions use only BLAKE3 and the RFC 6962 rules, so a test that
// passes with them shows the published structure is checkable independently.

func ivLeaf(data []byte) [32]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func ivNode(l, r [32]byte) [32]byte {
	h := blake3.New(32, nil)
	_, _ = h.Write([]byte{0x01})
	_, _ = h.Write(l[:])
	_, _ = h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ivVerifyInclusion is RFC 9162 §2.1.3.2 (inclusion proof verification).
func ivVerifyInclusion(index, size uint64, leaf [32]byte, path [][32]byte, root [32]byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = ivNode(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = ivNode(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

func decodeRoot(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad root %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
