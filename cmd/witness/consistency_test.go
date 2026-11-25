package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

type edSigner struct{ priv ed25519.PrivateKey }

func (s edSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }
func (s edSigner) PublicKey() ed25519.PublicKey  { return s.priv.Public().(ed25519.PublicKey) }

// appendAndSaveHead appends n records and copies the signed head to out.
func appendAndSaveHead(t *testing.T, st *store.Store, dir string, n int, out string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.Append("INFO", "e", "src", nil); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "tree-head.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestCmdConsistencyRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg := edSigner{priv}
	pub := hex.EncodeToString(sg.PublicKey())
	logDir, tmp := t.TempDir(), t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	st, err := store.Open(logDir, key, sg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	oldHead, newHead := filepath.Join(tmp, "old.json"), filepath.Join(tmp, "new.json")
	appendAndSaveHead(t, st, logDir, 5, oldHead)
	appendAndSaveHead(t, st, logDir, 6, newHead)

	// Off-host: build the proof from the leaf feed only.
	var feed []byte
	for i := uint64(0); i < st.LeafCount(); i++ {
		l, _ := st.LeafAt(i)
		feed = append(feed, l[:]...)
	}
	leaves := filepath.Join(tmp, "leaves.bin")
	if err := os.WriteFile(leaves, feed, 0644); err != nil {
		t.Fatal(err)
	}
	var proof, errb bytes.Buffer
	if rc := cmdProveConsistency([]string{"--old-size", "5", "--leaves", leaves}, &proof, &errb); rc != 0 {
		t.Fatalf("prove rc=%d: %s", rc, errb.String())
	}
	proofPath := filepath.Join(tmp, "proof.json")
	if err := os.WriteFile(proofPath, proof.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	// A proof against a shorter view of the feed is for a different new head.
	var short bytes.Buffer
	if rc := cmdProveConsistency([]string{"--old-size", "5", "--leaves", leaves, "--new-size", "8"}, &short, &errb); rc != 0 {
		t.Fatalf("prove --new-size rc=%d: %s", rc, errb.String())
	}
	shortPath := filepath.Join(tmp, "short.json")
	_ = os.WriteFile(shortPath, short.Bytes(), 0644)

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := hex.EncodeToString(otherPriv.Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"consistent", []string{"--old", oldHead, "--new", newHead, "--proof", proofPath, "--pubkey", pub}, 0},
		{"heads swapped (rollback)", []string{"--old", newHead, "--new", oldHead, "--proof", proofPath, "--pubkey", pub}, 1},
		{"proof for another head", []string{"--old", oldHead, "--new", newHead, "--proof", shortPath, "--pubkey", pub}, 1},
		{"wrong signer", []string{"--old", oldHead, "--new", newHead, "--proof", proofPath, "--pubkey", otherPub}, 1},
		{"no pubkey", []string{"--old", oldHead, "--new", newHead, "--proof", proofPath}, 2},
		{"missing file", []string{"--old", oldHead + ".x", "--new", newHead, "--proof", proofPath, "--pubkey", pub}, 2},
		{"no args", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, e bytes.Buffer
			if rc := cmdVerifyConsistency(tc.args, &out, &e); rc != tc.want {
				t.Fatalf("rc=%d want %d; stderr %q", rc, tc.want, e.String())
			}
			if tc.want == 0 && !strings.Contains(out.String(), "OK old_size=5 new_size=11") {
				t.Fatalf("stdout %q", out.String())
			}
		})
	}

	for _, bad := range [][]string{
		nil,
		{"--leaves", leaves},
		{"--old-size", "0", "--leaves", leaves},
		{"--old-size", "12", "--leaves", leaves},
		{"--old-size", "5", "--leaves", leaves, "--new-size", "99"},
		{"--old-size", "5", "--new-size", "8"},
	} {
		var out, e bytes.Buffer
		if rc := cmdProveConsistency(bad, &out, &e); rc != 2 {
			t.Fatalf("prove %v: rc=%d, want 2", bad, rc)
		}
	}
}
