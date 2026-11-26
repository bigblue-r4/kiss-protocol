package checkpoint_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/testwitness"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
	"golang.org/x/mod/sumdb/note"
)

func logKey(t *testing.T, origin string) (note.Signer, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s, vkey
}

func leaves(n int) []tlog.Hash {
	var l []tlog.Hash
	for i := 0; i < n; i++ {
		l = append(l, tlog.HashLeaf([]byte{byte(i), byte(i >> 8)}))
	}
	return l
}

func TestRoundTripAndXModInterop(t *testing.T) {
	signer, vkey := logKey(t, "pilot.example/log")
	l := leaves(9)
	c := checkpoint.Checkpoint{Origin: "pilot.example/log", Size: 9, Root: tlog.Root(l)}
	raw, err := checkpoint.SignLog(c, signer)
	if err != nil {
		t.Fatal(err)
	}
	w := testwitness.New("pilot.example/witness")
	cos := checkpoint.Cosign(w.Name, w.PrivateKey(), c.Text(), 1679315147)
	raw = append(raw, cos.String()...)

	s, err := checkpoint.Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Checkpoint.Size != 9 || s.Checkpoint.Root != c.Root || s.Checkpoint.Origin != c.Origin {
		t.Fatal("round trip changed the checkpoint")
	}
	if err := s.VerifyLog(vkey); err != nil {
		t.Fatal(err)
	}
	r := s.Cosignatures([]checkpoint.CosignerKey{w.Key()})
	if !r[0].Valid || r[0].Timestamp != 1679315147 {
		t.Fatalf("cosignature: %+v", r[0])
	}
	// The Go checksum database's note parser accepts the note and its log
	// signature, and ignores the cosignature as an unknown key.
	v, _ := note.NewVerifier(vkey)
	n, err := note.Open(raw, note.VerifierList(v))
	if err != nil {
		t.Fatalf("x/mod note.Open: %v", err)
	}
	if len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 1 {
		t.Fatalf("x/mod saw %d verified, %d unverified", len(n.Sigs), len(n.UnverifiedSigs))
	}
	// Key round trip.
	k, err := checkpoint.ParseCosignerKey(w.Key().String())
	if err != nil || k.ID != w.Key().ID {
		t.Fatalf("cosigner key round trip: %v", err)
	}
}

func TestSpecCosignerKeyExample(t *testing.T) {
	// A key printed by transparency-dev/witness cmd/generate_keys.
	if _, err := checkpoint.ParseCosignerKey("pilot.example/witness-a+4b0e43ac+BGgNmpL+Fhf97lH7XJWsqUu6EAv2BxKjm+pFz0yAfomd"); err != nil {
		t.Fatal(err)
	}
	if _, err := checkpoint.ParseCosignerKey("pilot.example/witness-a+4b0e43ad+BGgNmpL+Fhf97lH7XJWsqUu6EAv2BxKjm+pFz0yAfomd"); err == nil {
		t.Fatal("wrong key ID accepted")
	}
}

func TestTamperRejected(t *testing.T) {
	signer, vkey := logKey(t, "pilot.example/log")
	c := checkpoint.Checkpoint{Origin: "pilot.example/log", Size: 3, Root: tlog.Root(leaves(3))}
	raw, _ := checkpoint.SignLog(c, signer)
	w := testwitness.New("pilot.example/witness")
	raw = append(raw, checkpoint.Cosign(w.Name, w.PrivateKey(), c.Text(), 100).String()...)

	// Change the size line: log and cosignature both fail.
	bad := []byte(strings.Replace(string(raw), "\n3\n", "\n4\n", 1))
	s, err := checkpoint.Open(bad)
	if err != nil {
		t.Fatal(err)
	}
	if s.VerifyLog(vkey) == nil {
		t.Fatal("modified size accepted by log signature")
	}
	if s.Cosignatures([]checkpoint.CosignerKey{w.Key()})[0].Valid {
		t.Fatal("modified size accepted by cosignature")
	}
	// Wrong pinned log key.
	_, other := logKey(t, "pilot.example/log")
	s, _ = checkpoint.Open(raw)
	if s.VerifyLog(other) == nil {
		t.Fatal("wrong pinned key accepted")
	}
	// A cosignature from a different key under the witness's name is not
	// counted for the pinned witness.
	forger := testwitness.New("pilot.example/witness")
	s, _ = checkpoint.Open(append(append([]byte(nil), raw[:len(raw)-len(checkpoint.Cosign(w.Name, w.PrivateKey(), c.Text(), 100).String())]...), checkpoint.Cosign(forger.Name, forger.PrivateKey(), c.Text(), 100).String()...))
	if r := s.Cosignatures([]checkpoint.CosignerKey{w.Key()}); r[0].Present || r[0].Valid {
		t.Fatalf("forged cosignature counted: %+v", r[0])
	}
	// Forged signature bytes under the right key ID.
	line := checkpoint.Cosign(w.Name, w.PrivateKey(), c.Text(), 100)
	line.Payload[20] ^= 1
	s, _ = checkpoint.Open(append(raw[:len(raw)-len(line.String())], line.String()...))
	if r := s.Cosignatures([]checkpoint.CosignerKey{w.Key()}); !r[0].Present || r[0].Valid {
		t.Fatalf("corrupted cosignature: %+v", r[0])
	}
	// Changed timestamp fails (the time is signed).
	line = checkpoint.Cosign(w.Name, w.PrivateKey(), c.Text(), 100)
	line.Payload[7] = 101
	s, _ = checkpoint.Open(append(raw[:len(raw)-len(line.String())], line.String()...))
	if r := s.Cosignatures([]checkpoint.CosignerKey{w.Key()}); r[0].Valid {
		t.Fatal("changed timestamp accepted")
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		"o\n1\nAAAA\n",
		"o\n01\n" + strings.Repeat("A", 43) + "=\n\n— o AAAAAAAA\n",
		"o\n1\n" + strings.Repeat("A", 43) + "=\n\n— o AAAAAAAA",
		"o p\n1\n" + strings.Repeat("A", 43) + "=\n\n— o AAAAAAAA\n",
		"o\n1\n" + strings.Repeat("A", 43) + "=\n\n— o AAAAAAAA\n— o AAAAAAAA\n",
		"o\n1\n" + strings.Repeat("A", 43) + "=\n\n- o AAAAAAAA\n",
		"o\r\n1\n" + strings.Repeat("A", 43) + "=\n\n— o AAAAAAAA\n",
	} {
		if _, err := checkpoint.Open([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestWitnessClientProtocol(t *testing.T) {
	signer, vkey := logKey(t, "pilot.example/log")
	w := testwitness.New("pilot.example/witness")
	w.AddLog("pilot.example/log", vkey)
	srv := httptest.NewServer(w)
	defer srv.Close()
	ctx := context.Background()
	all := leaves(40)

	submit := func(old uint64, n int, leafs []tlog.Hash) ([]checkpoint.SigLine, error) {
		c := checkpoint.Checkpoint{Origin: "pilot.example/log", Size: uint64(n), Root: tlog.Root(leafs[:n])}
		raw, _ := checkpoint.SignLog(c, signer)
		p, _ := tlog.ProveConsistency(leafs[:n], old)
		return checkpoint.AddCheckpoint(ctx, srv.Client(), srv.URL, old, p, raw)
	}
	if _, err := submit(0, 10, all); err != nil {
		t.Fatal(err)
	}
	if _, err := submit(10, 25, all); err != nil {
		t.Fatal(err)
	}
	var ce *checkpoint.ConflictError
	if _, err := submit(10, 30, all); !errors.As(err, &ce) || ce.Size != 25 {
		t.Fatalf("want 409 with size 25, got %v", err)
	}
	// A rewritten history: the operator changes leaf 5 and re-signs.
	forked := append([]tlog.Hash(nil), all...)
	forked[5] = tlog.HashLeaf([]byte("rewritten"))
	var we *checkpoint.WitnessError
	if _, err := submit(25, 30, forked); !errors.As(err, &we) || we.Status != http.StatusUnprocessableEntity {
		t.Fatalf("rewrite: want 422, got %v", err)
	}
	if w.Held("pilot.example/log") != 25 {
		t.Fatal("witness advanced on a rejected checkpoint")
	}
	// A key the witness does not trust.
	other, _ := logKey(t, "pilot.example/log")
	c := checkpoint.Checkpoint{Origin: "pilot.example/log", Size: 30, Root: tlog.Root(all[:30])}
	raw, _ := checkpoint.SignLog(c, other)
	p, _ := tlog.ProveConsistency(all[:30], 25)
	if _, err := checkpoint.AddCheckpoint(ctx, srv.Client(), srv.URL, 25, p, raw); !errors.As(err, &we) || we.Status != http.StatusForbidden {
		t.Fatalf("untrusted key: want 403, got %v", err)
	}
	lines, err := submit(25, 40, all)
	if err != nil {
		t.Fatal(err)
	}
	c = checkpoint.Checkpoint{Origin: "pilot.example/log", Size: 40, Root: tlog.Root(all)}
	raw, _ = checkpoint.SignLog(c, signer)
	for _, l := range lines {
		raw = append(raw, l.String()...)
	}
	s, _ := checkpoint.Open(raw)
	if r := s.Cosignatures([]checkpoint.CosignerKey{w.Key()}); !r[0].Valid {
		t.Fatalf("returned cosignature: %+v", r[0])
	}
	_ = ed25519.PublicKey(nil)
}
