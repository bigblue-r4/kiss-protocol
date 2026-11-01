package accept

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

const mid = "machine-1"

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// Values seen on the OptiPlex test box on 2026-10-31.
var (
	snapRefresh = drift.Change{Type: "file_changed", Path: "/usr/bin/snap", Old: "2288…", New: "726468b8"}
	ollama      = drift.Change{Type: "new_process", Process: "ollama"}
	shadow      = drift.Change{Type: "file_changed", Path: "/etc/shadow", Old: "2dda…", New: "16e90566"}
)

func policy(op ed25519.PrivateKey, own ed25519.PrivateKey) Policy {
	p := Policy{MachineID: mid, Operators: []soul.AllowlistEntry{{Label: "chris", PubKey: pub(op)}}}
	if own != nil {
		p.Own = pub(own)
	}
	return p
}

func signedAccept(t *testing.T, k ed25519.PrivateKey, changes ...drift.Change) *Request {
	t.Helper()
	r, err := NewAccept(mid, "known change", changes)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(k); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestApprovalPinsTheHash(t *testing.T) {
	op := newKey(t)
	s := NewSet()
	if _, err := s.Apply(signedAccept(t, op, snapRefresh, ollama), policy(op, nil)); err != nil {
		t.Fatal(err)
	}
	// The same snap binary again: approved. A later refresh (new hash): not.
	nextRefresh := snapRefresh
	nextRefresh.New = "ffff0000"
	left, n := s.Filter([]drift.Change{snapRefresh, ollama, shadow, nextRefresh})
	if n != 2 {
		t.Errorf("approved = %d, want 2", n)
	}
	if len(left) != 2 || left[0] != shadow || left[1] != nextRefresh {
		t.Errorf("unapproved = %+v, want shadow + the new snap hash", left)
	}
}

func TestOwnKeyCannotApprove(t *testing.T) {
	op, own := newKey(t), newKey(t)
	p := policy(op, own)
	p.Operators = append(p.Operators, soul.AllowlistEntry{Label: "sneaky", PubKey: pub(own)})
	_, err := NewSet().Apply(signedAccept(t, own, ollama), p)
	if err == nil || !strings.Contains(err.Error(), "own key") {
		t.Fatalf("own key approval: err = %v, want refusal", err)
	}
	p.AllowOwn = true // --dev
	if _, err := NewSet().Apply(signedAccept(t, own, ollama), p); err != nil {
		t.Errorf("own key with --dev: %v", err)
	}
}

func TestRejects(t *testing.T) {
	op, stranger := newKey(t), newKey(t)
	p := policy(op, nil)

	if _, err := NewSet().Apply(signedAccept(t, stranger, ollama), p); err == nil {
		t.Error("untrusted signer accepted")
	}

	unsigned, _ := NewAccept(mid, "x", []drift.Change{ollama})
	if _, err := NewSet().Apply(unsigned, p); err == nil {
		t.Error("unsigned request accepted")
	}

	tampered := signedAccept(t, op, ollama)
	tampered.Changes = append(tampered.Changes, shadow)
	if _, err := NewSet().Apply(tampered, p); err == nil {
		t.Error("request changed after signing accepted")
	}

	other, _ := NewAccept("machine-2", "x", []drift.Change{ollama})
	_ = other.Sign(op)
	if _, err := NewSet().Apply(other, p); err == nil {
		t.Error("request for another machine accepted")
	}

	if _, err := NewAccept(mid, "", []drift.Change{ollama}); err == nil {
		t.Error("request without a reason built")
	}
	if _, err := NewAccept(mid, "x", []drift.Change{{Type: "file_changed", Path: "/etc/x"}}); err == nil {
		t.Error("file approval without a hash built")
	}

	s := NewSet()
	r := signedAccept(t, op, ollama)
	if _, err := s.Apply(r, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(r, p); err == nil {
		t.Error("the same request applied twice")
	}
}

// entry builds the log entry the daemon writes for an applied request.
func entry(t *testing.T, r *Request) store.Entry {
	t.Helper()
	ev, data := EntryFor(r, "chris")
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return store.Entry{Event: ev, Source: Source, Data: raw}
}

func TestReplayRebuildsAndRevokes(t *testing.T) {
	op := newKey(t)
	p := policy(op, nil)
	a1 := signedAccept(t, op, snapRefresh)
	a2 := signedAccept(t, op, ollama)
	rev, err := NewRevoke(mid, "ollama removed", a2.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = rev.Sign(op)

	// A replayed revoke after it: a2 must stay revoked.
	log := []store.Entry{entry(t, a1), entry(t, a2), entry(t, rev), entry(t, a2)}
	s, skipped := Replay(log, p)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the replayed a2)", skipped)
	}
	if got := len(s.Approvals()); got != 1 {
		t.Fatalf("active approvals = %d, want 1", got)
	}
	if _, n := s.Filter([]drift.Change{snapRefresh, ollama}); n != 1 {
		t.Errorf("approved after revoke = %d, want 1 (snap only)", n)
	}
}

func TestReplayIgnoresForgedAndUntrusted(t *testing.T) {
	op, stranger := newKey(t), newKey(t)
	p := policy(op, nil)

	forged := signedAccept(t, stranger, ollama)
	unsigned, _ := NewAccept(mid, "x", []drift.Change{shadow})
	wrongSource := entry(t, signedAccept(t, op, snapRefresh))
	wrongSource.Source = "myfeed" // looks right, but not the witness's own record

	s, skipped := Replay([]store.Entry{entry(t, forged), entry(t, unsigned), wrongSource}, p)
	if len(s.Approvals()) != 0 {
		t.Errorf("forged entries produced %d approvals", len(s.Approvals()))
	}
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2", skipped)
	}

	// An operator removed from operators.txt: their approvals stop applying.
	good := entry(t, signedAccept(t, op, ollama))
	if s, _ := Replay([]store.Entry{good}, Policy{MachineID: mid}); len(s.Approvals()) != 0 {
		t.Error("approval by a no-longer-trusted operator still active")
	}
}

func TestSpoolRoundTrip(t *testing.T) {
	op := newKey(t)
	dir := t.TempDir()
	unsigned, _ := NewAccept(mid, "x", []drift.Change{ollama})
	if _, err := Submit(dir, unsigned); err == nil {
		t.Error("unsigned request spooled")
	}
	r := signedAccept(t, op, ollama)
	if _, err := Submit(dir, r); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(SpoolDir(dir), "junk.json"), []byte("{not json"), 0600)
	_ = os.WriteFile(filepath.Join(SpoolDir(dir), "half.json.tmp"), []byte("{"), 0600)

	pending, err := ReadSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2 (.tmp skipped)", len(pending))
	}
	var ok, bad int
	for _, pr := range pending {
		if pr.Err != nil {
			bad++
			continue
		}
		if _, err := NewSet().Apply(pr.Request, policy(op, nil)); err != nil {
			t.Errorf("spooled request: %v", err)
		}
		ok++
	}
	if ok != 1 || bad != 1 {
		t.Errorf("ok=%d bad=%d, want 1 and 1", ok, bad)
	}
}

func TestKeygenAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.key")
	p, err := Keygen(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(path); err == nil {
		t.Error("keygen overwrote an existing key")
	}
	k, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !pub(k).Equal(p) {
		t.Error("loaded key does not match")
	}
}
