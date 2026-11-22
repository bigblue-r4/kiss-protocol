package accept

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

func TestProcessApprovalNameAndOptionalPath(t *testing.T) {
	op := newKey(t)
	pinned := drift.Change{Type: "new_process", Process: "pipelock", Path: "/opt/pipelock"}
	other := pinned
	other.Path = "/tmp/pipelock"
	unknown := pinned
	unknown.Path = ""
	renamed := pinned
	renamed.Process = "different"
	deleted := pinned
	deleted.Path += " (deleted)"
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("name_only_%t", legacy), func(t *testing.T) {
			approval := pinned
			if legacy {
				approval.Path = ""
			}
			req := signedAccept(t, op, approval)
			// Replay exercises signature verification and durable log reconstruction.
			s, skipped := Replay([]store.Entry{entry(t, req)}, policy(op, nil))
			if skipped != 0 {
				t.Fatalf("skipped %d", skipped)
			}
			left, n := s.Filter([]drift.Change{pinned, other, unknown, renamed, deleted})
			if legacy {
				if n != 4 || len(left) != 1 || left[0] != renamed {
					t.Fatalf("legacy mismatch: %d %+v", n, left)
				}
			} else {
				if n != 1 || len(left) != 4 || left[0] != other {
					t.Fatalf("path pin hides drift: %d %+v", n, left)
				}
			}
		})
	}
}

func TestLegacyNameOnlySignedJSONStillLoadsAndVerifies(t *testing.T) {
	// Independently encode the pre-path-pin v1 wire format, including field order.
	// This fixture is signed before loading it through the current Request type.
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	signer := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	payload := []byte(fmt.Sprintf(`{"v":1,"kind":"accept","id":"legacy-process","machine_id":"machine-1","created":"2026-11-01T00:00:00Z","reason":"old approval","changes":[{"type":"new_process","process":"pipelock"}],"signer":"%s"}`, signer))
	sig := hex.EncodeToString(ed25519.Sign(key, payload))
	wire := append(append([]byte{}, payload[:len(payload)-1]...), []byte(fmt.Sprintf(`,"sig":"%s"}`, sig))...)
	file := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(file, wire, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := r.payload()
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(payload) {
		t.Fatalf("legacy signed payload changed: %s", actual)
	}
	s := NewSet()
	if _, err := s.Apply(r, Policy{MachineID: mid, Operators: []soul.AllowlistEntry{{Label: "fixture", PubKey: key.Public().(ed25519.PublicKey)}}}); err != nil {
		t.Fatal(err)
	}
	left, n := s.Filter([]drift.Change{{Type: "new_process", Process: "pipelock", Path: "/opt/pipelock"}})
	if n != 1 || len(left) != 0 {
		t.Fatalf("legacy approval not applied: %d %+v", n, left)
	}
	// A path addition is covered by the signature, not an unsigned narrowing hint.
	r.Changes[0].Path = "/tmp/pipelock"
	if err := r.verifySig(); err == nil {
		t.Fatal("unsigned executable path accepted")
	}
}

func TestPinnedProcessPathSignedAndAbsolute(t *testing.T) {
	if _, err := NewAccept(mid, "test", []drift.Change{{Type: "new_process", Process: "pipelock", Path: "relative/pipelock"}}); err == nil {
		t.Fatal("relative executable pin accepted")
	}
	op := newKey(t)
	r := signedAccept(t, op, drift.Change{Type: "new_process", Process: "pipelock", Path: "/opt/pipelock"})
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Request
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if err := loaded.verifySig(); err != nil {
		t.Fatal(err)
	}
	loaded.Changes[0].Path = "/tmp/pipelock"
	if err := loaded.verifySig(); err == nil {
		t.Fatal("changed path signature verified")
	}
}
