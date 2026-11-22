package genesis

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/hashutil"
)

// This is the independently defined pre-process-identities snapshot wire type.
// Adding a field to Snapshot must not rewrite an existing genesis hash.
func TestPreProcessIdentitySnapshotHashUnchanged(t *testing.T) {
	type legacySnapshot struct {
		Version         int             `json:"version"`
		Timestamp       time.Time       `json:"timestamp"`
		MachineID       string          `json:"machine_id"`
		OS              OSInfo          `json:"os"`
		Files           []FileEntry     `json:"files"`
		Procs           []string        `json:"procs"`
		Nets            []string        `json:"nets"`
		Users           []string        `json:"users"`
		AgentsAtGenesis []AgentPresence `json:"agents_at_genesis"`
		WatchedDirs     []string        `json:"watched_dirs,omitempty"`
		Unreadable      []string        `json:"unreadable,omitempty"`
		Hash            string          `json:"hash"`
	}
	for _, watched := range []bool{false, true} {
		old := legacySnapshot{Version: 1, Timestamp: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), MachineID: "fixture", Procs: []string{"pipelock"}}
		if watched {
			old.WatchedDirs = []string{"/opt"}
			old.Unreadable = []string{"/opt/private"}
		}
		payload, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		old.Hash = hashutil.SHA256Hex(payload)
		wire, err := json.Marshal(old)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !loaded.Verify() || loaded.Hash != old.Hash {
			t.Fatal("existing genesis hash no longer verifies")
		}
		encoded, err := json.Marshal(loaded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, wire) {
			t.Fatalf("existing genesis bytes changed:\n%s\n%s", wire, encoded)
		}
		// Explicit empty slices must also remain omitted, like nil legacy fields.
		loaded.ProcessIdentities = []ProcessIdentity{}
		if !loaded.Verify() {
			t.Fatal("empty process identities changed a legacy hash")
		}
	}
}

func TestSnapshotHashCoversProcessExecutablePaths(t *testing.T) {
	s := &Snapshot{Version: 1, Procs: []string{"pipelock"}, ProcessIdentities: []ProcessIdentity{{Name: "pipelock", Path: "/opt/pipelock"}, {Name: "other"}}}
	s.Hash = s.computeHash()
	wire, err := s.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(wire)
	if err != nil || !loaded.Verify() {
		t.Fatalf("new snapshot roundtrip: %v", err)
	}
	if len(loaded.ProcessIdentities) != 2 || loaded.ProcessIdentities[1].Path != "" {
		t.Fatal("unreadable observation lost")
	}
	loaded.ProcessIdentities[0].Path = "/tmp/pipelock"
	if loaded.Verify() {
		t.Fatal("executable path not covered by genesis hash")
	}
}
