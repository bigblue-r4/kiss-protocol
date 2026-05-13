package genesis

import (
	"encoding/json"
	"testing"
)

func TestSnapshotVerify(t *testing.T) {
	snap, err := Take("test-machine-id")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if !snap.Verify() {
		t.Fatal("Verify: fresh snapshot failed integrity check")
	}
}

func TestSnapshotTamperDetection(t *testing.T) {
	snap, _ := Take("test-machine-id")
	snap.MachineID = "tampered"
	if snap.Verify() {
		t.Fatal("Verify: tampered snapshot passed integrity check")
	}
}

func TestSnapshotRoundtrip(t *testing.T) {
	snap, _ := Take("test-machine-id")
	data, err := snap.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	loaded, err := Load(data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Verify() {
		t.Fatal("Verify: roundtrip snapshot failed integrity check")
	}
	if loaded.MachineID != snap.MachineID {
		t.Fatalf("MachineID: got %q, want %q", loaded.MachineID, snap.MachineID)
	}
}

func TestSnapshotClean(t *testing.T) {
	snap, _ := Take("test-machine-id")
	snap.AgentsAtGenesis = nil
	if !snap.Clean() {
		t.Fatal("Clean: empty AgentsAtGenesis should be clean")
	}
	snap.AgentsAtGenesis = []AgentPresence{{Name: "test-agent"}}
	if snap.Clean() {
		t.Fatal("Clean: non-empty AgentsAtGenesis should not be clean")
	}
}

func TestSnapshotHashChangesWithContent(t *testing.T) {
	s1, _ := Take("machine-a")
	s2, _ := Take("machine-b")
	if s1.Hash == s2.Hash {
		t.Fatal("different machine IDs produced the same snapshot hash")
	}
}

func TestLoadInvalid(t *testing.T) {
	_, err := Load([]byte("not json"))
	if err == nil {
		t.Fatal("Load: expected error on invalid JSON, got nil")
	}
}

func TestSnapshotJSONHasVersion(t *testing.T) {
	snap, _ := Take("test-machine-id")
	data, _ := snap.Bytes()
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["version"]; !ok {
		t.Fatal("serialized snapshot missing 'version' field")
	}
}
