package drift

import (
	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
	"reflect"
	"testing"
)

func TestGenesisProcessIdentityComparison(t *testing.T) {
	original := genesis.ProcessIdentity{Name: "pipelock", Path: "/opt/pipelock"}
	other := genesis.ProcessIdentity{Name: "pipelock", Path: "/tmp/pipelock"}
	unknown := genesis.ProcessIdentity{Name: "pipelock"}
	deleted := genesis.ProcessIdentity{Name: "pipelock", Path: "/opt/pipelock (deleted)"}
	for _, tc := range []struct {
		name    string
		snap    genesis.Snapshot
		current []genesis.ProcessIdentity
		want    []Change
	}{
		{"same identity", genesis.Snapshot{Procs: []string{"pipelock"}, ProcessIdentities: []genesis.ProcessIdentity{original}}, []genesis.ProcessIdentity{original}, nil},
		{"different executable", genesis.Snapshot{Procs: []string{"pipelock"}, ProcessIdentities: []genesis.ProcessIdentity{original}}, []genesis.ProcessIdentity{original, other}, []Change{{Type: "new_process", Process: "pipelock", Path: "/tmp/pipelock"}}},
		{"path unavailable now", genesis.Snapshot{ProcessIdentities: []genesis.ProcessIdentity{original}}, []genesis.ProcessIdentity{unknown}, []Change{{Type: "new_process", Process: "pipelock"}}},
		{"path becomes readable", genesis.Snapshot{ProcessIdentities: []genesis.ProcessIdentity{unknown}}, []genesis.ProcessIdentity{original}, []Change{{Type: "new_process", Process: "pipelock", Path: "/opt/pipelock"}}},
		{"unreadable unchanged", genesis.Snapshot{ProcessIdentities: []genesis.ProcessIdentity{unknown}}, []genesis.ProcessIdentity{unknown}, nil},
		{"deleted identity", genesis.Snapshot{ProcessIdentities: []genesis.ProcessIdentity{original}}, []genesis.ProcessIdentity{deleted}, []Change{{Type: "new_process", Process: "pipelock", Path: deleted.Path}}},
		{"legacy names unchanged", genesis.Snapshot{Procs: []string{"pipelock"}}, []genesis.ProcessIdentity{original, other, unknown}, nil},
		{"legacy new name", genesis.Snapshot{Procs: []string{"unrelated"}}, []genesis.ProcessIdentity{other}, []Change{{Type: "new_process", Process: "pipelock", Path: other.Path}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := processChanges(&tc.snap, tc.current)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
