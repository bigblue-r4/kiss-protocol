// Package drift compares the current machine state against the genesis snapshot.
package drift

import (
	"os/exec"
	"strings"

	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
)

// Change describes a single detected deviation from genesis.
type Change struct {
	Type    string `json:"type"` // file_changed, file_removed, file_mode_changed, new_process
	Path    string `json:"path,omitempty"`
	Process string `json:"process,omitempty"`
	Old     string `json:"old,omitempty"`
	New     string `json:"new,omitempty"`
}

// Measure compares the live machine state against snap.
// Returns a (possibly empty) list of changes. An empty list means no drift.
func Measure(snap *genesis.Snapshot) ([]Change, error) {
	var changes []Change

	// Check every file recorded in genesis.
	for _, entry := range snap.Files {
		cur := genesis.HashOneFile(entry.Path)
		if cur == nil {
			changes = append(changes, Change{
				Type: "file_removed",
				Path: entry.Path,
				Old:  entry.SHA256,
			})
			continue
		}
		if cur.SHA256 != entry.SHA256 {
			changes = append(changes, Change{
				Type: "file_changed",
				Path: entry.Path,
				Old:  entry.SHA256,
				New:  cur.SHA256,
			})
		}
		if cur.Mode != entry.Mode {
			changes = append(changes, Change{
				Type: "file_mode_changed",
				Path: entry.Path,
				Old:  entry.Mode,
				New:  cur.Mode,
			})
		}
	}

	// Report processes that are running now but were not at genesis.
	// (Missing genesis processes are normal — they exit; new ones are notable.)
	genesisProcs := make(map[string]bool, len(snap.Procs))
	for _, p := range snap.Procs {
		genesisProcs[p] = true
	}
	for _, p := range currentProcs() {
		if !genesisProcs[p] {
			changes = append(changes, Change{
				Type:    "new_process",
				Process: p,
			})
		}
	}

	return changes, nil
}

func currentProcs() []string {
	out, err := exec.Command("ps", "-eo", "comm").Output()
	if err != nil {
		return nil
	}
	var procs []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p == "" || p == "COMMAND" || p == "COMM" {
			continue
		}
		if !seen[p] {
			seen[p] = true
			procs = append(procs, p)
		}
	}
	return procs
}
