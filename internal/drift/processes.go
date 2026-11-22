package drift

import "github.com/bigblue-r4/kiss-protocol/internal/genesis"

func processChanges(snap *genesis.Snapshot, current []genesis.ProcessIdentity) []Change {
	var changes []Change
	if len(snap.ProcessIdentities) != 0 {
		known := make(map[genesis.ProcessIdentity]bool, len(snap.ProcessIdentities))
		for _, p := range snap.ProcessIdentities {
			known[p] = true
		}
		for _, p := range current {
			if !known[p] {
				changes = append(changes, Change{Type: "new_process", Process: p.Name, Path: p.Path})
			}
		}
		return changes
	}
	// Legacy genesis contains only names; never invent path observations for it.
	known := make(map[string]bool, len(snap.Procs))
	for _, name := range snap.Procs {
		known[name] = true
	}
	for _, p := range current {
		if !known[p.Name] {
			changes = append(changes, Change{Type: "new_process", Process: p.Name, Path: p.Path})
		}
	}
	return changes
}

func currentProcs() []genesis.ProcessIdentity { return genesis.Processes() }
