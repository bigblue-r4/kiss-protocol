// Package drift compares the current machine state against the genesis snapshot.
package drift

import (
	"os"
	"path/filepath"

	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
)

// Unreadable is the New value of a file_added change whose file the witness
// cannot hash (no read permission, a link to a directory).
const Unreadable = "unreadable"

// Change describes a single detected deviation from genesis.
type Change struct {
	Type    string `json:"type"`           // file_changed, file_removed, file_mode_changed, file_added, new_process
	Path    string `json:"path,omitempty"` // file path, or resolved executable for new_process
	Process string `json:"process,omitempty"`
	Old     string `json:"old,omitempty"`
	New     string `json:"new,omitempty"`
}

// Measure compares the live machine state against snap.
// Returns a (possibly empty) list of changes. An empty list means no drift.
func Measure(snap *genesis.Snapshot) ([]Change, error) {
	var changes []Change

	// Check every file recorded in genesis. The cache hashes a file reached
	// through several paths (/bin -> /usr/bin) once per check.
	hc := genesis.NewHashCache()
	for _, entry := range snap.Files {
		cur := hc.Hash(entry.Path)
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

	changes = append(changes, addedFiles(snap, hc)...)

	changes = append(changes, processChanges(snap, currentProcs())...)
	return changes, nil
}

// addedFiles reports files in the watched directories that genesis did not
// record. A directory reached through a symlink to one already scanned
// (/bin -> /usr/bin) is scanned once, so each new file is reported once.
// Subdirectories are not entered, as at genesis.
func addedFiles(snap *genesis.Snapshot, hc *genesis.HashCache) []Change {
	known := make(map[string]bool, len(snap.Files)+len(snap.Unreadable))
	for _, f := range snap.Files {
		known[f.Path] = true
	}
	for _, p := range snap.Unreadable {
		known[p] = true
	}
	dirs, legacy := snap.ScanDirs()
	var changes []Change
	scanned := map[string]bool{}
	for _, d := range dirs {
		real, err := filepath.EvalSymlinks(d)
		if err != nil || scanned[real] {
			continue
		}
		scanned[real] = true
		des, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, de := range des {
			if de.IsDir() {
				continue
			}
			p := d + "/" + de.Name()
			if known[p] {
				continue
			}
			if cur := hc.Hash(p); cur != nil {
				changes = append(changes, Change{Type: "file_added", Path: p, New: cur.SHA256})
			} else if !legacy {
				// A legacy genesis kept no list of the entries it could not
				// read, so these cannot be told apart from ones present then.
				changes = append(changes, Change{Type: "file_added", Path: p, New: Unreadable})
			}
		}
	}
	return changes
}
