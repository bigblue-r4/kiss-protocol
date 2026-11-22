package drift

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type processIdentity struct{ name, path string }

// Genesis remains name-based for compatibility. For new names, preserve every
// distinct executable instead of collapsing different binaries with the same comm.
func processChanges(baseline []string, current []processIdentity) []Change {
	known := make(map[string]bool, len(baseline))
	for _, name := range baseline {
		known[name] = true
	}
	var changes []Change
	for _, p := range current {
		if !known[p.name] {
			changes = append(changes, Change{Type: "new_process", Process: p.name, Path: p.path})
		}
	}
	return changes
}

func currentProcs() []processIdentity {
	out, err := exec.Command("ps", "-eo", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil
	}
	return parseProcesses(string(out), runtime.GOOS == "linux", os.Readlink)
}

func parseProcesses(out string, linux bool, readlink func(string) (string, error)) []processIdentity {
	var procs []processIdentity
	seen := map[processIdentity]bool{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 {
			continue
		}
		if linux && (pid == 2 || fields[1] == "2") {
			continue
		}
		p := processIdentity{name: strings.Join(fields[2:], " ")}
		if linux {
			// procfs already resolves the executed inode's path. Do not resolve a
			// comm via PATH, or strip " (deleted)" and approve a replacement inode.
			if target, err := readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil && filepath.IsAbs(target) {
				p.path = target
			}
		}
		// Unreadable/exited processes remain visible with no path. They cannot
		// match a path-pinned approval; legacy name-only approvals still apply.
		if !seen[p] {
			seen[p] = true
			procs = append(procs, p)
		}
	}
	return procs
}
