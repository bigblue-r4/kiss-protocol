package genesis

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ProcessIdentity is one observed command name and its procfs executable target.
// Path is empty when unavailable; this is an observation, not a wildcard.
type ProcessIdentity struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// Processes collects the same identities for genesis and drift. Linux kernel
// threads are omitted. Platforms without procfs retain name-only observations.
func Processes() []ProcessIdentity {
	out, err := exec.Command("ps", "-eo", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil
	}
	return parseProcesses(string(out), runtime.GOOS == "linux", os.Readlink)
}

func parseProcesses(out string, linux bool, readlink func(string) (string, error)) []ProcessIdentity {
	var procs []ProcessIdentity
	seen := map[ProcessIdentity]bool{}
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
		p := ProcessIdentity{Name: strings.Join(fields[2:], " ")}
		if linux && readlink != nil {
			// procfs already resolves the executed inode's path. Do not resolve a
			// comm via PATH, or strip " (deleted)" and approve a replacement inode.
			if target, err := readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil && filepath.IsAbs(target) {
				p.Path = target
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

func processNames(procs []ProcessIdentity) []string {
	var names []string
	seen := map[string]bool{}
	for _, p := range procs {
		if !seen[p.Name] {
			seen[p.Name] = true
			names = append(names, p.Name)
		}
	}
	return names
}
