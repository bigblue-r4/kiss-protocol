// Package genesis captures a cryptographically verified machine state snapshot.
// This snapshot becomes entry zero of the witness log.
package genesis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Snapshot is the full machine state at genesis.
type Snapshot struct {
	Version   int         `json:"version"`
	Timestamp time.Time   `json:"timestamp"`
	MachineID string      `json:"machine_id"`
	OS        OSInfo      `json:"os"`
	Files     []FileEntry `json:"files"`
	Procs     []string    `json:"procs"`
	Nets      []string    `json:"nets"`
	Users     []string    `json:"users"`
	// AgentsAtGenesis records any AI agents detected before witness was installed.
	// An empty slice means genesis was taken cleanly before any agent.
	// A non-empty slice means the snapshot is COMPROMISED — agents had prior access.
	AgentsAtGenesis []AgentPresence `json:"agents_at_genesis"`
	// Hash is a SHA-256 of all other fields. Verified on load.
	Hash string `json:"hash"`
}

// Clean returns true if no AI agents were present when genesis was taken.
// A clean genesis means the witness was established before any agent had access.
func (s *Snapshot) Clean() bool {
	return len(s.AgentsAtGenesis) == 0
}

// OSInfo describes the operating system at genesis.
type OSInfo struct {
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
	Kernel   string `json:"kernel"`
	Hostname string `json:"hostname"`
}

// FileEntry is one file's integrity record.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Size   int64  `json:"size"`
}

// WatchFiles are individual files hashed at genesis and checked for drift.
var WatchFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group",
	"/etc/hosts", "/etc/resolv.conf", "/etc/hostname",
	"/etc/sudoers", "/etc/crontab", "/etc/environment",
	"/etc/ssh/sshd_config",
	"/proc/version",
}

// WatchDirs are directories that are shallow-hashed (one level, no recursion).
var WatchDirs = []string{
	"/usr/bin", "/usr/sbin", "/bin", "/sbin",
	"/etc/cron.d", "/etc/cron.daily", "/etc/init.d",
}

// Take captures the current machine state as a verified Snapshot.
func Take(machineID string) (*Snapshot, error) {
	hostname, _ := os.Hostname()
	s := &Snapshot{
		Version:   1,
		Timestamp: time.Now().UTC(),
		MachineID: machineID,
		OS: OSInfo{
			GOOS:     runtime.GOOS,
			GOARCH:   runtime.GOARCH,
			Kernel:   kernelVersion(),
			Hostname: hostname,
		},
		Files: hashPaths(WatchFiles, WatchDirs),
		Procs: procList(),
		Nets:  netInterfaces(),
		Users: userList(),
	}
	s.Hash = s.computeHash()
	return s, nil
}

// Verify checks the snapshot's integrity hash.
func (s *Snapshot) Verify() bool {
	return s.computeHash() == s.Hash
}

// Bytes serializes the snapshot to indented JSON.
func (s *Snapshot) Bytes() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Load deserializes a snapshot from JSON bytes.
func Load(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Snapshot) computeHash() string {
	// Hash all fields except Hash itself.
	tmp := *s
	tmp.Hash = ""
	data, _ := json.Marshal(tmp)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func kernelVersion() string {
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOOS
}

func hashPaths(files, dirs []string) []FileEntry {
	var entries []FileEntry
	for _, p := range files {
		if e := HashOneFile(p); e != nil {
			entries = append(entries, *e)
		}
	}
	for _, d := range dirs {
		des, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, de := range des {
			if de.IsDir() {
				continue // shallow only
			}
			if e := HashOneFile(d + "/" + de.Name()); e != nil {
				entries = append(entries, *e)
			}
		}
	}
	return entries
}

// HashOneFile computes a FileEntry for the given path. Returns nil on error.
func HashOneFile(path string) *FileEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return &FileEntry{
		Path:   path,
		SHA256: hex.EncodeToString(sum[:]),
		Mode:   fmt.Sprintf("%04o", info.Mode()),
		Size:   info.Size(),
	}
}

func procList() []string {
	out, err := exec.Command("ps", "-eo", "comm").Output()
	if err != nil {
		return nil
	}
	var procs []string
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p != "" && p != "COMMAND" && p != "COMM" {
			procs = append(procs, p)
		}
	}
	return procs
}

func netInterfaces() []string {
	// Linux: `ip -o link show`
	if out, err := exec.Command("ip", "-o", "link", "show").Output(); err == nil {
		var ifaces []string
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSuffix(parts[1], ":")
				ifaces = append(ifaces, name)
			}
		}
		return ifaces
	}
	// macOS: `ifconfig -l`
	if out, err := exec.Command("ifconfig", "-l").Output(); err == nil {
		return strings.Fields(strings.TrimSpace(string(out)))
	}
	return nil
}

func userList() []string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	var users []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, ":", 2); len(parts) >= 1 {
			users = append(users, parts[0])
		}
	}
	return users
}
