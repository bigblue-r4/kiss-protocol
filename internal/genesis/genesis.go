// Package genesis captures a cryptographically verified machine state snapshot.
// This snapshot becomes entry zero of the witness log.
package genesis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/hashutil"
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
//
// agents records any AI agents detected before witness was installed; it is
// folded into the snapshot BEFORE the integrity hash is computed. AgentsAtGenesis
// is part of the hashed payload, so assigning it after Take would leave the
// stored hash covering an empty agent list — a later Verify (e.g. on
// `witness start`) would then recompute a different hash and reject the genesis
// as tampered. Pass agents here so the hash and the recorded agents agree.
func Take(machineID string, agents []AgentPresence) (*Snapshot, error) {
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
		Files:           hashPaths(WatchFiles, WatchDirs),
		Procs:           procList(),
		Nets:            netInterfaces(),
		Users:           userList(),
		AgentsAtGenesis: agents,
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
	return hashutil.SHA256Hex(data)
}

func kernelVersion() string {
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOOS
}

func hashPaths(files, dirs []string) []FileEntry {
	var entries []FileEntry
	hc := NewHashCache()
	for _, p := range files {
		if e := hc.Hash(p); e != nil {
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
			if e := hc.Hash(d + "/" + de.Name()); e != nil {
				entries = append(entries, *e)
			}
		}
	}
	return entries
}

// HashOneFile computes a FileEntry for the given path. Returns nil on error.
//
// The file is streamed through SHA-256 rather than read whole, so a large
// binary in a watched directory costs a fixed buffer, not its size in memory.
// Mode and size come from the same open file that was hashed.
func HashOneFile(path string) *FileEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	return &FileEntry{
		Path:   path,
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Mode:   fmt.Sprintf("%04o", info.Mode()),
		Size:   info.Size(),
	}
}

// HashCache hashes each underlying file at most once per pass.
//
// On merged-/usr systems (current Debian, Ubuntu, Fedora) /bin and /sbin are
// symlinks to /usr/bin and /usr/sbin, so the watched directories name every
// binary twice, and many binaries are themselves symlinks to another watched
// file. HashOneFile follows symlinks, so two paths that resolve to the same
// file always get the same hash, mode and size; the cache computes that once
// and hands each path its own entry. Results are identical to calling
// HashOneFile on every path. Use a new cache for each pass: it never expires.
type HashCache struct {
	byReal map[string]*FileEntry // resolved path -> entry (nil = unreadable)
}

// NewHashCache returns an empty cache for one hashing pass.
func NewHashCache() *HashCache {
	return &HashCache{byReal: make(map[string]*FileEntry)}
}

// Hash is HashOneFile(path), computed once per resolved file.
func (c *HashCache) Hash(path string) *FileEntry {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return HashOneFile(path) // broken link, vanished file: no sharing
	}
	e, ok := c.byReal[real]
	if !ok {
		e = HashOneFile(real)
		c.byReal[real] = e
	}
	if e == nil {
		return nil
	}
	out := *e
	out.Path = path
	return &out
}

func procList() []string { return ProcNames() }

// ProcNames lists the distinct command names of running processes, skipping
// Linux kernel threads. Kernel threads (kthreadd, PID 2, and its children)
// rename themselves after the work queue they are serving — kworker/0:1-events
// becomes kworker/0:1-mm_percpu_wq — so a name-based comparison saw dozens of
// "new processes" on every drift check on an idle machine. They are not
// programs anyone launched, so they are left out of both genesis and drift.
func ProcNames() []string {
	out, err := exec.Command("ps", "-eo", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil
	}
	return parseProcNames(string(out), runtime.GOOS == "linux")
}

// parseProcNames reads `ps -eo pid=,ppid=,comm=` output. comm may contain
// spaces, so everything after the second field is the name.
func parseProcNames(out string, skipKernelThreads bool) []string {
	var procs []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if skipKernelThreads && (f[0] == "2" || f[1] == "2") {
			continue
		}
		name := strings.Join(f[2:], " ")
		if !seen[name] {
			seen[name] = true
			procs = append(procs, name)
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
