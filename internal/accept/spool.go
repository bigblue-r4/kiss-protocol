package accept

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SpoolDir is where the CLI leaves signed requests for the daemon.
func SpoolDir(primaryDir string) string { return filepath.Join(primaryDir, "accept-spool") }

// Submit copies a signed request into the spool. It does not check the
// signer's trust: the daemon does, and records a rejection if it fails.
func Submit(primaryDir string, r *Request) (string, error) {
	if err := r.verifySig(); err != nil {
		return "", err
	}
	dir := SpoolDir(primaryDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, r.ID+".json")
	tmp := path + ".tmp"
	if err := r.WriteFile(tmp); err != nil {
		return "", err
	}
	return path, os.Rename(tmp, path)
}

// Pending is one spooled request file. Err is set if it could not be read.
type Pending struct {
	File    string
	Request *Request
	Err     error
}

// ReadSpool lists the spooled requests, oldest name first. Partly written
// (.tmp) files are left alone.
func ReadSpool(primaryDir string) ([]Pending, error) {
	dir := SpoolDir(primaryDir)
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read spool: %w", err)
	}
	var out []Pending
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		r, err := ReadFile(path)
		out = append(out, Pending{File: path, Request: r, Err: err})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out, nil
}

// OperatorsPath is the operator allowlist under the witness dir. Same format
// as the soul trust allowlist ("<label> <hex-pubkey>" per line), but a
// separate file: an operator key approves drift, it does not sign tree heads.
func OperatorsPath(witnessDir string) string {
	return filepath.Join(witnessDir, "trust", "operators.txt")
}
