// Package tests holds repository-wide checks that no single package can make.
package tests

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/bigblue-r4/kiss-protocol"

// listDeps returns every package in the module with its full transitive
// dependency set, as reported by `go list -deps`.
func listDeps(t *testing.T) map[string][]string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the import-boundary check needs the go tool on PATH: %v", err)
	}
	cmd := exec.Command(goBin, "list", "-f", `{{.ImportPath}}{{range .Deps}} {{.}}{{end}}`, module+"/...")
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go list: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list: %v", err)
	}
	deps := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 {
			deps[f[0]] = f[1:]
		}
	}
	return deps
}

func under(pkg, prefix string) bool {
	p := module + "/" + prefix
	return pkg == p || strings.HasPrefix(pkg, p+"/")
}

// TestImportBoundaries makes the process-isolation claims in
// docs/enforcer-arch.md and docs/gate-arch.md compiler-checked: Go would let
// any command import any internal package of this module.
//
//   - the witness (cmd/witness) never links the enforcer or the gate;
//   - the gate (cmd/gate, internal/gate/...) never links the enforcer.
func TestImportBoundaries(t *testing.T) {
	deps := listDeps(t)
	if _, ok := deps[module+"/cmd/witness"]; !ok {
		t.Fatal("cmd/witness not found by go list: the check would pass vacuously")
	}
	rules := []struct {
		from      string   // package prefix the rule applies to
		forbidden []string // prefixes it must not depend on
	}{
		{"cmd/witness", []string{"internal/enforcer", "cmd/enforcer", "internal/gate", "cmd/gate"}},
		{"cmd/gate", []string{"internal/enforcer", "cmd/enforcer", "cmd/witness"}},
		{"internal/gate", []string{"internal/enforcer", "cmd"}},
	}
	for pkg, ds := range deps {
		for _, r := range rules {
			if !under(pkg, r.from) {
				continue
			}
			for _, d := range ds {
				for _, f := range r.forbidden {
					if under(d, f) {
						t.Errorf("%s depends on %s: %s must not import %s", pkg, d, r.from, f)
					}
				}
			}
		}
	}
}
