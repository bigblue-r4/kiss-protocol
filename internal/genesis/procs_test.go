package genesis

import (
	"reflect"
	"testing"
)

// Real-shaped `ps -eo pid=,ppid=,comm=` output from an idle Ubuntu box.
const psSample = `    1     0 systemd
    2     0 kthreadd
    3     2 rcu_gp
   41     2 kworker/0:1-events
   97     2 kworker/5:0-i915-unordered
  612     1 sshd
  790     1 ollama
  801   612 sshd
  950     1 split-brain-har
  960     1 Web Content
  961     1 Web Content
`

func TestParseProcNamesSkipsKernelThreads(t *testing.T) {
	got := parseProcNames(psSample, true)
	want := []string{"systemd", "sshd", "ollama", "split-brain-har", "Web Content"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseProcNamesKeepsAllWhenNotLinux(t *testing.T) {
	got := parseProcNames(psSample, false)
	for _, name := range []string{"kthreadd", "rcu_gp", "kworker/0:1-events"} {
		found := false
		for _, g := range got {
			if g == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q dropped with skipKernelThreads=false: %q", name, got)
		}
	}
}

func TestParseProcNamesIgnoresBlankAndShortLines(t *testing.T) {
	if got := parseProcNames("\n  \n 5 1\n", true); len(got) != 0 {
		t.Fatalf("got %q, want none", got)
	}
}

// A live kernel thread name must never come back from ProcNames on Linux.
func TestProcNamesLiveHasNoKworkers(t *testing.T) {
	for _, p := range ProcNames() {
		if len(p) >= 7 && p[:7] == "kworker" {
			t.Fatalf("kernel thread %q leaked into ProcNames", p)
		}
	}
}
