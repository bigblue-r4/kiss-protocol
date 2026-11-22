package drift

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"testing"
)

func TestProcessPathsPreserveSameNameDifferentExecutables(t *testing.T) {
	targets := map[string]string{"/proc/10/exe": "/opt/pipelock", "/proc/11/exe": "/tmp/pipelock", "/proc/12/exe": "/opt/pipelock", "/proc/13/exe": "/opt/pipelock (deleted)"}
	got := parseProcesses("2 0 kthreadd\n3 2 kworker\n10 1 pipelock\n11 1 pipelock\n12 1 pipelock\n13 1 pipelock\n14 1 pipelock\ninvalid 1 bad\n", true, func(path string) (string, error) {
		if p, ok := targets[path]; ok {
			return p, nil
		}
		return "", errors.New("denied")
	})
	want := []processIdentity{{"pipelock", "/opt/pipelock"}, {"pipelock", "/tmp/pipelock"}, {"pipelock", "/opt/pipelock (deleted)"}, {"pipelock", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	changes := processChanges([]string{"unrelated"}, got)
	if len(changes) != 4 || changes[1].Process != "pipelock" || changes[1].Path != "/tmp/pipelock" {
		t.Fatalf("same-name binary lost from drift: %+v", changes)
	}
	if got := processChanges([]string{"pipelock"}, got); len(got) != 0 {
		t.Fatalf("legacy genesis name comparison changed: %+v", got)
	}
}

func TestProcessPathUnavailableAndNonLinuxRemainNameOnly(t *testing.T) {
	for _, linux := range []bool{true, false} {
		got := parseProcesses("10 1 name with spaces\n", linux, func(string) (string, error) {
			if !linux {
				t.Fatal("non-Linux attempted procfs")
			}
			return "", os.ErrPermission
		})
		if !reflect.DeepEqual(got, []processIdentity{{name: "name with spaces"}}) {
			t.Fatalf("got %+v", got)
		}
	}
}

func TestLiveProcessUsesProcExeTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs")
	}
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(os.Getpid()), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range currentProcs() {
		if p.path == target {
			return
		}
	}
	t.Fatalf("current executable %q absent from process identities", target)
}
