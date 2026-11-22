package genesis

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

func TestProcessPathsPreserveSameNameDifferentExecutables(t *testing.T) {
	targets := map[string]string{"/proc/10/exe": "/opt/pipelock", "/proc/11/exe": "/tmp/pipelock", "/proc/12/exe": "/opt/pipelock", "/proc/13/exe": "/opt/pipelock (deleted)"}
	got := parseProcesses("2 0 kthreadd\n3 2 kworker\n10 1 pipelock\n11 1 pipelock\n12 1 pipelock\n13 1 pipelock\n14 1 pipelock\ninvalid 1 bad\n", true, func(path string) (string, error) {
		if p, ok := targets[path]; ok {
			return p, nil
		}
		return "", os.ErrPermission
	})
	want := []ProcessIdentity{{"pipelock", "/opt/pipelock"}, {"pipelock", "/tmp/pipelock"}, {"pipelock", "/opt/pipelock (deleted)"}, {"pipelock", ""}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
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
		if !reflect.DeepEqual(got, []ProcessIdentity{{Name: "name with spaces"}}) {
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
	for _, p := range Processes() {
		if p.Path == target {
			return
		}
	}
	t.Fatalf("current executable %q absent from process identities", target)
}

func TestProcessReadlinkExitVersusPermission(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		keep bool
	}{
		{"ENOENT", syscall.ENOENT, false}, {"ESRCH", syscall.ESRCH, false},
		{"EACCES", syscall.EACCES, true}, {"EPERM", syscall.EPERM, true},
		{"EIO", syscall.EIO, true},
		{"EINVAL", syscall.EINVAL, true},
	} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped_%t", tc.name, wrapped), func(t *testing.T) {
				err := tc.err
				if wrapped {
					err = &os.PathError{Op: "readlink", Path: "/proc/10/exe", Err: err}
				}
				got := parseProcesses("10 1 pipelock\n", true, func(string) (string, error) { return "", err })
				if tc.keep {
					if !reflect.DeepEqual(got, []ProcessIdentity{{Name: "pipelock"}}) {
						t.Fatalf("permission refusal dropped: %+v", got)
					}
				} else if len(got) != 0 {
					t.Fatalf("exited process invented identity: %+v", got)
				}
			})
		}
	}
}

func TestProcessRelativeExecutableTargetRemainsVisible(t *testing.T) {
	got := parseProcesses("10 1 pipelock\n", true, func(string) (string, error) { return "relative/pipelock", nil })
	if !reflect.DeepEqual(got, []ProcessIdentity{{Name: "pipelock"}}) {
		t.Fatalf("untrusted executable target hid process: %+v", got)
	}
}
