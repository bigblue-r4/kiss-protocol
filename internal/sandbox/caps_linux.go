//go:build linux

package sandbox

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Linux prctl(2) constants (linux/prctl.h).
const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
)

// DropAmbientCaps clears the ambient capability set on every thread of this
// process. The hardened unit grants CAP_DAC_READ_SEARCH as an ambient
// capability so the witness can read root-only files it fingerprints (such as
// /etc/shadow). Ambient capabilities are inherited across exec, so without
// this every program the witness starts (Pipelock, ps, ip, its watchdog)
// would inherit the right to read any file. Clearing the ambient set leaves
// the witness's own effective capability in place and gives children nothing.
//
// It must run before the witness starts any other program. It needs a static
// (CGO_ENABLED=0) build: in a cgo build the Go runtime cannot apply a
// process-wide prctl and this returns ENOTSUP, which the caller records.
func DropAmbientCaps() error {
	if amb, err := ambientCaps(); err == nil && amb == 0 {
		return nil // nothing granted, nothing to clear (dev runs, non-systemd starts)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0); errno != 0 {
		return errno
	}
	return nil
}

// ambientCaps reads this process's ambient capability set from /proc.
func ambientCaps() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "CapAmb:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		}
	}
	return 0, os.ErrNotExist
}
