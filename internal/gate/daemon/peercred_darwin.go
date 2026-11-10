//go:build darwin

package daemon

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket
// (LOCAL_PEERCRED), which the kernel fills in and the peer cannot forge.
func peerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, false
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil || cerr != nil || cred == nil {
		return -1, false
	}
	return int(cred.Uid), true
}
