//go:build linux

package daemon

import (
	"net"
	"syscall"
)

// peerUID returns the uid of the process on the other end of a unix socket
// (SO_PEERCRED), which the kernel fills in and the peer cannot forge.
func peerUID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return -1, false
	}
	return int(cred.Uid), true
}
