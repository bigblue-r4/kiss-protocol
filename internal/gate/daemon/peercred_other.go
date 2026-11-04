//go:build !linux

package daemon

import "net"

// peerUID is unavailable off Linux: every caller is refused (fail closed).
func peerUID(net.Conn) (int, bool) { return -1, false }
