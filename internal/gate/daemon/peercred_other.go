//go:build !linux && !darwin

package daemon

import "net"

// peerUID is unavailable off Linux and macOS: every caller is refused (fail closed).
func peerUID(net.Conn) (int, bool) { return -1, false }
