//go:build unix

package pipelock

import (
	"os"
	"syscall"
)

// identOf returns the device and inode of a file, so a resumed tailer can tell
// "the same file, grown" from "a different file at the same path".
func identOf(fi os.FileInfo) fileIdent {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fileIdent{Dev: uint64(st.Dev), Ino: uint64(st.Ino)} //nolint:unconvert // types differ by platform
	}
	return fileIdent{}
}
