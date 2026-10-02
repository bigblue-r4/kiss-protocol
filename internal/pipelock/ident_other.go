//go:build !unix

package pipelock

import "os"

// identOf has no inode to read on this platform. A zero identity still lets
// resume work, but a file replaced at the same size cannot be told apart.
func identOf(os.FileInfo) fileIdent { return fileIdent{} }
