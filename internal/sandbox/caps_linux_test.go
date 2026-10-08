//go:build linux

package sandbox

import (
	"errors"
	"syscall"
	"testing"
)

// Without root this can only show the call is accepted and leaves no ambient
// set behind; the inheritance check needs a real capability and runs as part
// of the root install test (docs/hardening-test.md).
func TestDropAmbientCapsClearsTheSet(t *testing.T) {
	err := DropAmbientCaps()
	if errors.Is(err, syscall.ENOTSUP) {
		t.Skip("cgo build: process-wide prctl unavailable; release builds are CGO_ENABLED=0")
	}
	if err != nil {
		t.Fatalf("DropAmbientCaps: %v", err)
	}
	amb, err := readProcStatusField("CapAmb")
	if err != nil {
		t.Fatal(err)
	}
	if amb != 0 {
		t.Fatalf("CapAmb = 0x%x after clearing", amb)
	}
}
