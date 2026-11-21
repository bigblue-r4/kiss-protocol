package accept

import (
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
)

// A new file is approved by path and hash, like a changed one: the same file
// stays approved, a different file at that path is reported again.
func TestApproveFileAddedPinsTheHash(t *testing.T) {
	op := newKey(t)
	added := drift.Change{Type: "file_added", Path: "/usr/local/bin/rustc", New: "aa11"}
	s := NewSet()
	if _, err := s.Apply(signedAccept(t, op, added), policy(op, nil)); err != nil {
		t.Fatal(err)
	}
	swapped := added
	swapped.New = "bb22"
	left, n := s.Filter([]drift.Change{added, swapped})
	if n != 1 || len(left) != 1 || left[0] != swapped {
		t.Fatalf("approved=%d unapproved=%+v, want the same file approved and the swapped one reported", n, left)
	}
	if _, err := NewAccept(mid, "x", []drift.Change{{Type: "file_added", Path: "/usr/bin/x"}}); err == nil {
		t.Error("file_added approval without a hash accepted")
	}
}
