package mirror

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bigblue-r4/kiss-protocol/internal/fsutil"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// LeavesFilename is the leaf-hash feed beside tree-head.json in a file mirror:
// the raw 32-byte Merkle leaf hashes of every record, in log order.
//
// A signed tree head proves "the log had this root at this size", but on its
// own a later head can describe a completely rewritten history. An off-host
// verifier that keeps its own copy of the feed recomputes every new head's
// root from the leaves it already holds plus the new ones; a rewrite of any
// earlier record changes the root and is caught (audit F1 / R3).
// Leaf hashes reveal no record content (each is BLAKE3 of the record JSON).
const LeavesFilename = "leaves.bin"

// LeafSource is the log a feed is published from (implemented by store.Store).
type LeafSource interface {
	LeafCount() uint64
	LeafAt(i uint64) ([32]byte, bool)
	LeavesFrom(from uint64) [][32]byte
}

// LeafPublisher is implemented by mirror backends that can carry the feed.
type LeafPublisher interface {
	// PublishLeaves brings the feed up to date with src. It returns
	// reset=true when the existing feed disagreed with src and was replaced
	// (a re-initialised log, or a tampered mirror): callers must record that.
	PublishLeaves(src LeafSource) (reset bool, err error)
}

// PublishLeaves implements LeafPublisher for the file backend.
//
// Normal case: append the leaves the feed does not have yet (fsynced).
// The feed never shrinks while it agrees with src: a slower concurrent push
// with an older snapshot leaves a longer feed alone. When the first or last
// shared leaf disagrees with src, the feed is rewritten atomically from src.
func (b *fileBackend) PublishLeaves(src LeafSource) (bool, error) {
	b.leafMu.Lock()
	defer b.leafMu.Unlock()

	path := filepath.Join(b.dir, LeavesFilename)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return false, fmt.Errorf("mirror leaves: open: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("mirror leaves: stat: %w", err)
	}
	if fi.Size()%32 != 0 {
		return true, b.rewriteLeaves(src, "feed size is not a multiple of 32 bytes")
	}
	have := uint64(fi.Size() / 32)
	total := src.LeafCount()

	shared := have
	if total < shared {
		shared = total
	}
	if shared > 0 {
		for _, i := range []uint64{0, shared - 1} {
			var got [32]byte
			if _, err := f.ReadAt(got[:], int64(i)*32); err != nil {
				return false, fmt.Errorf("mirror leaves: read: %w", err)
			}
			want, ok := src.LeafAt(i)
			if !ok || !bytes.Equal(got[:], want[:]) {
				return true, b.rewriteLeaves(src, fmt.Sprintf("feed disagrees with the log at leaf %d", i))
			}
		}
	}
	if have >= total {
		return false, nil // up to date, or a newer snapshot already wrote more
	}

	newLeaves := src.LeavesFrom(have)
	buf := make([]byte, 0, 32*len(newLeaves))
	for _, l := range newLeaves {
		buf = append(buf, l[:]...)
	}
	if _, err := f.WriteAt(buf, int64(have)*32); err != nil {
		return false, fmt.Errorf("mirror leaves: append: %w", err)
	}
	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("mirror leaves: sync: %w", err)
	}
	return false, nil
}

func (b *fileBackend) rewriteLeaves(src LeafSource, why string) error {
	all := src.LeavesFrom(0)
	buf := make([]byte, 0, 32*len(all))
	for _, l := range all {
		buf = append(buf, l[:]...)
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(b.dir, LeavesFilename), buf, 0644); err != nil {
		return fmt.Errorf("mirror leaves: rewrite (%s): %w", why, err)
	}
	return nil
}

// ReadLeaves reads a leaf-hash feed: consecutive 32-byte leaf hashes.
func ReadLeaves(r io.Reader) ([][32]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("leaf feed is %d bytes, not a multiple of 32", len(data))
	}
	leaves := make([][32]byte, len(data)/32)
	for i := range leaves {
		copy(leaves[i][:], data[i*32:])
	}
	return leaves, nil
}

// ErrLeafRootMismatch: the feed's first size leaves do not give the head's root.
var ErrLeafRootMismatch = errors.New("leaf feed root does not match the signed head: history differs from the leaves held")

// VerifyLeafRoot checks that the first size leaves of the feed produce root.
func VerifyLeafRoot(leaves [][32]byte, size uint64, root [32]byte) error {
	if size > uint64(len(leaves)) {
		return fmt.Errorf("leaf feed has %d leaves, head claims %d", len(leaves), size)
	}
	if merkle.Root(leaves[:size]) != root {
		return ErrLeafRootMismatch
	}
	return nil
}
