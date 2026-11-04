package store

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
)

// ErrHeadBehind reports a stored head covering fewer records than the reader
// already holds: the log was truncated or its head rolled back.
var ErrHeadBehind = errors.New("stored tree head covers fewer records than already read: log truncated or head rolled back")

// ErrLogShort reports a log holding fewer records than its stored head
// covers, after retries: records were removed.
var ErrLogShort = errors.New("log holds fewer records than its stored tree head covers: records removed")

// ReadSince returns the stored tree head and the records it covers that come
// after the first have records, which a previous call ended at byte offset
// off. It also returns the offset just past the last returned record, to pass
// to the next call. Start with off = 0, have = 0.
//
// It is read-only like ExportDir and OpenPinned: it opens the log O_RDONLY and
// never writes, renames, truncates or creates a file, so it is safe beside the
// running daemon and works on a read-only directory. It reads the head first,
// then the log (records reach the log before the head that covers them), so
// the records it returns are complete and can no longer change.
//
// It verifies nothing: not the head's signature, not that the new records
// extend what the caller already holds. The caller (the gate's evidence view)
// does both, against keys it pins.
//
// If the head covers fewer than have records it returns the head and
// ErrHeadBehind. An absent head is fine for an empty log (have == 0) and
// ErrMissingTreeHead otherwise.
func ReadSince(dir string, key []byte, off int64, have uint64) (TreeHead, []Entry, int64, error) {
	var lastErr error
	for i := 0; i < readOnlyAttempts; i++ {
		if i > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		head, err := readStoredHead(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				return TreeHead{}, nil, off, err
			}
			if have > 0 {
				return TreeHead{}, nil, off, ErrMissingTreeHead
			}
			return TreeHead{}, nil, off, nil
		}
		if head.Size < have {
			return head, nil, off, ErrHeadBehind
		}
		need := head.Size - have
		if need == 0 {
			return head, nil, off, nil
		}
		entries, ends, err := readLogFrom(filepath.Join(dir, logFilename), key, off, need)
		if err != nil {
			return TreeHead{}, nil, off, err
		}
		if uint64(len(entries)) < need {
			// Only possible if the log lost records (or the daemon is moving
			// a crash tail aside at start): retry, then report.
			lastErr = fmt.Errorf("%w (head covers %d, log holds %d after the %d already read)", ErrLogShort, head.Size, have+uint64(len(entries)), have)
			continue
		}
		return head, entries, ends[len(ends)-1], nil
	}
	return TreeHead{}, nil, off, lastErr
}

// readLogFrom reads up to max records starting at byte offset off, the way
// readLog does (a frame that does not decrypt or decode is skipped, a partial
// frame ends the read). ends[i] is the offset just past entries[i]. Opens
// O_RDONLY; never writes.
func readLogFrom(path string, key []byte, off int64, max uint64) (entries []Entry, ends []int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, nil, err
	}
	for uint64(len(entries)) < max {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			break
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length == 0 || length > 64<<20 {
			break
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(f, sealed); err != nil {
			break
		}
		off += 4 + int64(length)
		plain, err := encrypt.Open(sealed, key)
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(plain, &e); err != nil {
			continue
		}
		entries = append(entries, e)
		ends = append(ends, off)
	}
	return entries, ends, nil
}

// LeafHash returns the Merkle leaf hash of e, exactly as the log computes it.
func LeafHash(e Entry) [32]byte { return leafHash(e) }

// VerifyHeadSignature checks that h is signed by one of pins over its size
// and root, as VerifyExport does for an export's head. It does not check the
// root against any records. An empty head (size 0) has no signature to check.
func VerifyHeadSignature(h TreeHead, pins []ed25519.PublicKey) error {
	if len(pins) == 0 {
		return errors.New("store: verifying a head signature needs at least one pinned key")
	}
	var root [32]byte
	if h.Size > 0 {
		b, err := hex.DecodeString(h.Root)
		if err != nil || len(b) != 32 {
			return errors.New("tree head: malformed root")
		}
		copy(root[:], b)
	}
	return verifyHeadSignature(h, root, pins)
}
