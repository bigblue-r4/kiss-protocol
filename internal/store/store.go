// Package store implements the primary encrypted, append-only Merkle log.
//
// Each entry is encrypted with AES-256-GCM and stored as a framed record
// (4-byte big-endian length prefix). Separately, a tree head file holds the
// current Merkle root and a BLAKE3-keyed MAC over (size || root), which
// catches any tampering with the tree head itself. Phase 2 upgrades the MAC
// to an ed25519 signature from a hardware-bound key.
//
// The Merkle tree is rebuilt from the decrypted leaf data on Open, so an
// attacker who rewrites encrypted records without also rewriting the tree
// head is detected on startup. An attacker who rewrites the tree head is
// detected by the MAC.
package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

const (
	logFilename      = "witness.log"
	treeHeadFilename = "tree-head.json"
)

// Entry is one log record. PrevHash is accepted on decode for v1 backward
// compatibility but is not written by v2.
type Entry struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	Level     string          `json:"level"`
	Event     string          `json:"event"`
	Source    string          `json:"source"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// ErrMissingTreeHead reports a log that has entries but no tree-head.json. The
// head is what makes a truncated or edited log detectable, so its absence is
// treated as tampering, not as a fresh store.
var ErrMissingTreeHead = errors.New("tree head missing for a non-empty log: the head file was removed (log may have been truncated)")

// ErrUnexpectedSigner reports a tree head signed by a key other than the
// witness's own signer or a key the operator trusts. The signer_key the head
// file names is attacker-writable, so when the store is opened with a signer
// the signature must come from that signer or from the trust allowlist passed
// to OpenTrusting (which is how a key rotation keeps opening the old head).
var ErrUnexpectedSigner = errors.New("tree head signed by a key that is neither this witness's signer nor in the trust allowlist: the head may have been forged")

// TreeHead is the Merkle log head stored at tree-head.json.
type TreeHead struct {
	Size      uint64 `json:"size"`
	Root      string `json:"root"`      // hex-encoded 32-byte BLAKE3 root
	PrevRoot  string `json:"prev_root"` // root of the immediately prior head; "" for size==0
	Timestamp string `json:"ts"`
	MAC       string `json:"mac"`                  // BLAKE3-keyed(machineKey, size_be8 || root)
	Signature string `json:"sig,omitempty"`        // ed25519 sig over (size_be8 || root), Phase 2+
	SignerKey string `json:"signer_key,omitempty"` // hex pubkey corresponding to Signature
}

// Store is an encrypted, append-only Merkle log.
type Store struct {
	mu  sync.Mutex
	dir string
	key []byte
	s   signer.Signer // nil → BLAKE3-MAC mode (Phase 1)
	// trusted: other keys whose heads are accepted when s is set (see OpenTrusting).
	trusted []ed25519.PublicKey
	// unsignedHead: opened with a signer, but the stored head carried no
	// signature (see OpenedWithUnsignedHead).
	unsignedHead bool
	recovered    Recovery
	seq          uint64
	leaves       [][32]byte
	f            *os.File
}

// Open opens or creates the log at dir/witness.log.
// s is the signer used to authenticate tree heads. Pass nil to use the
// Phase 1 BLAKE3-keyed MAC only (acceptable for read-only opens or testing).
// If existing entries are present it rebuilds the Merkle tree and verifies
// the stored tree head. Returns an error if integrity fails.
func Open(dir string, key []byte, s signer.Signer) (*Store, error) {
	return OpenTrusting(dir, key, s, nil)
}

// OpenTrusting is Open for a store whose head may be signed by a key other
// than s: the keys in trusted (the operator's trust allowlist). After a key
// rotation the existing head is signed by the old key; with the old key
// trusted it opens, and the next Append signs with s. Ignored when s is nil.
func OpenTrusting(dir string, key []byte, s signer.Signer, trusted []ed25519.PublicKey) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, logFilename)
	entries, ends, frames, size, err := readLog(path, key)
	if err != nil {
		return nil, fmt.Errorf("store: read existing log: %w", err)
	}

	// Rebuild Merkle tree from decrypted entry data.
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}

	// A crash between writing a record and writing its head leaves exactly one
	// complete record the head does not cover yet. Verify the head against
	// the records it does cover; the extra one is moved aside below, never
	// signed (signing it would let anyone with the machine key get a forged
	// record signed by restarting the witness).
	committed := len(leaves)
	if len(leaves) > 0 {
		if h, err := readStoredHead(dir); err == nil && h.Size >= 1 && h.Size+1 == uint64(len(leaves)) {
			committed = int(h.Size)
		}
		if err := verifyTreeHead(dir, key, s, trusted, leaves[:committed]); err != nil {
			return nil, fmt.Errorf("store: tree head integrity: %w", err)
		}
	}

	// Anything after the last committed record is a crash tail: a half-written
	// record, or the one uncommitted record above. Left in place it would sit
	// in front of every later write and make the log unreadable, so it is
	// moved to a quarantine file (kept for inspection) and reported.
	var cut int64
	if committed > 0 {
		cut = ends[committed-1]
	}
	// Only a true crash tail is moved: after the cut there may be the one
	// uncommitted record and/or a partial frame, nothing else. Complete records
	// that fail to decrypt (a wrong key, corruption) are never moved here.
	lastGood := cut
	if len(ends) > 0 {
		lastGood = ends[len(ends)-1]
	}
	var rec Recovery
	if size > cut && frames == lastGood {
		q, err := quarantineTail(path, cut, size)
		if err != nil {
			return nil, fmt.Errorf("store: recover crash tail: %w", err)
		}
		rec = Recovery{Bytes: size - cut, UncommittedRecords: len(leaves) - committed, QuarantineFile: q}
		entries, leaves = entries[:committed], leaves[:committed]
	}
	if committed < len(leaves) {
		// Not a clean crash tail: the head must cover every record.
		if err := verifyTreeHead(dir, key, s, trusted, leaves); err != nil {
			return nil, fmt.Errorf("store: tree head integrity: %w", err)
		}
	}

	var seq uint64
	if len(entries) > 0 {
		seq = entries[len(entries)-1].Seq
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	unsigned := false
	if s != nil && len(leaves) > 0 {
		if head, err := readStoredHead(dir); err == nil && head.Signature == "" {
			unsigned = true
		}
	}

	return &Store{dir: dir, key: key, s: s, trusted: trusted, unsignedHead: unsigned, recovered: rec, seq: seq, leaves: leaves, f: f}, nil
}

// Recovery describes a crash tail removed from the log when it was opened.
type Recovery struct {
	Bytes              int64  // bytes moved out of witness.log
	UncommittedRecords int    // complete records the head did not yet cover (0 or 1)
	QuarantineFile     string // where the bytes were moved; never deleted
}

// Recovered reports a crash tail found and moved aside by Open (zero if none).
// The caller should record it: the log is intact up to its signed head, and
// the quarantined bytes are evidence of the interrupted write.
func (s *Store) Recovered() Recovery { return s.recovered }

// RootAt returns the hex Merkle root of the first size records: the root the
// log had when it was that long. An append-only log's root at an earlier
// published size must equal the root published then.
func (s *Store) RootAt(size uint64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size > uint64(len(s.leaves)) {
		return "", fmt.Errorf("store: size %d exceeds log size %d", size, len(s.leaves))
	}
	root := merkle.Root(s.leaves[:size])
	return hex.EncodeToString(root[:]), nil
}

// OpenedWithUnsignedHead reports that the store was opened with a signer but
// the stored head had no signature. That is expected once, when signing is
// first configured for an existing log; otherwise someone stripped the
// signature to get around the signer check. Either way the caller should
// record it. The next Append signs the head again.
func (s *Store) OpenedWithUnsignedHead() bool {
	return s.unsignedHead
}

// Append encrypts and appends a new entry to the log, then updates the tree head.
func (s *Store) Append(level, event, source string, data interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	// Sanitize string fields to valid UTF-8 so json.Marshal produces a stable
	// byte sequence. Without this, invalid bytes (e.g. \xbd) are replaced with
	// the � JSON escape on the first marshal but output as literal UTF-8
	// after an unmarshal→remarshal cycle, causing a leaf-hash mismatch.
	e := Entry{
		Seq:       s.seq,
		Timestamp: time.Now().UTC(),
		Level:     strings.ToValidUTF8(level, "\xef\xbf\xbd"),
		Event:     strings.ToValidUTF8(event, "\xef\xbf\xbd"),
		Source:    strings.ToValidUTF8(source, "\xef\xbf\xbd"),
	}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		e.Data = json.RawMessage(b)
	}

	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sealed, err := encrypt.Seal(plain, s.key)
	if err != nil {
		return err
	}

	// One write per record: length prefix and record together, so an
	// interrupted write leaves at most one partial frame at the end (which
	// Open recovers), never a length without its record.
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(sealed)), uint32(len(sealed)))
	frame = append(frame, sealed...)
	if _, err := s.f.Write(frame); err != nil {
		return err
	}

	s.leaves = append(s.leaves, leafHash(e))
	return writeTreeHead(s.dir, s.key, s.s, s.leaves)
}

// Snapshot flushes and returns the raw encrypted log bytes.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.f.Sync()
	return os.ReadFile(filepath.Join(s.dir, logFilename))
}

// Close flushes and closes the log.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.f.Sync()
	return s.f.Close()
}

// Path returns the log file path.
func (s *Store) Path() string {
	return filepath.Join(s.dir, logFilename)
}

// Head returns the current tree head.
func (s *Store) Head() TreeHead {
	s.mu.Lock()
	defer s.mu.Unlock()
	root := merkle.Root(s.leaves)
	return TreeHead{
		Size:      uint64(len(s.leaves)),
		Root:      hex.EncodeToString(root[:]),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// VerifyIntegrity decrypts all entries, rebuilds the Merkle tree, and checks
// the stored tree head. Returns the number of verified leaves and any error.
func (s *Store) VerifyIntegrity() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := ReadAll(s.dir, s.key)
	if err != nil {
		return 0, err
	}
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}
	if len(leaves) == 0 {
		return 0, nil
	}
	if err := verifyTreeHead(s.dir, s.key, s.s, s.trusted, leaves); err != nil {
		return 0, err
	}
	return uint64(len(leaves)), nil
}

// InclusionProof returns an inclusion proof for the entry at the given
// 0-based leaf index, along with the entry itself.
func (s *Store) InclusionProof(index uint64) (merkle.Proof, Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := ReadAll(s.dir, s.key)
	if err != nil {
		return merkle.Proof{}, Entry{}, err
	}
	if index >= uint64(len(entries)) {
		return merkle.Proof{}, Entry{}, fmt.Errorf("index %d out of range (log has %d entries)", index, len(entries))
	}
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}
	proof, err := merkle.Prove(leaves, index)
	if err != nil {
		return merkle.Proof{}, Entry{}, err
	}
	return proof, entries[index], nil
}

// ReadAll decrypts and returns all entries from dir/witness.log.
// Entries with an unrecognised prev_hash field (v1 format) are decoded
// normally — the field is simply ignored by the v2 struct.
func ReadAll(dir string, key []byte) ([]Entry, error) {
	entries, _, _, _, err := readLog(filepath.Join(dir, logFilename), key)
	return entries, err
}

// readLog is ReadAll that also reports, for each returned entry, the byte
// offset just past its frame; frames, the offset just past the last complete
// frame (decryptable or not); and the file size. Bytes past frames are a
// partial (torn) write.
func readLog(path string, key []byte) (entries []Entry, ends []int64, frames, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, 0, 0, nil
		}
		return nil, nil, 0, 0, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}

	var off int64
	for {
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
	return entries, ends, off, size, nil
}

// quarantineTail copies bytes [from, to) of the log to a new file beside it,
// then truncates the log to from. Returns the quarantine file's path.
func quarantineTail(path string, from, to int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	tail := make([]byte, to-from)
	_, err = f.ReadAt(tail, from)
	_ = f.Close()
	if err != nil {
		return "", err
	}
	q := fmt.Sprintf("%s.crash-tail-%d", path, time.Now().UnixNano())
	if err := os.WriteFile(q, tail, 0600); err != nil {
		return "", err
	}
	return q, os.Truncate(path, from)
}

// leafHash returns the Merkle leaf hash for an entry.
// It hashes the canonical JSON encoding of the entry so that the hash is
// computable from plaintext — no encryption key required to verify the tree.
func leafHash(e Entry) [32]byte {
	b, _ := json.Marshal(e)
	return merkle.HashLeaf(b)
}

// writeTreeHead atomically writes the tree head file.
// If s is non-nil, an ed25519 signature is included alongside the BLAKE3 MAC.
// prevRoot is the root of the previous tree head, enabling the enforcer and
// the audit command to verify head chain continuity without re-reading the log.
func writeTreeHead(dir string, key []byte, s signer.Signer, leaves [][32]byte) error {
	root := merkle.Root(leaves)
	mac := computeMAC(key, uint64(len(leaves)), root)

	// Read the previous tree head's root for chain linkage.
	prevRoot := ""
	if existing, err := readStoredHead(dir); err == nil && existing.Root != "" {
		prevRoot = existing.Root
	}

	head := TreeHead{
		Size:      uint64(len(leaves)),
		Root:      hex.EncodeToString(root[:]),
		PrevRoot:  prevRoot,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		MAC:       hex.EncodeToString(mac[:]),
	}

	if s != nil {
		sigInput := treeHeadSigInput(uint64(len(leaves)), root)
		sig, err := s.Sign(sigInput)
		if err != nil {
			return fmt.Errorf("sign tree head: %w", err)
		}
		head.Signature = hex.EncodeToString(sig)
		head.SignerKey = hex.EncodeToString(s.PublicKey())
	}

	data, err := json.MarshalIndent(head, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, treeHeadFilename+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, treeHeadFilename))
}

// verifyTreeHead reads tree-head.json and checks it against the given leaf set.
// Always verifies the BLAKE3 MAC. If a Signature field is present, also verifies
// the ed25519 signature. If s is non-nil the signature must be s's own or from
// a key in trusted: the signer_key in the file is attacker-writable, so it is
// only taken at its word when no signer is available to pin to. If s is
// non-nil and no sig is present, it does not fail (allows Phase 1 → Phase 2
// transition without a re-init); Open reports it through OpenedWithUnsignedHead.
func verifyTreeHead(dir string, key []byte, s signer.Signer, trusted []ed25519.PublicKey, leaves [][32]byte) error {
	data, err := os.ReadFile(filepath.Join(dir, treeHeadFilename))
	if err != nil {
		if os.IsNotExist(err) {
			if len(leaves) == 0 {
				return nil // a new, empty store: the head is created on first Append
			}
			// Every log in this format has had a head since the Merkle log was
			// introduced, and Append writes it with every entry. A log with entries
			// and no head means the head was removed — which, without this check,
			// also let a truncated log verify cleanly.
			return ErrMissingTreeHead
		}
		return err
	}
	var head TreeHead
	if err := json.Unmarshal(data, &head); err != nil {
		return fmt.Errorf("parse tree head: %w", err)
	}

	root := merkle.Root(leaves)
	storedRoot, err := hex.DecodeString(head.Root)
	if err != nil || len(storedRoot) != 32 {
		return errors.New("tree head: malformed root")
	}
	var storedRootArr [32]byte
	copy(storedRootArr[:], storedRoot)
	if root != storedRootArr {
		return fmt.Errorf("tree head root mismatch: log tampered (stored %s, computed %s)",
			head.Root, hex.EncodeToString(root[:]))
	}
	if head.Size != uint64(len(leaves)) {
		return fmt.Errorf("tree head size mismatch: stored %d, log has %d", head.Size, len(leaves))
	}

	storedMAC, err := hex.DecodeString(head.MAC)
	if err != nil || len(storedMAC) != 32 {
		return errors.New("tree head: malformed MAC")
	}
	expected := computeMAC(key, uint64(len(leaves)), root)
	if !macEqual(expected[:], storedMAC) {
		return errors.New("tree head MAC failed — tree head may have been tampered")
	}

	// Ed25519 signature check (Phase 2+).
	if head.Signature != "" {
		rawSig, err := hex.DecodeString(head.Signature)
		if err != nil || len(rawSig) != ed25519.SignatureSize {
			return errors.New("tree head: malformed signature")
		}
		pubBytes, err := hex.DecodeString(head.SignerKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return errors.New("tree head: malformed signer_key")
		}
		if s != nil && !keyAccepted(pubBytes, s.PublicKey(), trusted) {
			return fmt.Errorf("%w (head key %s, this witness's key %s)",
				ErrUnexpectedSigner, head.SignerKey, hex.EncodeToString(s.PublicKey()))
		}
		sigInput := treeHeadSigInput(uint64(len(leaves)), root)
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), sigInput, rawSig) {
			return errors.New("tree head signature verification failed")
		}
	}

	return nil
}

// keyAccepted reports whether a head signed by pub may be trusted: it is the
// witness's own key or one the operator listed.
func keyAccepted(pub, own []byte, trusted []ed25519.PublicKey) bool {
	if bytes.Equal(pub, own) {
		return true
	}
	for _, k := range trusted {
		if bytes.Equal(pub, k) {
			return true
		}
	}
	return false
}

// treeHeadSigInput returns the byte slice that is signed/verified for a tree head.
func treeHeadSigInput(size uint64, root [32]byte) []byte {
	var sizeBuf [8]byte
	binary.BigEndian.PutUint64(sizeBuf[:], size)
	input := make([]byte, 8+32)
	copy(input[:8], sizeBuf[:])
	copy(input[8:], root[:])
	return input
}

// computeMAC returns BLAKE3-keyed(key, size_be8 || root).
func computeMAC(key []byte, size uint64, root [32]byte) [32]byte {
	h := blake3.New(32, key)
	// blake3's Write never returns an error; discard explicitly.
	_, _ = h.Write(treeHeadSigInput(size, root))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// readStoredHead reads the on-disk tree-head.json without verifying it.
// Used only to extract PrevRoot for linkage before overwriting.
func readStoredHead(dir string) (TreeHead, error) {
	data, err := os.ReadFile(filepath.Join(dir, treeHeadFilename))
	if err != nil {
		return TreeHead{}, err
	}
	var h TreeHead
	return h, json.Unmarshal(data, &h)
}

// macEqual is a constant-time comparison.
func macEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
