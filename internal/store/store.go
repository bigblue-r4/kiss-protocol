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
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// TreeHead is the Merkle log head stored at tree-head.json.
type TreeHead struct {
	Size      uint64 `json:"size"`
	Root      string `json:"root"`              // hex-encoded 32-byte BLAKE3 root
	PrevRoot  string `json:"prev_root"`          // root of the immediately prior head; "" for size==0
	Timestamp string `json:"ts"`
	MAC       string `json:"mac"`                  // BLAKE3-keyed(machineKey, size_be8 || root)
	Signature string `json:"sig,omitempty"`        // ed25519 sig over (size_be8 || root), Phase 2+
	SignerKey string `json:"signer_key,omitempty"` // hex pubkey corresponding to Signature
}

// Store is an encrypted, append-only Merkle log.
type Store struct {
	mu     sync.Mutex
	dir    string
	key    []byte
	s      signer.Signer // nil → BLAKE3-MAC mode (Phase 1)
	seq    uint64
	leaves [][32]byte
	f      *os.File
}

// Open opens or creates the log at dir/witness.log.
// s is the signer used to authenticate tree heads. Pass nil to use the
// Phase 1 BLAKE3-keyed MAC only (acceptable for read-only opens or testing).
// If existing entries are present it rebuilds the Merkle tree and verifies
// the stored tree head. Returns an error if integrity fails.
func Open(dir string, key []byte, s signer.Signer) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	entries, err := ReadAll(dir, key)
	if err != nil {
		return nil, fmt.Errorf("store: read existing log: %w", err)
	}

	// Rebuild Merkle tree from decrypted entry data.
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}

	// Verify stored tree head if one exists.
	if len(leaves) > 0 {
		if err := verifyTreeHead(dir, key, s, leaves); err != nil {
			return nil, fmt.Errorf("store: tree head integrity: %w", err)
		}
	}

	var seq uint64
	if len(entries) > 0 {
		seq = entries[len(entries)-1].Seq
	}

	path := filepath.Join(dir, logFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}

	return &Store{dir: dir, key: key, s: s, seq: seq, leaves: leaves, f: f}, nil
}

// Append encrypts and appends a new entry to the log, then updates the tree head.
func (s *Store) Append(level, event, source string, data interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	e := Entry{
		Seq:       s.seq,
		Timestamp: time.Now().UTC(),
		Level:     level,
		Event:     event,
		Source:    source,
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

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
	if _, err := s.f.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := s.f.Write(sealed); err != nil {
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
	if err := verifyTreeHead(s.dir, s.key, s.s, leaves); err != nil {
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
	path := filepath.Join(dir, logFilename)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
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
		plain, err := encrypt.Open(sealed, key)
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(plain, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
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
// the ed25519 signature. If s is non-nil and no sig is present, logs a warning
// but does not fail (allows Phase 1 → Phase 2 transition without a re-init).
func verifyTreeHead(dir string, key []byte, s signer.Signer, leaves [][32]byte) error {
	data, err := os.ReadFile(filepath.Join(dir, treeHeadFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no tree head yet; created on first Append
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
		sigInput := treeHeadSigInput(uint64(len(leaves)), root)
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), sigInput, rawSig) {
			return errors.New("tree head signature verification failed")
		}
	}

	return nil
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
	h.Write(treeHeadSigInput(size, root))
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
