package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// ExportFormat names the export document layout. Bump it on any change a
// verifier has to know about.
const ExportFormat = "witness-export/1"

// Export is a self-verifying copy of the log, taken at one signed head.
//
// LeafHashes covers every record up to Head.Size, so a verifier holding only
// the export and the signer's public key can recompute the root and check the
// signature: no machine key, no access to the witness host. Entries holds the
// decrypted records that matched the filter; each must hash to its leaf, so a
// filtered export still proves every record it shows is in the signed log.
type Export struct {
	Format     string   `json:"format"`
	Head       TreeHead `json:"head"`
	LeafHashes []string `json:"leaf_hashes"`
	Entries    []Entry  `json:"entries"`
	Filter     Filter   `json:"filter"`
}

// Filter selects which records an export includes in full. The zero value
// selects everything.
type Filter struct {
	Since   time.Time `json:"since,omitempty"`
	Until   time.Time `json:"until,omitempty"`
	Sources []string  `json:"sources,omitempty"`
}

func (f Filter) match(e Entry) bool {
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Timestamp.Before(f.Until) {
		return false
	}
	if len(f.Sources) == 0 {
		return true
	}
	for _, s := range f.Sources {
		if e.Source == s {
			return true
		}
	}
	return false
}

// exportAttempts bounds the retries when a running witness appends between
// reading the head and reading the log.
const exportAttempts = 20

// Export returns the log as of its current stored head (see ExportDir).
func (s *Store) Export(f Filter) (Export, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ExportDir(s.dir, s.key, f)
}

// ExportDir returns the log in dir as of its current stored head. The head is
// the signed file on disk, not a recomputed one, so the export carries the
// signature a third party checks. It only reads: unlike Open it never moves a
// crash tail aside, so it is safe while the witness daemon is appending; the
// head and log are re-read until they agree.
func ExportDir(dir string, key []byte, f Filter) (Export, error) {
	var lastErr error
	for i := 0; i < exportAttempts; i++ {
		head, err := readStoredHead(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return Export{Format: ExportFormat, LeafHashes: []string{}, Entries: []Entry{}, Filter: f}, nil
			}
			return Export{}, err
		}
		entries, _, _, _, err := readLog(filepath.Join(dir, logFilename), key)
		if err != nil {
			return Export{}, err
		}
		if uint64(len(entries)) < head.Size {
			lastErr = fmt.Errorf("log has %d records, head covers %d", len(entries), head.Size)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		entries = entries[:head.Size]
		leaves := make([][32]byte, len(entries))
		for j, e := range entries {
			leaves[j] = leafHash(e)
		}
		root := merkle.Root(leaves)
		if hex.EncodeToString(root[:]) != head.Root {
			lastErr = errors.New("head root does not match the log")
			time.Sleep(10 * time.Millisecond)
			continue
		}
		out := Export{Format: ExportFormat, Head: head, LeafHashes: make([]string, len(leaves)), Entries: []Entry{}, Filter: f}
		for j, l := range leaves {
			out.LeafHashes[j] = hex.EncodeToString(l[:])
			if f.match(entries[j]) {
				out.Entries = append(out.Entries, entries[j])
			}
		}
		return out, nil
	}
	return Export{}, fmt.Errorf("store: export: head and log never agreed: %w", lastErr)
}

// VerifyResult is what VerifyExport established.
type VerifyResult struct {
	Size        uint64
	Root        string
	EntriesSeen int
	PriorsOK    int
}

// VerifyExport checks an export with nothing but public data:
//
//   - the root recomputed from LeafHashes equals Head.Root, and Head.Size matches;
//   - Head is signed by one of pins (at least one pin is required: an export
//     that verifies against the key it names itself proves nothing);
//   - every entry shown hashes to the leaf at its position (Seq is 1-based);
//   - every prior head (one held from an earlier export) is a prefix of this
//     log: its root equals the root of the first prior.Size leaves. That is the
//     append-only check: a log rewritten after a head left the host fails it.
func VerifyExport(x Export, pins []ed25519.PublicKey, priors []TreeHead) (VerifyResult, error) {
	if x.Format != ExportFormat {
		return VerifyResult{}, fmt.Errorf("unknown export format %q", x.Format)
	}
	if len(pins) == 0 {
		return VerifyResult{}, errors.New("verify-export needs the signer's public key (--pubkey)")
	}
	if uint64(len(x.LeafHashes)) != x.Head.Size {
		return VerifyResult{}, fmt.Errorf("head size %d but %d leaf hashes", x.Head.Size, len(x.LeafHashes))
	}
	leaves := make([][32]byte, len(x.LeafHashes))
	for i, h := range x.LeafHashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return VerifyResult{}, fmt.Errorf("leaf %d: malformed hash", i)
		}
		copy(leaves[i][:], b)
	}
	root := merkle.Root(leaves)
	if x.Head.Size == 0 {
		// A log with no records has never written a head; nothing to check
		// beyond the priors below (any prior with records means truncation).
	} else if hex.EncodeToString(root[:]) != x.Head.Root {
		return VerifyResult{}, fmt.Errorf("root mismatch: head says %s, leaves give %s", x.Head.Root, hex.EncodeToString(root[:]))
	}
	if err := verifyHeadSignature(x.Head, root, pins); err != nil {
		return VerifyResult{}, err
	}
	for _, e := range x.Entries {
		if e.Seq == 0 || e.Seq > x.Head.Size {
			return VerifyResult{}, fmt.Errorf("entry seq %d outside the log (size %d)", e.Seq, x.Head.Size)
		}
		if leafHash(e) != leaves[e.Seq-1] {
			return VerifyResult{}, fmt.Errorf("entry seq %d does not match its leaf: altered after export", e.Seq)
		}
	}
	for i, p := range priors {
		if p.Size > x.Head.Size {
			return VerifyResult{}, fmt.Errorf("prior head %d (size %d) is longer than this log (size %d): log truncated", i, p.Size, x.Head.Size)
		}
		pr := merkle.Root(leaves[:p.Size])
		if hex.EncodeToString(pr[:]) != p.Root {
			return VerifyResult{}, fmt.Errorf("prior head %d (size %d): root %s, this log gives %s: log rewritten after that head", i, p.Size, p.Root, hex.EncodeToString(pr[:]))
		}
		var prRoot [32]byte
		copy(prRoot[:], pr[:])
		if err := verifyHeadSignature(p, prRoot, pins); err != nil {
			return VerifyResult{}, fmt.Errorf("prior head %d: %w", i, err)
		}
	}
	return VerifyResult{Size: x.Head.Size, Root: x.Head.Root, EntriesSeen: len(x.Entries), PriorsOK: len(priors)}, nil
}

func verifyHeadSignature(h TreeHead, root [32]byte, pins []ed25519.PublicKey) error {
	if h.Size == 0 {
		return nil // an empty log has no head to sign
	}
	if h.Signature == "" {
		return ErrHeadNotSigned
	}
	sig, err := hex.DecodeString(h.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("tree head: malformed signature")
	}
	pub, err := hex.DecodeString(h.SignerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("tree head: malformed signer_key")
	}
	pinned := false
	for _, p := range pins {
		if bytes.Equal(pub, p) {
			pinned = true
		}
	}
	if !pinned {
		return ErrUnexpectedSigner
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), treeHeadSigInput(h.Size, root), sig) {
		return errors.New("tree head signature verification failed")
	}
	return nil
}

// ReadExport decodes an export document.
func ReadExport(data []byte) (Export, error) {
	var x Export
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&x); err != nil {
		return Export{}, fmt.Errorf("parse export: %w", err)
	}
	return x, nil
}
