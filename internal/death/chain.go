package death

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const tailBytes int64 = 1 << 20

// Reference hashes the exact previous JSON file bytes, including whitespace.
type Reference struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type SkippedRecord struct {
	Name  string `json:"name"`
	Error string `json:"error"`
}

type savedRecord struct {
	Record
	Reference
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == hex.EncodeToString(b)
}

func recordNames(dir string) ([]string, error) {
	// Glob returns lexicographic order, independent of the JSON timestamps.
	return filepath.Glob(filepath.Join(dir, "death_*.json"))
}

func loadRecord(path string) (savedRecord, error) {
	var s savedRecord
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	// Death records are small. Do not load unbounded data from corrupt files.
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return s, err
	}
	if len(data) > 1<<20 {
		return s, fmt.Errorf("death record exceeds 1 MiB")
	}
	if err := json.Unmarshal(data, &s.Record); err != nil {
		return s, err
	}
	if s.Format != "witness-death/1" && s.Format != "witness-death/2" {
		return s, fmt.Errorf("unsupported format %q", s.Format)
	}
	if s.LogBytes < -1 {
		return s, fmt.Errorf("invalid log length")
	}
	switch s.LogHash.Status {
	case "complete":
		if s.LogBytes < 0 || !validDigest(s.anchor()) {
			return s, fmt.Errorf("invalid complete log hash")
		}
	case "incomplete", "error":
	default:
		return s, fmt.Errorf("invalid log hash status %q", s.LogHash.Status)
	}
	if s.Format == "witness-death/2" {
		if s.HashMode != "full" && s.HashMode != "segment" && s.LogBytes >= 0 {
			return s, fmt.Errorf("invalid hash mode")
		}
		if s.HashMode == "segment" {
			if s.PrevRecord == nil || s.SegmentStart < 0 || s.SegmentStart > s.LogBytes {
				return s, fmt.Errorf("invalid segment reference or bounds")
			}
			if s.LogHash.Status == "complete" && (!validDigest(s.SegmentSHA256) || !validDigest(s.ChainSHA256) || s.LogHash.SHA256 != "") {
				return s, fmt.Errorf("invalid complete segment hash")
			}
		} else {
			if s.SegmentSHA256 != "" || s.ChainSHA256 != "" || s.SegmentStart != 0 {
				return s, fmt.Errorf("segment fields on full record")
			}
			if s.LogHash.Status == "complete" && !validDigest(s.LogHash.SHA256) {
				return s, fmt.Errorf("invalid full hash")
			}
		}
		if s.TailSHA256 != "" && (s.TailHash.Status != "complete" || !validDigest(s.TailSHA256) || s.TailHash.SHA256 != s.TailSHA256) {
			return s, fmt.Errorf("inconsistent tail hash")
		}
		if s.TailHash.Status == "complete" && !validDigest(s.TailSHA256) {
			return s, fmt.Errorf("missing complete tail hash")
		}
		if s.LogHash.Status != "complete" && (s.LogHash.SHA256 != "" || s.SegmentSHA256 != "" || s.ChainSHA256 != "") {
			return s, fmt.Errorf("partial digest on unfinished hash")
		}
	}
	h := sha256.Sum256(data)
	s.Reference = Reference{Name: filepath.Base(path), SHA256: hex.EncodeToString(h[:])}
	return s, nil
}

func (r Record) anchor() string {
	if r.Format == "witness-death/2" && r.HashMode == "segment" {
		return r.ChainSHA256
	}
	return r.LogHash.SHA256
}

// chainDigest encodes raw 32-byte digests followed by uint64 big-endian length.
func chainDigest(previous, segment string, length int64) string {
	p, _ := hex.DecodeString(previous)
	s, _ := hex.DecodeString(segment)
	data := append(p, s...)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(length))
	data = append(data, n[:]...)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func tailStart(length int64) int64 {
	if length > tailBytes {
		return length - tailBytes
	}
	return 0
}

func (b *Broadcaster) hashLog(ctx context.Context, path string, r *Record) {
	r.HashMode = "full"
	paths, err := recordNames(b.primaryDir)
	r.FallbackReason = "no_previous_record"
	var prev *savedRecord
	if err != nil {
		r.FallbackReason = "history_read_error: " + err.Error()
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if ctx.Err() != nil {
			r.FallbackReason = "history_deadline"
			break
		}
		s, err := loadRecord(paths[i])
		if err != nil {
			r.SkippedRecords = append(r.SkippedRecords, SkippedRecord{Name: filepath.Base(paths[i]), Error: err.Error()})
			continue
		}
		prev = &s
		r.PrevRecord = &s.Reference
		break
	}
	if prev != nil {
		r.LogShrank = prev.LogBytes >= 0 && r.LogBytes < prev.LogBytes
		switch {
		case len(r.SkippedRecords) > 0:
			r.FallbackReason = "skipped_invalid_records"
		case r.LogShrank:
			r.FallbackReason = "log_shrank"
		case prev.LogHash.Status != "complete":
			r.FallbackReason = "previous_hash_" + prev.LogHash.Status
		case prev.MachineID != r.MachineID:
			r.FallbackReason = "machine_id_changed"
		case prev.Format == "witness-death/1":
			r.FallbackReason = "previous_record_has_no_tail"
		case !validDigest(prev.TailSHA256):
			r.FallbackReason = "previous_record_has_no_tail"
		default:
			r.FallbackReason = ""
			if prev.PrevRecord != nil {
				if err := checkLink(b.primaryDir, prev.Reference.Name, prev.PrevRecord); err != nil {
					r.FallbackReason = "previous_record_link_invalid: " + err.Error()
				}
			}
			if r.FallbackReason == "" {
				start := tailStart(prev.LogBytes)
				h := hashRange(ctx, path, start, prev.LogBytes-start)
				switch {
				case h.Status != "complete":
					r.FallbackReason = "previous_tail_" + h.Status
				case h.SHA256 != prev.TailSHA256:
					r.PrefixChanged = true
					r.FallbackReason = "prefix_changed"
				default:
					r.HashMode = "segment"
					r.SegmentStart = prev.LogBytes
				}
			}
		}
	} else if len(r.SkippedRecords) > 0 {
		r.FallbackReason = "skipped_invalid_records"
	}
	// Save the current tail even for a full fallback. A future complete record can
	// resume incremental hashing; an incomplete tail cannot serve as a guard.
	start := tailStart(r.LogBytes)
	r.TailHash = hashRange(ctx, path, start, r.LogBytes-start)
	r.TailSHA256 = r.TailHash.SHA256
	if r.HashMode == "segment" {
		h := hashRange(ctx, path, r.SegmentStart, r.LogBytes-r.SegmentStart)
		r.LogHash = Hash{Status: h.Status, Error: h.Error}
		if h.Status == "complete" {
			r.SegmentSHA256 = h.SHA256
			r.ChainSHA256 = chainDigest(prev.anchor(), h.SHA256, r.LogBytes)
		}
	} else {
		r.LogHash = hashFile(ctx, path, r.LogBytes)
	}
}

func checkLink(dir, current string, ref *Reference) error {
	if ref.Name != filepath.Base(ref.Name) || ref.Name >= current || !validDigest(ref.SHA256) {
		return fmt.Errorf("invalid previous record reference")
	}
	paths, err := recordNames(dir)
	if err != nil {
		return err
	}
	found := false
	for _, path := range paths {
		if filepath.Base(path) == ref.Name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("missing previous record %s", ref.Name)
	}
	s, err := loadRecord(filepath.Join(dir, ref.Name))
	if err != nil {
		return err
	}
	if s.Reference.SHA256 != ref.SHA256 {
		return fmt.Errorf("previous record %s SHA-256 mismatch", ref.Name)
	}
	return nil
}
