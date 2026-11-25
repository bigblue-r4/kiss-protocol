// Package evlog is the pilot evidence log: an append-only file of plaintext
// records in an RFC 6962 SHA-256 tree, with C2SP checkpoints signed by the
// log and cosigned by tlog-witness witnesses.
//
// Layout of the public directory (everything an evaluator needs, nothing
// secret):
//
//	records.jsonl      one record per line; leaf i = SHA-256(0x00 || line i without its newline)
//	checkpoint         the latest signed checkpoint, with the cosignatures it got
//	checkpoints/<N>    the checkpoint at size N, kept
//	log.json           informational descriptor (keys in it are NOT trusted by the verifier)
//	status.json        per-witness outcome of the last checkpoint round
//
// The private data directory holds the witness state and quarantined bytes.
// The signing key is read from a separate file.
//
// Records are plaintext by design (Stage 2 decision D3): the pilot is for
// synthetic or explicitly authorised non-sensitive data only.
package evlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
	"golang.org/x/mod/sumdb/note"
)

// Format identifies the public layout and record format.
const Format = "harborlight-pilot-log/1"

// DefaultMaxRecord bounds one feed line.
const DefaultMaxRecord = 64 << 10

// Witness is a configured tlog-witness.
type Witness struct {
	URL string                 // submission prefix
	Key checkpoint.CosignerKey // pinned
	// OperatorControlled marks a witness that runs under the log operator's
	// control (such as the one in the local demo). It is disclosed; it
	// demonstrates the protocol but gives no independence.
	OperatorControlled bool
}

// Config configures a log.
type Config struct {
	DataDir, PublicDir string
	Signer             note.Signer
	VerifierKey        string // the log's note verifier key
	Witnesses          []Witness
	MaxRecord          int
	Now                func() time.Time
	HTTP               *http.Client
}

// Record is one line of records.jsonl. Exactly one of Event, Rejected or
// Kind is set: an accepted feed line, a rejected one (only its hash is
// kept), or a record the log writes about itself.
type Record struct {
	Seq      uint64          `json:"seq"`
	Received string          `json:"received"`
	FeedEnd  int64           `json:"feed_end"`
	Event    json.RawMessage `json:"event,omitempty"`
	Rejected string          `json:"rejected,omitempty"`
	LineHash string          `json:"line_sha256,omitempty"`
	Kind     string          `json:"kind,omitempty"`
	Detail   string          `json:"detail,omitempty"`
}

// WitnessStatus is the outcome of the last round for one witness.
type WitnessStatus struct {
	Name     string `json:"name"`
	Held     uint64 `json:"held_size"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Attempts string `json:"at"`
}

// Log is an open evidence log. One process writes it.
type Log struct {
	cfg      Config
	mu       sync.Mutex
	f        *os.File
	leaves   []tlog.Hash
	feedEnd  int64
	held     map[string]uint64
	Recovery []string // what Open had to repair, also written as records
}

// Open opens or creates the log. It refuses to start if the records on disk
// do not match the log's own latest checkpoint: that is lost or altered
// evidence, and it must be looked at, not papered over.
func Open(cfg Config) (*Log, error) {
	if cfg.MaxRecord == 0 {
		cfg.MaxRecord = DefaultMaxRecord
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	for _, d := range []string{cfg.DataDir, cfg.PublicDir, filepath.Join(cfg.PublicDir, "checkpoints")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	l := &Log{cfg: cfg, held: map[string]uint64{}}
	path := filepath.Join(cfg.PublicDir, "records.jsonl")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if i := bytes.LastIndexByte(data, '\n'); i+1 != len(data) {
		// A torn final write: move the partial line aside, keep it, record it.
		tail := data[i+1:]
		q := filepath.Join(cfg.DataDir, "quarantine", fmt.Sprintf("records-%d.tail", cfg.Now().UnixNano()))
		if err := os.MkdirAll(filepath.Dir(q), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(q, tail, 0o600); err != nil {
			return nil, err
		}
		if err := os.Truncate(path, int64(i+1)); err != nil {
			return nil, err
		}
		data = data[:i+1]
		sum := sha256.Sum256(tail)
		l.Recovery = append(l.Recovery, fmt.Sprintf("torn final record: %d bytes (sha256 %s) moved to %s", len(tail), hex.EncodeToString(sum[:]), filepath.Base(q)))
	}
	for n, line := range bytes.SplitAfter(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		line = line[:len(line)-1]
		var r Record
		if err := json.Unmarshal(line, &r); err != nil || r.Seq != uint64(n) {
			return nil, fmt.Errorf("evlog: records.jsonl line %d is not record %d: refusing to start", n+1, n)
		}
		l.leaves = append(l.leaves, tlog.HashLeaf(line))
		if r.FeedEnd > 0 || r.Kind == "feed_reset" {
			l.feedEnd = r.FeedEnd
		}
	}
	if raw, err := os.ReadFile(filepath.Join(cfg.PublicDir, "checkpoint")); err == nil {
		s, err := checkpoint.Open(raw)
		if err != nil {
			return nil, fmt.Errorf("evlog: own checkpoint unreadable: %w", err)
		}
		if err := s.VerifyLog(cfg.VerifierKey); err != nil {
			return nil, fmt.Errorf("evlog: own checkpoint not signed by this log's key: %w", err)
		}
		c := s.Checkpoint
		if c.Size > uint64(len(l.leaves)) {
			return nil, fmt.Errorf("evlog: checkpoint commits to %d records but only %d are on disk: evidence lost, refusing to start", c.Size, len(l.leaves))
		}
		if tlog.Root(l.leaves[:c.Size]) != c.Root {
			return nil, fmt.Errorf("evlog: records on disk do not match the signed checkpoint at size %d: evidence altered, refusing to start", c.Size)
		}
	}
	if b, err := os.ReadFile(filepath.Join(cfg.DataDir, "witness-state.json")); err == nil {
		if err := json.Unmarshal(b, &l.held); err != nil {
			return nil, fmt.Errorf("evlog: witness-state.json: %w", err)
		}
	}
	l.f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	for _, msg := range l.Recovery {
		if err := l.appendLocked([]Record{{Kind: "recovery", Detail: msg, FeedEnd: l.feedEnd}}); err != nil {
			return nil, err
		}
	}
	if err := l.writeDescriptor(); err != nil {
		return nil, err
	}
	return l, nil
}

// Close closes the records file.
func (l *Log) Close() error { return l.f.Close() }

// Size is the number of records.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.leaves))
}

func (l *Log) appendLocked(rs []Record) error {
	var buf bytes.Buffer
	var hashes []tlog.Hash
	now := l.cfg.Now().UTC().Format(time.RFC3339Nano)
	for i := range rs {
		rs[i].Seq = uint64(len(l.leaves) + i)
		rs[i].Received = now
		line, err := json.Marshal(rs[i])
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
		hashes = append(hashes, tlog.HashLeaf(line))
	}
	if _, err := l.f.Write(buf.Bytes()); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.leaves = append(l.leaves, hashes...)
	return nil
}

// Append records events written by the process itself (used by tests and
// by `harborlight-log append`). Each must be a JSON object.
func (l *Log) Append(events ...json.RawMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rs := make([]Record, 0, len(events))
	for _, e := range events {
		rs = append(rs, l.feedRecord(e, l.feedEnd))
	}
	return l.appendLocked(rs)
}

func (l *Log) feedRecord(line []byte, end int64) Record {
	r := Record{FeedEnd: end}
	switch {
	case len(line) > l.cfg.MaxRecord:
		r.Rejected = "line longer than " + strconv.Itoa(l.cfg.MaxRecord) + " bytes"
	case !json.Valid(line) || bytes.TrimSpace(line)[0] != '{':
		r.Rejected = "not a JSON object"
	default:
		var c bytes.Buffer
		if err := json.Compact(&c, line); err != nil {
			r.Rejected = "not a JSON object"
		} else {
			r.Event = c.Bytes()
		}
	}
	if r.Rejected != "" {
		sum := sha256.Sum256(line)
		r.LineHash = hex.EncodeToString(sum[:])
	}
	return r
}

// Ingest appends every complete new line of an NDJSON feed file, from where
// the last record left off. Invalid lines are recorded as rejected, with
// their hash and not their content. A feed that shrank is recorded as a
// feed_reset and read again from the start.
func (l *Log) Ingest(feed string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(feed)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	var rs []Record
	if st.Size() < l.feedEnd {
		rs = append(rs, Record{Kind: "feed_reset", Detail: fmt.Sprintf("feed shrank from %d to %d bytes", l.feedEnd, st.Size())})
		l.feedEnd = 0
	}
	if _, err := f.Seek(l.feedEnd, io.SeekStart); err != nil {
		return 0, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	off := l.feedEnd
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Overlong line: consume to its end and reject it.
			h := sha256.New()
			h.Write(line)
			n := int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = r.ReadSlice('\n')
				h.Write(line)
				n += int64(len(line))
			}
			if err != nil {
				break // incomplete: wait for the rest
			}
			off += n
			rs = append(rs, Record{FeedEnd: off, Rejected: "line longer than the read buffer", LineHash: hex.EncodeToString(h.Sum(nil))})
			continue
		}
		if err != nil {
			break // EOF; a partial last line waits for its newline
		}
		off += int64(len(line))
		body := bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		rs = append(rs, l.feedRecord(append([]byte(nil), body...), off))
	}
	if len(rs) == 0 {
		return 0, nil
	}
	if err := l.appendLocked(rs); err != nil {
		return 0, err
	}
	l.feedEnd = off
	return len(rs), nil
}

// Checkpoint signs the current tree, submits it to every witness, and
// publishes it with the cosignatures that verified. It is safe to call with
// no new records: witnesses re-cosign the same size with a fresh timestamp,
// which keeps the checkpoint fresh for verifiers.
func (l *Log) Checkpoint(ctx context.Context) ([]WitnessStatus, error) {
	l.mu.Lock()
	leaves := l.leaves
	l.mu.Unlock()
	c := checkpoint.Checkpoint{Origin: l.cfg.Signer.Name(), Size: uint64(len(leaves)), Root: tlog.Root(leaves)}
	raw, err := checkpoint.SignLog(c, l.cfg.Signer)
	if err != nil {
		return nil, err
	}
	var cosigs []byte
	var status []WitnessStatus
	for _, w := range l.cfg.Witnesses {
		st := WitnessStatus{Name: w.Key.Name, Attempts: l.cfg.Now().UTC().Format(time.RFC3339)}
		lines, err := l.submit(ctx, w, c.Size, leaves, raw)
		if err == nil {
			s, _ := checkpoint.Open(appendLines(raw, lines))
			if s == nil || !s.Cosignatures([]checkpoint.CosignerKey{w.Key})[0].Valid {
				err = errors.New("witness answered without a valid cosignature from its pinned key")
			} else {
				for _, line := range lines {
					if line.Name == w.Key.Name && line.KeyID == w.Key.ID {
						cosigs = append(cosigs, line.String()...)
					}
				}
			}
		}
		if err != nil {
			st.Error = err.Error()
		} else {
			st.OK = true
		}
		st.Held = l.held[w.Key.Name]
		status = append(status, st)
	}
	full := append(raw, cosigs...)
	if err := writeAtomic(filepath.Join(l.cfg.PublicDir, "checkpoints", strconv.FormatUint(c.Size, 10)), full); err != nil {
		return status, err
	}
	if err := writeAtomic(filepath.Join(l.cfg.PublicDir, "checkpoint"), full); err != nil {
		return status, err
	}
	if b, err := json.MarshalIndent(l.held, "", "  "); err == nil {
		if err := writeAtomic(filepath.Join(l.cfg.DataDir, "witness-state.json"), b); err != nil {
			return status, err
		}
	}
	b, _ := json.MarshalIndent(map[string]any{"checkpoint_size": c.Size, "witnesses": status}, "", "  ")
	return status, writeAtomic(filepath.Join(l.cfg.PublicDir, "status.json"), b)
}

func (l *Log) submit(ctx context.Context, w Witness, size uint64, leaves []tlog.Hash, raw []byte) ([]checkpoint.SigLine, error) {
	for attempt := 0; attempt < 2; attempt++ {
		old := l.held[w.Key.Name]
		if old > size {
			return nil, fmt.Errorf("witness holds size %d, larger than this log (%d): the log lost records", old, size)
		}
		proof, err := tlog.ProveConsistency(leaves[:size], old)
		if err != nil {
			return nil, err
		}
		lines, err := checkpoint.AddCheckpoint(ctx, l.cfg.HTTP, w.URL, old, proof, raw)
		var ce *checkpoint.ConflictError
		if errors.As(err, &ce) {
			l.held[w.Key.Name] = ce.Size
			continue
		}
		if err != nil {
			return nil, err
		}
		l.held[w.Key.Name] = size
		return lines, nil
	}
	return nil, errors.New("witness state kept changing")
}

func appendLines(raw []byte, lines []checkpoint.SigLine) []byte {
	out := append([]byte(nil), raw...)
	for _, l := range lines {
		out = append(out, l.String()...)
	}
	return out
}

func (l *Log) writeDescriptor() error {
	type wd struct {
		Name               string `json:"name"`
		Key                string `json:"key"`
		URL                string `json:"url"`
		OperatorControlled bool   `json:"operator_controlled"`
	}
	var ws []wd
	for _, w := range l.cfg.Witnesses {
		ws = append(ws, wd{w.Key.Name, w.Key.String(), w.URL, w.OperatorControlled})
	}
	b, err := json.MarshalIndent(map[string]any{
		"format":    Format,
		"origin":    l.cfg.Signer.Name(),
		"log_key":   l.cfg.VerifierKey,
		"witnesses": ws,
		"leaf":      "SHA-256(0x00 || records.jsonl line without its newline), RFC 6962 tree",
		"data":      "plaintext; synthetic or explicitly authorised non-sensitive data only",
		"notice":    "Informational. A verifier must take the log and witness keys from a trusted channel, not from this file.",
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(l.cfg.PublicDir, "log.json"), b)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
