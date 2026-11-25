// Package verify is the standalone pilot verifier. It needs only public
// material: the log's public directory (local path or URL) and public keys
// pinned by the evaluator. It never needs or reads a private key.
//
// Every run ends in exactly one of three results:
//
//	VERIFIED      every check passed
//	FAILED        evidence is provably wrong: altered, missing, rolled back,
//	              forged, or signed by the wrong key
//	UNVERIFIABLE  the verifier could not establish the result: an input could
//	              not be fetched, the witness quorum is not met, or the newest
//	              cosignature is older than the freshness bound
//
// UNVERIFIABLE is never reported as success.
package verify

import (
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
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
	"golang.org/x/mod/sumdb/note"
)

// Status is a check or overall result.
type Status string

// The three results.
const (
	Verified     Status = "VERIFIED"
	Failed       Status = "FAILED"
	Unverifiable Status = "UNVERIFIABLE"
)

// MaxClockSkew is how far in the future a cosignature timestamp may be.
const MaxClockSkew = 5 * time.Minute

// Options are the evaluator's inputs.
type Options struct {
	Source             string // public directory: a path, or an http(s) URL
	LogKey             string // pinned log verifier key
	WitnessKeys        []checkpoint.CosignerKey
	OperatorControlled map[string]bool // witness names run by the log operator
	Quorum             int
	MaxAge             time.Duration
	StatePath          string // optional: the last checkpoint this evaluator verified
	Now                func() time.Time
	HTTP               *http.Client
	MaxBytes           int64 // bound on records.jsonl
}

// Check is one line of the result.
type Check struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  Status `json:"status"`
	Detail  string `json:"detail"`
	Warning string `json:"warning,omitempty"`
}

// WitnessResult is one pinned witness's outcome.
type WitnessResult struct {
	Name               string `json:"name"`
	Key                string `json:"key"`
	OperatorControlled bool   `json:"operator_controlled"`
	Present            bool   `json:"present"`
	Valid              bool   `json:"valid"`
	Fresh              bool   `json:"fresh"`
	Timestamp          string `json:"timestamp,omitempty"`
	Error              string `json:"error,omitempty"`
}

// Completeness summarises what the records say about missing or repeated
// input. It never changes the result: completeness is disclosed, not proven.
type Completeness struct {
	Events          int            `json:"events"`
	Rejected        int            `json:"rejected_lines"`
	LogNotices      []string       `json:"log_notices,omitempty"`
	BySource        map[string]int `json:"events_by_source,omitempty"`
	Batches         int            `json:"batches"`
	IncompleteBatch []string       `json:"incomplete_batches,omitempty"`
	DuplicateBatch  []string       `json:"duplicate_batch_entries,omitempty"`
	SequenceGaps    []string       `json:"sequence_gaps,omitempty"`
	SequenceRepeats []string       `json:"sequence_repeats,omitempty"`
	Uncheckpointed  uint64         `json:"records_after_checkpoint"`
}

// Result is the whole outcome, also the report's data.
type Result struct {
	Overall      Status          `json:"result"`
	Summary      string          `json:"summary"`
	Checks       []Check         `json:"checks"`
	Origin       string          `json:"origin,omitempty"`
	Size         uint64          `json:"checkpoint_size"`
	Root         string          `json:"checkpoint_root,omitempty"`
	Witnesses    []WitnessResult `json:"witnesses"`
	Completeness Completeness    `json:"completeness"`
	Disclosures  []string        `json:"disclosures"`
	Manifest     Manifest        `json:"manifest"`
}

// Manifest records exactly what was checked and with what.
type Manifest struct {
	Source         string            `json:"source"`
	VerifiedAt     string            `json:"verified_at"`
	Verifier       string            `json:"verifier"`
	LogKey         string            `json:"pinned_log_key"`
	WitnessKeys    []string          `json:"pinned_witness_keys"`
	Quorum         int               `json:"quorum"`
	MaxAge         string            `json:"max_checkpoint_age"`
	PriorState     string            `json:"prior_state,omitempty"`
	InputSHA256    map[string]string `json:"input_sha256"`
	CheckpointText string            `json:"checkpoint_note,omitempty"`
}

// State is what an evaluator keeps between runs to detect rollback and
// rewritten history.
type State struct {
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"`
	At     string `json:"verified_at"`
}

func (r *Result) add(id, title string, s Status, detail string) *Check {
	r.Checks = append(r.Checks, Check{ID: id, Title: title, Status: s, Detail: detail})
	return &r.Checks[len(r.Checks)-1]
}

// Run verifies. It does not return an error: every problem is a check.
func Run(ctx context.Context, o Options) *Result {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 2 << 30
	}
	now := o.Now()
	r := &Result{Disclosures: baseDisclosures()}
	r.Manifest = Manifest{
		Source: o.Source, VerifiedAt: now.UTC().Format(time.RFC3339), Verifier: version(),
		LogKey: o.LogKey, Quorum: o.Quorum, MaxAge: o.MaxAge.String(), PriorState: o.StatePath,
		InputSHA256: map[string]string{},
	}
	for _, k := range o.WitnessKeys {
		r.Manifest.WitnessKeys = append(r.Manifest.WitnessKeys, k.String())
	}
	defer r.finish()

	// 1. Checkpoint.
	raw, err := fetch(ctx, o, "checkpoint", 64<<10)
	if err != nil {
		r.add("checkpoint.fetch", "Checkpoint available", Unverifiable, err.Error())
		return r
	}
	r.Manifest.InputSHA256["checkpoint"] = sha(raw)
	r.Manifest.CheckpointText = string(raw)
	s, err := checkpoint.Open(raw)
	if err != nil {
		r.add("checkpoint.parse", "Checkpoint well formed", Failed, err.Error())
		return r
	}
	c := s.Checkpoint
	r.Origin, r.Size, r.Root = c.Origin, c.Size, hex.EncodeToString(c.Root[:])
	v, err := note.NewVerifier(o.LogKey)
	if err != nil {
		r.add("checkpoint.log_key", "Pinned log key usable", Unverifiable, err.Error())
		return r
	}
	if c.Origin != v.Name() {
		r.add("checkpoint.origin", "Checkpoint is for the pinned log", Failed, fmt.Sprintf("checkpoint origin %q, pinned log %q", c.Origin, v.Name()))
		return r
	}
	if err := s.VerifyLog(o.LogKey); err != nil {
		r.add("checkpoint.log_signature", "Checkpoint signed by the pinned log key", Failed, err.Error())
		return r
	}
	r.add("checkpoint.log_signature", "Checkpoint signed by the pinned log key", Verified, fmt.Sprintf("%s, size %d", c.Origin, c.Size))

	// 2. Witness cosignatures: quorum and freshness.
	r.witnesses(s, o, now)

	// 3. Records reproduce the checkpoint.
	recs, err := fetch(ctx, o, "records.jsonl", o.MaxBytes)
	if err != nil {
		r.add("records.fetch", "Records available", Unverifiable, err.Error())
		return r
	}
	r.Manifest.InputSHA256["records.jsonl"] = sha(recs)
	leaves, parsed, ok := r.records(recs, c)
	if !ok {
		return r
	}

	// 4. Consistency with what this evaluator verified before.
	r.prior(o, c, leaves)

	// 5. Completeness (disclosed, never part of the pass/fail).
	r.completeness(parsed, c.Size)

	if o.StatePath != "" && r.overall() == Verified {
		b, _ := json.MarshalIndent(State{Origin: c.Origin, Size: c.Size, Root: hex.EncodeToString(c.Root[:]), At: now.UTC().Format(time.RFC3339)}, "", "  ")
		if err := os.WriteFile(o.StatePath, b, 0o644); err != nil {
			r.add("state.save", "Verified checkpoint saved for the next run", Unverifiable, err.Error())
		}
	}
	return r
}

func (r *Result) witnesses(s *checkpoint.Signed, o Options, now time.Time) {
	got := s.Cosignatures(o.WitnessKeys)
	fresh, independent, valid := 0, 0, 0
	var newest time.Time
	for _, g := range got {
		w := WitnessResult{Name: g.Key.Name, Key: g.Key.String(), OperatorControlled: o.OperatorControlled[g.Key.Name], Present: g.Present, Valid: g.Valid, Error: g.Err}
		if g.Present && !g.Valid {
			r.add("witness."+g.Key.Name, "Cosignature from "+g.Key.Name, Failed, "a signature line carries this witness's key ID but does not verify: forged or corrupted ("+g.Err+")")
		}
		if g.Valid {
			valid++
			ts := time.Unix(int64(g.Timestamp), 0)
			w.Timestamp = ts.UTC().Format(time.RFC3339)
			switch {
			case ts.After(now.Add(MaxClockSkew)):
				w.Error = "timestamp is in the future"
			case now.Sub(ts) > o.MaxAge:
				w.Error = fmt.Sprintf("stale: cosigned %s ago, bound %s", now.Sub(ts).Round(time.Second), o.MaxAge)
			default:
				w.Fresh = true
				fresh++
				if !w.OperatorControlled {
					independent++
				}
				if ts.After(newest) {
					newest = ts
				}
			}
		}
		r.Witnesses = append(r.Witnesses, w)
	}
	title := fmt.Sprintf("Witness quorum (%d of %d pinned witnesses, fresh within %s)", o.Quorum, len(o.WitnessKeys), o.MaxAge)
	switch {
	case fresh >= o.Quorum:
		c := r.add("witness.quorum", title, Verified, fmt.Sprintf("%d fresh valid cosignature(s); newest %s", fresh, newest.UTC().Format(time.RFC3339)))
		if independent < o.Quorum {
			c.Warning = "The quorum is met only with witnesses marked as run by the log operator. This demonstrates the protocol; it gives no independence, and the operator could show different histories to different verifiers."
			r.Disclosures = append(r.Disclosures, "THIS RUN: witness quorum met only by operator-controlled witnesses (no independence).")
		}
	case valid > fresh:
		r.add("witness.quorum", title, Unverifiable, fmt.Sprintf("only %d fresh valid cosignature(s), %d stale or future-dated: the checkpoint may be outdated or withheld", fresh, valid-fresh))
	default:
		r.add("witness.quorum", title, Unverifiable, fmt.Sprintf("%d fresh valid cosignature(s): witness unavailable, or a checkpoint the witnesses never saw (a possible split view)", fresh))
	}
}

func (r *Result) records(data []byte, c checkpoint.Checkpoint) ([]tlog.Hash, []map[string]json.RawMessage, bool) {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = data[:bytes.LastIndexByte(data, '\n')+1] // a partial line being written is not a record yet
	}
	var leaves []tlog.Hash
	var parsed []map[string]json.RawMessage
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(data) == 0 {
			break
		}
		leaves = append(leaves, tlog.HashLeaf(line))
		var m map[string]json.RawMessage
		if json.Unmarshal(line, &m) != nil {
			m = nil
		}
		parsed = append(parsed, m)
	}
	n := uint64(len(leaves))
	if n < c.Size {
		r.add("records.count", "Every checkpointed record present", Failed, fmt.Sprintf("the checkpoint commits to %d records; the source has %d: evidence deleted or truncated", c.Size, n))
		return nil, nil, false
	}
	if tlog.Root(leaves[:c.Size]) != c.Root {
		r.add("records.root", "Records reproduce the checkpoint root", Failed, "the records do not hash to the signed root: a record was modified, inserted, removed or reordered"+locate(parsed[:c.Size]))
		return nil, nil, false
	}
	for i := uint64(0); i < c.Size; i++ {
		var seq uint64
		if parsed[i] == nil || json.Unmarshal(parsed[i]["seq"], &seq) != nil || seq != i {
			r.add("records.sequence", "Record sequence numbers", Failed, fmt.Sprintf("record %d is signed into the log but its seq field is wrong or missing: the log itself wrote a bad record", i))
			return nil, nil, false
		}
	}
	r.add("records.root", "Records reproduce the checkpoint root", Verified, fmt.Sprintf("%d records hash to the signed root", c.Size))
	return leaves, parsed, true
}

// locate names the first record whose seq does not match its position, a
// hint for the evaluator; the root mismatch is the proof.
func locate(parsed []map[string]json.RawMessage) string {
	seen := map[uint64]bool{}
	for i, m := range parsed {
		var seq uint64
		if m == nil || json.Unmarshal(m["seq"], &seq) != nil {
			return fmt.Sprintf(" (record %d is not a valid record)", i)
		}
		if seen[seq] {
			return fmt.Sprintf(" (record seq %d appears twice: a replayed record)", seq)
		}
		seen[seq] = true
		if seq != uint64(i) {
			return fmt.Sprintf(" (first out-of-place record at line %d, seq %d)", i+1, seq)
		}
	}
	return ""
}

func (r *Result) prior(o Options, c checkpoint.Checkpoint, leaves []tlog.Hash) {
	if o.StatePath == "" {
		r.add("history.prior", "Consistent with this evaluator's previous verification", Verified, "no previous state given (first run): rollback and rewrite are checked from the next run on, if --state is kept")
		r.Checks[len(r.Checks)-1].Warning = "First run: no earlier checkpoint to compare with."
		return
	}
	b, err := os.ReadFile(o.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		c := r.add("history.prior", "Consistent with this evaluator's previous verification", Verified, "no state file yet: this run creates it")
		c.Warning = "First run: no earlier checkpoint to compare with."
		return
	}
	var st State
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	if err != nil {
		r.add("history.prior", "Consistent with this evaluator's previous verification", Unverifiable, "state file unreadable: "+fmt.Sprint(err))
		return
	}
	root, err := hex.DecodeString(st.Root)
	if err != nil || len(root) != 32 || st.Origin != c.Origin {
		r.add("history.prior", "Consistent with this evaluator's previous verification", Unverifiable, "state file is for another log or is malformed")
		return
	}
	switch {
	case st.Size > c.Size:
		r.add("history.prior", "Consistent with this evaluator's previous verification", Failed, fmt.Sprintf("rollback: this evaluator verified size %d on %s; the log now shows %d", st.Size, st.At, c.Size))
	case tlog.Root(leaves[:st.Size]) != tlog.Hash(root):
		r.add("history.prior", "Consistent with this evaluator's previous verification", Failed, fmt.Sprintf("history rewritten: the first %d records no longer match the root verified on %s", st.Size, st.At))
	default:
		r.add("history.prior", "Consistent with this evaluator's previous verification", Verified, fmt.Sprintf("extends the checkpoint verified on %s (size %d to %d)", st.At, st.Size, c.Size))
	}
}

func (r *Result) completeness(parsed []map[string]json.RawMessage, size uint64) {
	cp := &r.Completeness
	cp.BySource = map[string]int{}
	cp.Uncheckpointed = uint64(len(parsed)) - size
	type batch struct {
		count int
		seen  map[int]int
	}
	batches := map[string]*batch{}
	lastSeq := map[string]int64{}
	for _, m := range parsed[:size] {
		var kind, rejected, detail string
		_ = json.Unmarshal(m["kind"], &kind)
		_ = json.Unmarshal(m["rejected"], &rejected)
		_ = json.Unmarshal(m["detail"], &detail)
		switch {
		case kind != "":
			cp.LogNotices = append(cp.LogNotices, kind+": "+detail)
			continue
		case rejected != "":
			cp.Rejected++
			continue
		}
		cp.Events++
		var ev struct {
			Source     string `json:"source"`
			Batch      string `json:"batch"`
			BatchIndex *int   `json:"batch_index"`
			BatchCount int    `json:"batch_count"`
			SourceSeq  *int64 `json:"source_seq"`
		}
		_ = json.Unmarshal(m["event"], &ev)
		src := ev.Source
		if src == "" {
			src = "(none)"
		}
		cp.BySource[src]++
		if ev.Batch != "" && ev.BatchIndex != nil {
			b := batches[ev.Batch]
			if b == nil {
				b = &batch{count: ev.BatchCount, seen: map[int]int{}}
				batches[ev.Batch] = b
			}
			b.seen[*ev.BatchIndex]++
		}
		if ev.SourceSeq != nil {
			last, ok := lastSeq[src]
			switch {
			case ok && *ev.SourceSeq == last:
				cp.SequenceRepeats = append(cp.SequenceRepeats, fmt.Sprintf("%s: seq %d repeated", src, last))
			case ok && *ev.SourceSeq > last+1:
				cp.SequenceGaps = append(cp.SequenceGaps, fmt.Sprintf("%s: %d missing between %d and %d", src, *ev.SourceSeq-last-1, last, *ev.SourceSeq))
			case ok && *ev.SourceSeq < last:
				cp.SequenceRepeats = append(cp.SequenceRepeats, fmt.Sprintf("%s: seq went back from %d to %d (redelivery or reset)", src, last, *ev.SourceSeq))
			}
			if !ok || *ev.SourceSeq > last {
				lastSeq[src] = *ev.SourceSeq
			}
		}
	}
	ids := make([]string, 0, len(batches))
	for id := range batches {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	cp.Batches = len(ids)
	for _, id := range ids {
		b := batches[id]
		missing := 0
		var dups []string
		for i := 0; i < b.count; i++ {
			switch n := b.seen[i]; {
			case n == 0:
				missing++
			case n > 1:
				dups = append(dups, fmt.Sprintf("batch %s entry %d recorded %d times", id, i, n))
			}
		}
		if len(dups) == b.count && b.count > 1 {
			cp.DuplicateBatch = append(cp.DuplicateBatch, fmt.Sprintf("batch %s: all %d entries recorded %d times (the whole batch was delivered again)", id, b.count, b.seen[0]))
		} else {
			cp.DuplicateBatch = append(cp.DuplicateBatch, dups...)
		}
		if missing > 0 {
			cp.IncompleteBatch = append(cp.IncompleteBatch, fmt.Sprintf("batch %s: %d of %d entries missing", id, missing, b.count))
		}
	}
	title := "Completeness indicators (disclosed, not proven)"
	detail := fmt.Sprintf("%d events, %d rejected lines, %d batches; %d incomplete batches, %d duplicate-delivery findings, %d sequence gaps, %d repeats; %d records after the checkpoint not yet covered",
		cp.Events, cp.Rejected, cp.Batches, len(cp.IncompleteBatch), len(cp.DuplicateBatch), len(cp.SequenceGaps), len(cp.SequenceRepeats), cp.Uncheckpointed)
	c := r.add("completeness", title, Verified, detail)
	if len(cp.IncompleteBatch)+len(cp.DuplicateBatch)+len(cp.SequenceGaps)+len(cp.SequenceRepeats)+cp.Rejected+len(cp.LogNotices) > 0 {
		c.Warning = "The log is intact, but its input shows gaps, repeats, rejected lines or log notices. See the completeness section."
	}
}

func (r *Result) overall() Status {
	s := Verified
	for _, c := range r.Checks {
		switch c.Status {
		case Failed:
			return Failed
		case Unverifiable:
			s = Unverifiable
		}
	}
	return s
}

func (r *Result) finish() {
	r.Overall = r.overall()
	for _, c := range r.Checks {
		if c.Status == r.Overall && r.Overall != Verified {
			r.Summary = c.Title + ": " + c.Detail
			return
		}
	}
	r.Summary = fmt.Sprintf("%d records of %s verified against a pinned log key and witness quorum", r.Size, r.Origin)
	for _, c := range r.Checks {
		if c.Warning != "" && c.ID == "witness.quorum" {
			r.Summary += " (witness NOT independent)"
		}
	}
}

func baseDisclosures() []string {
	return []string{
		"Completeness: the log proves that what it received is unaltered. It cannot prove that it received everything the source emitted.",
		"Truth of content: a record proves only that the log received this payload, not that the event it describes happened.",
		"Operator: the log operator holds the log signing key. Witnesses stop the operator from showing different histories to different verifiers only up to the witness quorum: the operator plus that many colluding witnesses could still do so.",
		"Time: record times are the log host's clock. A cosignature timestamp bounds when a checkpoint existed, not when an event happened.",
		"Keys: the pilot uses software keys on the log host; anyone with root there can sign as the log. Hardware key custody is not part of the pilot.",
		"Scope: this is a pilot evaluation, not a certification. It makes no Proof-of-Control Tier 3 or Tier 4 claim and no production security guarantee.",
	}
}

func fetch(ctx context.Context, o Options, name string, max int64) ([]byte, error) {
	if strings.HasPrefix(o.Source, "http://") || strings.HasPrefix(o.Source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(o.Source, "/")+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		resp, err := o.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: HTTP %d", name, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err == nil && int64(len(b)) > max {
			err = fmt.Errorf("%s: larger than %d bytes", name, max)
		}
		return b, err
	}
	f, err := os.Open(filepath.Join(o.Source, name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s: larger than %d bytes", name, max)
	}
	return b, err
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		v := bi.Main.Version
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				v += " " + s.Value
			}
		}
		return "harborlight-verify " + v
	}
	return "harborlight-verify (unknown build)"
}
