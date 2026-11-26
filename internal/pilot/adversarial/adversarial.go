// Package adversarial is the pilot's re-runnable adversarial regression
// suite. Each case builds an honest log with the real log code, attacks it
// the way an operator, a network attacker or a failure would, runs the real
// verifier, and compares the result with the expected one.
//
// It runs in CI (go test) and on an evaluator's machine
// (harborlight-adversarial), against an in-process tlog-witness by default.
package adversarial

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/evlog"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor/rekortest"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/testwitness"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/verify"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
	"golang.org/x/mod/sumdb/note"
)

const origin = "pilot.example/adversarial-log"

// Case is one scenario.
type Case struct {
	ID, Attack, Expect string
	Run                func(e *Env) (*verify.Result, error)
	ExpectStatus       verify.Status
	// KnownLimit marks an attack the pilot does not stop under the stated
	// conditions. The case pins that behaviour so it stays documented; it
	// passes when the verifier behaves as disclosed, not when it is safe.
	KnownLimit bool
}

// Outcome is a case's result.
type Outcome struct {
	ID         string        `json:"id"`
	Attack     string        `json:"attack"`
	Expect     verify.Status `json:"expected"`
	Got        verify.Status `json:"got"`
	Pass       bool          `json:"pass"`
	KnownLimit bool          `json:"known_limit,omitempty"`
	Summary    string        `json:"verifier_summary"`
}

// Env is a fresh honest deployment for one case.
type Env struct {
	Dir     string
	Signer  note.Signer
	VKey    string
	Witness *testwitness.Witness
	srv     *httptest.Server
	Rekor   *rekortest.Server
	rekor   *httptest.Server
	Anchor  *ecdsa.PrivateKey
	Log     *evlog.Log
	cfg     evlog.Config
	State   string
	Now     time.Time
}

func newEnv(dir string) (*Env, error) {
	skey, vkey, err := note.GenerateKey(nil, origin)
	if err != nil {
		return nil, err
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, err
	}
	w := testwitness.New("pilot.example/adversarial-witness")
	w.AddLog(origin, vkey)
	e := &Env{Dir: dir, Signer: signer, VKey: vkey, Witness: w, srv: httptest.NewServer(w), State: filepath.Join(dir, "evaluator-state.json"), Now: time.Now()}
	// Every environment anchors in an in-process Rekor stand-in; the
	// verifier checks anchors only in the cases that pin the Rekor keys.
	e.Rekor = rekortest.New()
	e.rekor = httptest.NewServer(e.Rekor)
	priv, _, err := rekor.GenerateKey()
	if err != nil {
		return nil, err
	}
	if e.Anchor, err = rekor.ParsePrivateKey(priv); err != nil {
		return nil, err
	}
	e.cfg = evlog.Config{DataDir: filepath.Join(dir, "data"), PublicDir: filepath.Join(dir, "public"), Signer: signer, VerifierKey: vkey,
		Witnesses: []evlog.Witness{{URL: e.srv.URL, Key: w.Key()}},
		Anchor:    &evlog.AnchorConfig{URL: e.rekor.URL, Key: e.Anchor}}
	e.Log, err = evlog.Open(e.cfg)
	if err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Env) close() {
	if e.Log != nil {
		e.Log.Close()
	}
	e.srv.Close()
	e.rekor.Close()
}

// pinRekor pins the Rekor and anchoring keys; online also searches Rekor.
func (e *Env) pinRekor(online bool) func(*verify.Options) {
	return func(o *verify.Options) {
		o.RekorKey, o.AnchorKey = e.Rekor.Public(), &e.Anchor.PublicKey
		if online {
			o.RekorURL = e.rekor.URL
		}
	}
}

// collude rewrites record 3 in a copy of the public directory, re-signs it
// with the real log key, and cosigns it with the witness's own private key:
// the log operator and the witness acting together. With reanchor, the
// rewritten checkpoint is also anchored in Rekor with the real anchoring
// key and anchor.json is replaced.
func (e *Env) collude(reanchor bool) (string, error) {
	d, err := e.editRecords(func(l [][]byte) [][]byte {
		l[3] = bytes.Replace(l[3], []byte(`"allow"`), []byte(`"block"`), 1)
		return l
	})
	if err != nil {
		return "", err
	}
	ls, err := lines(d)
	if err != nil {
		return "", err
	}
	var leaves []tlog.Hash
	for _, l := range ls {
		leaves = append(leaves, tlog.HashLeaf(bytes.TrimSuffix(l, []byte("\n"))))
	}
	c := checkpoint.Checkpoint{Origin: origin, Size: uint64(len(leaves)), Root: tlog.Root(leaves)}
	raw, err := checkpoint.SignLog(c, e.Signer)
	if err != nil {
		return "", err
	}
	raw = append(raw, checkpoint.Cosign(e.Witness.Key().Name, e.Witness.PrivateKey(), c.Text(), uint64(e.Now.Unix())).String()...)
	if err := os.WriteFile(filepath.Join(d, "checkpoint"), raw, 0o644); err != nil {
		return "", err
	}
	if reanchor {
		uuid, entry, err := rekor.Upload(context.Background(), nil, e.rekor.URL, rekor.Digest(c.Text()), e.Anchor)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(rekor.Anchor{Format: rekor.AnchorFormat, Size: c.Size, Rekor: e.rekor.URL, UUID: uuid, Entry: entry})
		if err := os.WriteFile(filepath.Join(d, "anchor.json"), b, 0o644); err != nil {
			return "", err
		}
	}
	return d, nil
}

// Grow appends n synthetic events and checkpoints.
func (e *Env) Grow(n int) error {
	start := int(e.Log.Size())
	var evs []json.RawMessage
	for i := 0; i < n; i++ {
		evs = append(evs, json.RawMessage(fmt.Sprintf(`{"source":"synthetic","source_seq":%d,"action":"allow","path":"/v1/chat/%d"}`, start+i+1, start+i)))
	}
	if err := e.Log.Append(evs...); err != nil {
		return err
	}
	_, err := e.Log.Checkpoint(context.Background())
	return err
}

// Verify runs the verifier on a public directory.
func (e *Env) Verify(public string, mod func(*verify.Options)) *verify.Result {
	o := verify.Options{Source: public, LogKey: e.VKey, WitnessKeys: []checkpoint.CosignerKey{e.Witness.Key()}, Quorum: 1, MaxAge: 10 * time.Minute, StatePath: e.State,
		Now: func() time.Time { return e.Now }}
	if mod != nil {
		mod(&o)
	}
	return verify.Run(context.Background(), o)
}

// Public is the honest public directory.
func (e *Env) Public() string { return e.cfg.PublicDir }

// Copy copies the public directory to a new attacker-controlled one.
func (e *Env) Copy() (string, error) {
	dst := filepath.Join(e.Dir, fmt.Sprintf("attacked-%d", time.Now().UnixNano()))
	return dst, filepath.Walk(e.cfg.PublicDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(e.cfg.PublicDir, p)
		if fi.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

func lines(dir string) ([][]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, "records.jsonl"))
	if err != nil {
		return nil, err
	}
	return bytes.SplitAfter(b, []byte("\n"))[:bytes.Count(b, []byte("\n"))], nil
}

func writeLines(dir string, ls [][]byte) error {
	return os.WriteFile(filepath.Join(dir, "records.jsonl"), bytes.Join(ls, nil), 0o644)
}

// editRecords copies the public dir and edits its record lines.
func (e *Env) editRecords(f func([][]byte) [][]byte) (string, error) {
	dst, err := e.Copy()
	if err != nil {
		return "", err
	}
	ls, err := lines(dst)
	if err != nil {
		return "", err
	}
	return dst, writeLines(dst, f(ls))
}

// resign rebuilds a checkpoint over the attacker's records with the real
// log key (a malicious operator) and asks the real witness to cosign it.
func (e *Env) resign(dir string) error {
	ls, err := lines(dir)
	if err != nil {
		return err
	}
	var leaves []tlog.Hash
	for _, l := range ls {
		leaves = append(leaves, tlog.HashLeaf(bytes.TrimSuffix(l, []byte("\n"))))
	}
	c := checkpoint.Checkpoint{Origin: origin, Size: uint64(len(leaves)), Root: tlog.Root(leaves)}
	raw, err := checkpoint.SignLog(c, e.Signer)
	if err != nil {
		return err
	}
	old := e.Witness.Held(origin)
	if old <= c.Size {
		p, _ := tlog.ProveConsistency(leaves, old)
		body, _ := checkpoint.AddCheckpointBody(old, p, raw)
		if line, status, _ := e.Witness.Add(body); status == 200 {
			raw = append(raw, line...)
		}
	}
	return os.WriteFile(filepath.Join(dir, "checkpoint"), raw, 0o644)
}

// Cases is the suite.
func Cases() []Case {
	honest := func(e *Env) (*verify.Result, error) { return e.Verify(e.Public(), nil), nil }
	edit := func(f func([][]byte) [][]byte) func(*Env) (*verify.Result, error) {
		return func(e *Env) (*verify.Result, error) {
			d, err := e.editRecords(f)
			if err != nil {
				return nil, err
			}
			return e.Verify(d, nil), nil
		}
	}
	return []Case{
		{ID: "A01-baseline", Attack: "none: honest log, fresh witness cosignature", ExpectStatus: verify.Verified, Run: honest},
		{ID: "A02-modify", Attack: "change one field of one record", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte {
			l[7] = bytes.Replace(l[7], []byte(`"allow"`), []byte(`"block"`), 1)
			return l
		})},
		{ID: "A03-insert", Attack: "insert a fabricated record", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte {
			fake := []byte(`{"seq":5,"received":"2026-01-01T00:00:00Z","feed_end":0,"event":{"source":"synthetic","action":"allow"}}` + "\n")
			return append(l[:5], append([][]byte{fake}, l[5:]...)...)
		})},
		{ID: "A04-delete", Attack: "delete one record from the middle", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte { return append(l[:4], l[5:]...) })},
		{ID: "A05-reorder", Attack: "swap two records", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte { l[2], l[3] = l[3], l[2]; return l })},
		{ID: "A06-replay", Attack: "replay (duplicate) a record in place of another", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte { l[6] = l[5]; return l })},
		{ID: "A07-truncate", Attack: "drop the newest checkpointed records", ExpectStatus: verify.Failed, Run: edit(func(l [][]byte) [][]byte { return l[:len(l)-3] })},
		{ID: "A08-rewrite-resign-first-look", Attack: "operator rewrites a record and re-signs with the real log key; evaluator has no earlier state", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.editRecords(func(l [][]byte) [][]byte {
				l[3] = bytes.Replace(l[3], []byte(`"allow"`), []byte(`"block"`), 1)
				return l
			})
			if err != nil {
				return nil, err
			}
			if err := e.resign(d); err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = "" }), nil
		}},
		{ID: "A09-rewrite-resign-known", Attack: "the same rewrite, shown to an evaluator who verified the honest log before", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			if r := e.Verify(e.Public(), nil); r.Overall != verify.Verified {
				return r, nil
			}
			d, err := e.editRecords(func(l [][]byte) [][]byte {
				l[3] = bytes.Replace(l[3], []byte(`"allow"`), []byte(`"block"`), 1)
				return l
			})
			if err != nil {
				return nil, err
			}
			if err := e.resign(d); err != nil {
				return nil, err
			}
			return e.Verify(d, nil), nil
		}},
		{ID: "A10-split-view", Attack: "two histories: evaluator A gets the honest one, evaluator B a fork signed by the log key; the witness refuses the fork", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			if r := e.Verify(e.Public(), func(o *verify.Options) { o.StatePath = "" }); r.Overall != verify.Verified {
				return r, nil
			}
			d, err := e.editRecords(func(l [][]byte) [][]byte {
				return append(l[:6], []byte(`{"seq":6,"received":"2026-01-01T00:00:00Z","feed_end":0,"event":{"source":"synthetic","action":"forked"}}`+"\n"))
			})
			if err != nil {
				return nil, err
			}
			if err := e.resign(d); err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = filepath.Join(e.Dir, "evaluator-b.json") }), nil
		}},
		{ID: "A11-rollback", Attack: "serve an older, genuinely cosigned checkpoint and its records to an evaluator who saw a newer one", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			old, err := e.Copy()
			if err != nil {
				return nil, err
			}
			if err := e.Grow(5); err != nil {
				return nil, err
			}
			if r := e.Verify(e.Public(), nil); r.Overall != verify.Verified {
				return r, nil
			}
			return e.Verify(old, nil), nil
		}},
		{ID: "A12-stale-witness", Attack: "the newest cosignature is older than the evaluator's freshness bound (withheld or frozen checkpoint)", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			return e.Verify(e.Public(), func(o *verify.Options) { o.Now = func() time.Time { return e.Now.Add(2 * time.Hour) } }), nil
		}},
		{ID: "A13-witness-down", Attack: "the witness is unreachable when the log checkpoints", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			e.Witness.Down = true
			if err := e.Grow(3); err != nil {
				return nil, err
			}
			return e.Verify(e.Public(), func(o *verify.Options) { o.StatePath = "" }), nil
		}},
		{ID: "A14-forged-cosignature", Attack: "corrupt the witness cosignature bytes", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.Copy()
			if err != nil {
				return nil, err
			}
			raw, _ := os.ReadFile(filepath.Join(d, "checkpoint"))
			i := bytes.LastIndex(raw, []byte(" "))
			b := append([]byte(nil), raw...)
			if b[i+20] == 'A' {
				b[i+20] = 'B'
			} else {
				b[i+20] = 'A'
			}
			if err := os.WriteFile(filepath.Join(d, "checkpoint"), b, 0o644); err != nil {
				return nil, err
			}
			return e.Verify(d, nil), nil
		}},
		{ID: "A15-wrong-log-key", Attack: "a checkpoint signed by a key other than the pinned log key", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			_, other, _ := note.GenerateKey(nil, origin)
			return e.Verify(e.Public(), func(o *verify.Options) { o.LogKey = other }), nil
		}},
		{ID: "A16-impostor-witness", Attack: "a cosignature from a key that is not the pinned witness key", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			imp := testwitness.New("pilot.example/adversarial-witness")
			return e.Verify(e.Public(), func(o *verify.Options) { o.WitnessKeys = []checkpoint.CosignerKey{imp.Key()} }), nil
		}},
		{ID: "A17-torn-write", Attack: "power cut mid-write: a partial record at the end of the log; the log restarts", ExpectStatus: verify.Verified, Run: func(e *Env) (*verify.Result, error) {
			e.Log.Close()
			f, err := os.OpenFile(filepath.Join(e.Public(), "records.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return nil, err
			}
			_, _ = f.WriteString(`{"seq":20,"received":"2026-`)
			f.Close()
			if e.Log, err = evlog.Open(e.cfg); err != nil {
				return nil, err
			}
			if _, err := e.Log.Checkpoint(context.Background()); err != nil {
				return nil, err
			}
			r := e.Verify(e.Public(), nil)
			if len(r.Completeness.LogNotices) == 0 {
				r.Overall, r.Summary = "MISSING-NOTICE", "the recovery was not recorded as a log notice"
			}
			return r, nil
		}},
		{ID: "A18-evidence-deleted-at-host", Attack: "records under a signed checkpoint deleted on the log host; the log restarts", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			e.Log.Close()
			ls, _ := lines(e.Public())
			_ = writeLines(e.Public(), ls[:len(ls)-2])
			_, err := evlog.Open(e.cfg)
			r := e.Verify(e.Public(), nil)
			if err == nil || !strings.Contains(err.Error(), "refusing to start") {
				r.Overall, r.Summary = "LOG-STARTED", "the log started over deleted evidence"
			}
			e.Log = nil
			return r, nil
		}},
		{ID: "A19-flood", Attack: "garbage and oversized input lines on the feed", ExpectStatus: verify.Verified, Run: func(e *Env) (*verify.Result, error) {
			feed := filepath.Join(e.Dir, "feed.jsonl")
			var b bytes.Buffer
			for i := 0; i < 500; i++ {
				b.WriteString("garbage line\n")
			}
			b.WriteString(`{"big":"` + strings.Repeat("x", 200<<10) + `"}` + "\n")
			b.WriteString(`{"source":"synthetic","action":"allow"}` + "\n")
			_ = os.WriteFile(feed, b.Bytes(), 0o644)
			if _, err := e.Log.Ingest(feed); err != nil {
				return nil, err
			}
			if _, err := e.Log.Checkpoint(context.Background()); err != nil {
				return nil, err
			}
			r := e.Verify(e.Public(), nil)
			if r.Completeness.Rejected != 501 {
				r.Overall, r.Summary = "WRONG-COUNT", fmt.Sprintf("%d rejected lines recorded, want 501", r.Completeness.Rejected)
			}
			return r, nil
		}},
		{ID: "A20-source-unreachable", Attack: "the public directory cannot be fetched", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			return e.Verify(filepath.Join(e.Dir, "does-not-exist"), nil), nil
		}},
		{ID: "A21-records-withheld", Attack: "checkpoint served, records file withheld", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.Copy()
			if err != nil {
				return nil, err
			}
			if err := os.Remove(filepath.Join(d, "records.jsonl")); err != nil {
				return nil, err
			}
			return e.Verify(d, nil), nil
		}},
		{ID: "A22-anchored-baseline", Attack: "none: honest log, Rekor keys pinned, every anchor checked online", ExpectStatus: verify.Verified, Run: func(e *Env) (*verify.Result, error) {
			r := e.Verify(e.Public(), e.pinRekor(true))
			if r.Anchor == nil || r.Anchor.Size != 20 {
				r.Overall, r.Summary = "NO-ANCHOR", "the honest anchor was not reported"
			}
			return r, nil
		}},
		{ID: "A23-collusion-without-anchor", KnownLimit: true, Attack: "KNOWN LIMIT: log operator and witness collude to rewrite a record; a first-time evaluator without the Rekor pins accepts it", ExpectStatus: verify.Verified, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.collude(false)
			if err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = "" }), nil
		}},
		{ID: "A24-collusion-anchor-offline", Attack: "the same collusion; the evaluator pins the Rekor keys (offline check of the latest anchor)", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.collude(false)
			if err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = ""; e.pinRekor(false)(o) }), nil
		}},
		{ID: "A25-collusion-reanchor-offline", KnownLimit: true, Attack: "KNOWN LIMIT: the colluders also anchor the rewrite in Rekor with the real anchoring key; an offline check sees only the new anchor", ExpectStatus: verify.Verified, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.collude(true)
			if err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = ""; e.pinRekor(false)(o) }), nil
		}},
		{ID: "A26-collusion-reanchor-online", Attack: "the same re-anchored rewrite; the evaluator searches Rekor for every anchor by the anchoring key", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.collude(true)
			if err != nil {
				return nil, err
			}
			return e.Verify(d, func(o *verify.Options) { o.StatePath = ""; e.pinRekor(true)(o) }), nil
		}},
		{ID: "A27-forged-anchor", Attack: "corrupt Rekor's signed entry timestamp in anchor.json", ExpectStatus: verify.Failed, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.Copy()
			if err != nil {
				return nil, err
			}
			p := filepath.Join(d, "anchor.json")
			var a rekor.Anchor
			b, _ := os.ReadFile(p)
			if err := json.Unmarshal(b, &a); err != nil {
				return nil, err
			}
			var en rekor.Entry
			if err := json.Unmarshal(a.Entry, &en); err != nil {
				return nil, err
			}
			set, _ := base64.StdEncoding.DecodeString(en.Verification.SignedEntryTimestamp)
			set[len(set)-1] ^= 1
			en.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(set)
			a.Entry, _ = json.Marshal(en)
			b, _ = json.Marshal(a)
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return nil, err
			}
			return e.Verify(d, e.pinRekor(false)), nil
		}},
		{ID: "A28-anchor-withheld", Attack: "anchor.json withheld from an evaluator who pinned the Rekor keys", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			d, err := e.Copy()
			if err != nil {
				return nil, err
			}
			if err := os.Remove(filepath.Join(d, "anchor.json")); err != nil {
				return nil, err
			}
			return e.Verify(d, e.pinRekor(false)), nil
		}},
		{ID: "A29-rekor-unreachable", Attack: "Rekor is down when the evaluator searches it", ExpectStatus: verify.Unverifiable, Run: func(e *Env) (*verify.Result, error) {
			e.Rekor.Down = true
			return e.Verify(e.Public(), e.pinRekor(true)), nil
		}},
	}
}

// Run executes every case in a fresh environment under dir.
func Run(dir string) ([]Outcome, error) {
	var out []Outcome
	for _, c := range Cases() {
		d := filepath.Join(dir, c.ID)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
		e, err := newEnv(d)
		if err != nil {
			return nil, err
		}
		if err := e.Grow(20); err != nil {
			e.close()
			return nil, err
		}
		r, err := c.Run(e)
		e.close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		out = append(out, Outcome{ID: c.ID, Attack: c.Attack, Expect: c.ExpectStatus, Got: r.Overall, Pass: r.Overall == c.ExpectStatus, KnownLimit: c.KnownLimit, Summary: r.Summary})
	}
	return out, nil
}
