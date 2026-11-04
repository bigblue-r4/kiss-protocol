package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

type keySigner struct{ priv ed25519.PrivateKey }

func (k keySigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(k.priv, m), nil }
func (k keySigner) PublicKey() ed25519.PublicKey  { return k.priv.Public().(ed25519.PublicKey) }

func newSigner(seed byte) keySigner {
	return keySigner{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))}
}

var logKey = bytes.Repeat([]byte{7}, 32)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// buildLog writes a witness log of n routine records into dir, signed by s
// (nil: MAC only, as an unsigned witness writes), and returns the open store.
func buildLog(t *testing.T, dir string, s keySigner, n int, tag string) *store.Store {
	t.Helper()
	var st *store.Store
	var err error
	if s.priv == nil {
		st, err = store.Open(dir, logKey, nil)
	} else {
		st, err = store.Open(dir, logKey, s)
	}
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := st.Append("INFO", "drift_clean", "drift", map[string]string{"tag": tag, "i": fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// overwrite replaces the witness files in dst with those from src, as an
// attacker with root on the witness host could.
func overwrite(t *testing.T, src, dst string) {
	t.Helper()
	for _, f := range []string{"witness.log", "tree-head.json"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, f), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func newView(t *testing.T, dir string, pins []ed25519.PublicKey, c *clock, priors ...store.TreeHead) *View {
	t.Helper()
	v, err := New(Config{Dir: dir, Key: logKey, Pins: pins, Now: c.Now, Priors: priors})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustChain(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, ErrChainUnverified) {
		t.Fatalf("%s: err = %v, want CHAIN_UNVERIFIED", what, err)
	}
}

// mustReason is mustChain plus the check that it failed for the intended
// reason, so a test cannot pass on an incidental error.
func mustReason(t *testing.T, err error, what, reason string) {
	t.Helper()
	mustChain(t, err, what)
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("%s: failed for the wrong reason: %v (want %q)", what, err, reason)
	}
}

// forge writes entries as a witness log, frame by frame exactly as the
// witness does, with a head signed by s. It is how an attacker holding the
// machine key (and possibly a signing key) rewrites a log so that every
// record keeps its byte length and the gate's read offset stays aligned.
func forge(t *testing.T, dir string, entries []store.Entry, s keySigner) {
	t.Helper()
	var log []byte
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		plain, _ := json.Marshal(e)
		sealed, err := encrypt.Seal(plain, logKey)
		if err != nil {
			t.Fatal(err)
		}
		log = binary.BigEndian.AppendUint32(log, uint32(len(sealed)))
		log = append(log, sealed...)
		leaves[i] = store.LeafHash(e)
	}
	root := merkle.Root(leaves)
	msg := binary.BigEndian.AppendUint64(nil, uint64(len(entries)))
	msg = append(msg, root[:]...)
	sig, _ := s.Sign(msg)
	head, _ := json.Marshal(store.TreeHead{Size: uint64(len(entries)), Root: hex.EncodeToString(root[:]),
		Timestamp: time.Now().UTC().Format(time.RFC3339), MAC: strings.Repeat("00", 32),
		Signature: hex.EncodeToString(sig), SignerKey: hex.EncodeToString(s.PublicKey())})
	if err := os.WriteFile(filepath.Join(dir, "witness.log"), log, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tree-head.json"), head, 0600); err != nil {
		t.Fatal(err)
	}
}

// grown returns the dir's records plus n more, optionally with record edit
// (0-based) changed to an equal-length different value.
func grown(t *testing.T, dir string, n, edit int) []store.Entry {
	t.Helper()
	es, err := store.ReadAll(dir, logKey)
	if err != nil {
		t.Fatal(err)
	}
	if edit >= 0 {
		es[edit].Data = json.RawMessage(strings.Replace(string(es[edit].Data), "real", "fake", 1))
	}
	last := es[len(es)-1]
	for i := 0; i < n; i++ {
		last.Seq++
		last.Data = json.RawMessage(`{"tag":"more"}`)
		es = append(es, last)
	}
	return es
}

func TestFrontierMatchesMerkle(t *testing.T) {
	var f frontier
	var leaves [][32]byte
	if f.root() != merkle.Root(nil) {
		t.Fatal("empty frontier root differs")
	}
	for i := 0; i < 300; i++ {
		l := merkle.HashLeaf([]byte(fmt.Sprint(i)))
		leaves = append(leaves, l)
		f.push(l)
		if f.root() != merkle.Root(leaves) {
			t.Fatalf("size %d: frontier root differs from merkle.Root", i+1)
		}
	}
}

func TestSyncAndIncremental(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 10, "a")
	defer st.Close()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	v := newView(t, dir, []ed25519.PublicKey{wk.PublicKey()}, c)
	if v.Status().Synced {
		t.Fatal("synced before the first poll")
	}
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if s := v.Status(); !s.Synced || s.Size != 10 || s.HeadAge != 0 {
		t.Fatalf("after sync: %+v", s)
	}
	for i := 0; i < 5; i++ {
		_ = st.Append("INFO", "drift_clean", "drift", nil)
	}
	c.Add(30 * time.Second)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if s := v.Status(); s.Size != 15 || s.HeadAge != 0 {
		t.Fatalf("after growth: %+v", s)
	}
	if err := v.FullVerify(); err != nil {
		t.Fatalf("full verify of a genuine log: %v", err)
	}
}

// Acceptance 6: the log is rewritten and its head re-signed with the
// attacker's own key.
func TestAcceptance6_HeadSignedByForeignKey(t *testing.T) {
	wk, attacker := newSigner(5), newSigner(9)
	pins := []ed25519.PublicKey{wk.PublicKey()}
	c := &clock{t: time.Unix(1_800_000_000, 0)}

	dir := t.TempDir()
	buildLog(t, dir, wk, 6, "real").Close()
	v := newView(t, dir, pins, c)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	// The genuine records kept byte for byte, three more appended, head
	// signed by the attacker: only the signature check can catch this.
	forge(t, dir, grown(t, dir, 3, -1), attacker)
	mustReason(t, v.Poll(), "live view, aligned attacker-signed growth", "not signed by a pinned witness key")
	mustReason(t, v.Poll(), "sticky", "not signed by a pinned witness key")

	// A wholesale replacement misaligns the read offset: refused too.
	dir2 := t.TempDir()
	buildLog(t, dir2, wk, 6, "real").Close()
	v2 := newView(t, dir2, pins, c)
	if err := v2.Poll(); err != nil {
		t.Fatal(err)
	}
	forged := t.TempDir()
	buildLog(t, forged, attacker, 9, "real").Close()
	overwrite(t, forged, dir2)
	mustChain(t, v2.Poll(), "live view, wholesale attacker log")
	if v.Status().Synced || v.Fresh(time.Hour) {
		t.Fatal("failed view still reports synced/fresh")
	}

	// A gate starting on the attacker's log never syncs.
	fresh := newView(t, dir, pins, c)
	mustReason(t, fresh.Poll(), "bootstrap on attacker-signed log", "not signed by a pinned witness key")

	// The attacker names the real key in the head but cannot sign with it.
	h := filepath.Join(dir, "tree-head.json")
	b, _ := os.ReadFile(h)
	_ = os.WriteFile(h, bytes.ReplaceAll(b, []byte(hex.EncodeToString(attacker.PublicKey())), []byte(hex.EncodeToString(wk.PublicKey()))), 0600)
	mustReason(t, newView(t, dir, pins, c).Poll(), "attacker head naming the real key", "signature verification failed")

	// An unsigned witness (MAC only) is not evidence either.
	plain := t.TempDir()
	buildLog(t, plain, keySigner{}, 3, "x").Close()
	mustReason(t, newView(t, plain, pins, c).Poll(), "unsigned head", "not signed")
}

// Acceptance 7: the log is rewritten and re-signed with the REAL witness key
// (the key is on the witness host), so only the append-only check catches it.
func TestAcceptance7_RealKeyRewrite(t *testing.T) {
	wk := newSigner(5)
	pins := []ed25519.PublicKey{wk.PublicKey()}
	c := &clock{t: time.Unix(1_800_000_000, 0)}

	setup := func() (string, *View) {
		dir := t.TempDir()
		buildLog(t, dir, wk, 5, "real").Close()
		v := newView(t, dir, pins, c)
		if err := v.Poll(); err != nil {
			t.Fatal(err)
		}
		return dir, v
	}
	rewritten := func(n int, tag string) string {
		d := t.TempDir()
		buildLog(t, d, wk, n, tag).Close()
		return d
	}

	t.Run("aligned: record 2 edited, three appended, re-signed with the real key", func(t *testing.T) {
		dir, v := setup()
		forge(t, dir, grown(t, dir, 3, 1), wk)
		mustReason(t, v.Poll(), "aligned real-key rewrite", "does not extend the 5 verified records")
	})
	t.Run("aligned: genuine records kept, growth re-signed with the real key", func(t *testing.T) {
		dir, v := setup()
		forge(t, dir, grown(t, dir, 3, -1), wk)
		if err := v.Poll(); err != nil {
			t.Fatalf("forge() itself must produce a log the view accepts when nothing is changed: %v", err)
		}
	})
	cases := map[string]struct{ src, reason string }{
		"wholesale: longer, different history": {rewritten(8, "fake"), "CHAIN_UNVERIFIED"},
		"same size, different":                 {rewritten(5, "fake"), "rewritten in place"},
		"truncated":                            {rewritten(3, "real"), "truncated or head rolled back"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir, v := setup()
			overwrite(t, tc.src, dir)
			mustReason(t, v.Poll(), name, tc.reason)
		})
	}

	t.Run("head file rolled back", func(t *testing.T) {
		dir := t.TempDir()
		st := buildLog(t, dir, wk, 3, "real")
		old, _ := os.ReadFile(filepath.Join(dir, "tree-head.json"))
		_ = st.Append("INFO", "drift_clean", "drift", nil)
		_ = st.Close()
		v := newView(t, dir, pins, c)
		if err := v.Poll(); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, "tree-head.json"), old, 0600)
		mustReason(t, v.Poll(), "replayed older head", "truncated or head rolled back")
	})

	t.Run("after a gate restart, via retained priors", func(t *testing.T) {
		dir, v := setup()
		priors := v.Priors()
		overwrite(t, rewritten(8, "fake"), dir)
		mustReason(t, newView(t, dir, pins, c, priors...).Poll(), "restart on rewritten log", "is not a prefix of this log")
		trunc := t.TempDir()
		buildLog(t, trunc, wk, 2, "real").Close()
		overwrite(t, trunc, dir)
		mustReason(t, newView(t, dir, pins, c, priors...).Poll(), "restart on truncated log", "truncated")
	})

	t.Run("after a gate restart, genuine growth passes", func(t *testing.T) {
		dir := t.TempDir()
		st := buildLog(t, dir, wk, 5, "real")
		v := newView(t, dir, pins, c)
		if err := v.Poll(); err != nil {
			t.Fatal(err)
		}
		priors := v.Priors()
		for i := 0; i < 4; i++ {
			_ = st.Append("INFO", "drift_clean", "drift", nil)
		}
		_ = st.Close()
		if err := newView(t, dir, pins, c, priors...).Poll(); err != nil {
			t.Fatalf("restart on a genuinely grown log: %v", err)
		}
	})

	t.Run("old record edited, head left alone: only the full re-read sees it", func(t *testing.T) {
		dir, v := setup()
		// Rebuild with record 2 changed but keep the old head: the log no
		// longer matches its head, and incremental polls read past it.
		src := rewritten(5, "fake")
		b, _ := os.ReadFile(filepath.Join(src, "witness.log"))
		_ = os.WriteFile(filepath.Join(dir, "witness.log"), b, 0600)
		if err := v.Poll(); err != nil {
			t.Fatalf("incremental poll (nothing new): %v", err)
		}
		mustReason(t, v.FullVerify(), "full re-verify", "head root does not match the log")
		mustChain(t, v.Poll(), "sticky after full re-verify")
	})
}

// Acceptance 8: no new verified head within head_max_age. Neither an idle
// poll nor a replayed or re-signed head of the same size refreshes the age.
func TestAcceptance8_StaleHead(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 4, "real")
	defer st.Close()
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	v := newView(t, dir, []ed25519.PublicKey{wk.PublicKey()}, c)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	maxAge := 60 * time.Second
	if !v.Fresh(maxAge) {
		t.Fatal("not fresh right after sync")
	}
	c.Add(61 * time.Second)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if v.Fresh(maxAge) {
		t.Fatalf("fresh with no new head for 61s (age %s)", v.Status().HeadAge)
	}
	// The head file rewritten with the same content (as a stalled-but-alive
	// witness re-signing would) is not growth.
	h := filepath.Join(dir, "tree-head.json")
	b, _ := os.ReadFile(h)
	_ = os.WriteFile(h, b, 0600)
	_ = v.Poll()
	if v.Fresh(maxAge) {
		t.Fatal("same-size head refreshed the age")
	}
	_ = st.Append("INFO", "drift_clean", "drift", nil)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if !v.Fresh(maxAge) {
		t.Fatal("not fresh after the witness appended again")
	}

	empty := newView(t, t.TempDir(), []ed25519.PublicKey{wk.PublicKey()}, c)
	if err := empty.Poll(); err != nil {
		t.Fatal(err)
	}
	if empty.Fresh(time.Hour) {
		t.Fatal("an empty log is never fresh evidence")
	}
}

// Acceptance 9 (evidence side): CRITICAL lifecycle records are classified and
// exposed; routine records are not kept; pipelock warn is not a block.
func TestAcceptance9_Signals(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 0, "")
	defer st.Close()
	t0 := time.Now().UTC().Add(-time.Minute)
	app := func(level, event, source string, data any) {
		if err := st.Append(level, event, source, data); err != nil {
			t.Fatal(err)
		}
	}
	app("INFO", "daemon_start", "witness", map[string]string{"v": "3.3.3"})
	app("CRITICAL", "witness_downtime", "witness", map[string]any{"clean_stop": false, "gap_seconds": 40})
	app("CRITICAL", "mirror_unreachable", "witness", map[string]any{"consecutive": 3})
	app("CRITICAL", "mirror_not_configured", "witness", nil)
	app("DEATH", "signal_received", "witness", map[string]string{"detail": "terminated"})
	app("DRIFT", "drift_detected", "drift", []map[string]string{{"kind": "new_process", "name": "xmrig"}})
	app("INFO", "drift_clean", "drift", nil)
	app("WARN", "sbh_decision:stop_and_ask", "sbh", map[string]any{"stop_and_ask": true})
	app("WARN", "sbh_escalation", "sbh", nil)
	app("WARN", "pipelock_receipt:proxy_decision", "pipelock", map[string]any{"detail": map[string]any{"payload": map[string]any{"verdict": "block"}}})
	app("WARN", "pipelock_receipt:proxy_decision", "pipelock", map[string]any{"detail": map[string]any{"payload": map[string]any{"verdict": "warn"}}})
	app("INFO", "pipelock_receipt:http_request", "pipelock", map[string]any{"detail": map[string]any{"action_record": map[string]any{"verdict": "allow"}}})
	app("INFO", "connect", "netflow", map[string]string{"from": "laptop-07", "to": "wallet-container"})
	app("INFO", "gate_request", "gate", map[string]string{"action_hash": "ab"})

	c := &clock{t: time.Now()}
	v := newView(t, dir, []ed25519.PublicKey{wk.PublicKey()}, c)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range v.Signals(t0) {
		got = append(got, fmt.Sprintf("%s/%v", s.Kind, s.Critical))
	}
	want := []string{
		"daemon_start/false", "witness_downtime/true", "mirror_unreachable/true", "mirror_not_configured/true",
		"death/true", "drift_detected/false", "sbh_stop_and_ask/false", "sbh_escalation/false",
		"pipelock_block/false", "feed/false", "gate/false",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("signals:\n got %v\nwant %v", got, want)
	}
	if crit := v.Signals(t0, KindDowntime, KindMirrorUnreachable); len(crit) != 2 || !crit[0].Critical {
		t.Fatalf("filtered criticals: %+v", crit)
	}
	if _, ok := v.LastSeen("netflow"); !ok {
		t.Fatal("feed source not tracked")
	}
	if s, ok := v.Last("witness", "witness_downtime"); !ok || s.Level != "CRITICAL" {
		t.Fatalf("last downtime: %+v %v", s, ok)
	}
	if got := v.Signals(time.Now().Add(time.Hour)); len(got) != 0 {
		t.Fatalf("signals from the future: %d", len(got))
	}
}

func TestSignalsPruned(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 0, "")
	defer st.Close()
	for i := 0; i < 10; i++ {
		_ = st.Append("INFO", "connect", "netflow", nil)
	}
	c := &clock{t: time.Now()}
	v, _ := New(Config{Dir: dir, Key: logKey, Pins: []ed25519.PublicKey{wk.PublicKey()}, Now: c.Now, MaxSignals: 4})
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if n := len(v.Signals(time.Time{})); n != 4 {
		t.Fatalf("kept %d signals, cap 4", n)
	}
	c.Add(48 * time.Hour)
	_ = st.Append("INFO", "connect", "netflow", nil)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if n := len(v.Signals(time.Time{})); n != 0 {
		t.Fatalf("kept %d signals older than the lookback", n)
	}
}

// fingerprint hashes names, sizes, modes and contents under dir.
func fingerprint(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, _ := os.Lstat(p)
		sum := ""
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			h := sha256.Sum256(b)
			sum = hex.EncodeToString(h[:])
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%d|%d|%s", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano(), sum))
		return nil
	})
	sort.Strings(lines)
	return fmt.Sprint(lines)
}

// TestViewNeverMutates: polling and full re-verification leave the witness
// directory exactly as it was, even with an uncommitted tail present.
func TestViewNeverMutates(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	buildLog(t, dir, wk, 7, "real").Close()
	f, _ := os.OpenFile(filepath.Join(dir, "witness.log"), os.O_APPEND|os.O_WRONLY, 0600)
	_, _ = f.Write([]byte{0, 0, 0, 40, 1, 2, 3}) // torn frame
	_ = f.Close()
	before := fingerprint(t, dir)
	c := &clock{t: time.Now()}
	v := newView(t, dir, []ed25519.PublicKey{wk.PublicKey()}, c)
	if err := v.Poll(); err != nil {
		t.Fatal(err)
	}
	if err := v.FullVerify(); err != nil {
		t.Fatal(err)
	}
	if after := fingerprint(t, dir); after != before {
		t.Fatalf("the evidence view changed the witness directory:\n%s\n%s", before, after)
	}
}

// TestPollBesideWriter: polling while the witness appends never fails and
// ends exactly at the full log.
func TestPollBesideWriter(t *testing.T) {
	wk := newSigner(5)
	dir := t.TempDir()
	st := buildLog(t, dir, wk, 1, "real")
	c := &clock{t: time.Now()}
	v := newView(t, dir, []ed25519.PublicKey{wk.PublicKey()}, c)
	const n = 200
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			_ = st.Append("INFO", "drift_clean", "drift", nil)
		}
	}()
	for {
		if err := v.Poll(); err != nil {
			t.Fatalf("poll beside writer: %v", err)
		}
		select {
		case <-done:
			if err := v.Poll(); err != nil {
				t.Fatal(err)
			}
			_ = st.Close()
			if s := v.Status(); s.Size != n+1 || !s.Synced {
				t.Fatalf("ended at %+v, want size %d", s, n+1)
			}
			return
		default:
		}
	}
}

func TestNewNeedsPins(t *testing.T) {
	if _, err := New(Config{Dir: "x", Key: logKey}); err == nil {
		t.Fatal("view without pinned witness keys")
	}
}
