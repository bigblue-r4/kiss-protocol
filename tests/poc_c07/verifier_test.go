//go:build poc_c07

package poc_c07

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// ── The published tooling, run as shipped (cmd/witness) ─────────────────────

var witnessBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "poc-c07-bin")
	if err != nil {
		panic(err)
	}
	witnessBin = filepath.Join(dir, "witness")
	out, err := exec.Command("go", "build", "-o", witnessBin, "../../cmd/witness").CombinedOutput()
	if err != nil {
		panic("build witness: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// sandbox is a HOME with a witness config pointing at a fresh store and a
// file mirror. The store uses this machine's real key, as the binary derives it.
type sandbox struct {
	home, primary, mirror string
	key                   []byte
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	home := t.TempDir()
	sb := sandbox{home: home, primary: filepath.Join(home, "primary"), mirror: filepath.Join(home, "mirror")}
	k, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		t.Fatal(err)
	}
	sb.key = k
	_ = os.MkdirAll(filepath.Join(home, ".witness"), 0700)
	_ = os.MkdirAll(sb.mirror, 0700)
	cfg, _ := json.Marshal(map[string]any{"primary_dir": sb.primary, "drift_interval_sec": 30, "mirror_url": "file://" + sb.mirror})
	if err := os.WriteFile(filepath.Join(home, ".witness", "config.json"), cfg, 0600); err != nil {
		t.Fatal(err)
	}
	return sb
}

func (sb sandbox) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(witnessBin, args...)
	cmd.Env = append(os.Environ(), "HOME="+sb.home)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

// publish copies the current head to the mirror, as the daemon's drift tick does.
func (sb sandbox) publish(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(sb.primary, "tree-head.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(sb.mirror, "tree-head.json"), b, 0600)
}

func (sb sandbox) appendN(t *testing.T, s *keySigner, n int) {
	t.Helper()
	st, err := store.Open(sb.primary, sb.key, s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		_ = st.Append("INFO", "action", "gateway", map[string]int{"i": i})
	}
	_ = st.Close()
}

func TestC07_7_3_1_PublishedVerifierCatchesAModifiedRecord(t *testing.T) {
	sb := newSandbox(t)
	s := newSigner(t)
	sb.appendN(t, s, 6)
	if code, out := sb.run(t, "verify"); code != 0 {
		t.Fatalf("clean log: witness verify exit %d: %s", code, out)
	}
	e := readEntries(t, sb.primary, sb.key)
	e[2].Event = "edited"
	rewriteLog(t, sb.primary, sb.key, e)
	if code, out := sb.run(t, "verify"); code == 0 || !strings.Contains(out, "INTEGRITY FAILURE") {
		t.Fatalf("modified log: witness verify exit %d: %s", code, out)
	}
}

// The mirror catches truncation followed by a re-sign (mirror claims more).
func TestC07_7_6_6_MirrorCatchesTruncateAndReSign(t *testing.T) {
	sb := newSandbox(t)
	s := newSigner(t)
	sb.appendN(t, s, 8)
	sb.publish(t)
	e := readEntries(t, sb.primary, sb.key)
	rewriteLog(t, sb.primary, sb.key, e[:5])
	forgeHead(t, sb.primary, sb.key, s)
	if code, _ := sb.run(t, "verify"); code != 0 {
		t.Fatal("setup: the re-signed truncated log should pass the local check")
	}
	if code, out := sb.run(t, "audit"); code != 1 {
		t.Fatalf("witness audit exit %d, want 1 (mirror claims more): %s", code, out)
	}
}

func TestC07_7_6_6_MirrorCatchesSameSizeRewrite(t *testing.T) {
	sb := newSandbox(t)
	s := newSigner(t)
	sb.appendN(t, s, 8)
	sb.publish(t)
	e := readEntries(t, sb.primary, sb.key)
	e[1].Data = json.RawMessage(`{"i":-1}`)
	rewriteLog(t, sb.primary, sb.key, e)
	forgeHead(t, sb.primary, sb.key, s)
	if code, out := sb.run(t, "audit"); code != 1 {
		t.Fatalf("witness audit exit %d, want 1 (root mismatch at equal size): %s", code, out)
	}
}

// Probe (C7.3.5, attack A9): rewrite a past record, re-sign, then append one
// more record. The mirror is now "behind", and audit compares only sizes in
// that case, never whether the old root is a prefix of the new log.
func TestC07_7_3_5_Probe_AuditCatchesRewriteThenAppend(t *testing.T) {
	sb := newSandbox(t)
	s := newSigner(t)
	sb.appendN(t, s, 8)
	sb.publish(t)
	e := readEntries(t, sb.primary, sb.key)
	e[1].Data = json.RawMessage(`{"i":-1}`)
	rewriteLog(t, sb.primary, sb.key, e)
	forgeHead(t, sb.primary, sb.key, s)
	sb.appendN(t, s, 1) // one honest-looking record on top
	code, out := sb.run(t, "audit")
	t.Logf("witness audit exit %d:\n%s", code, strings.TrimSpace(out))
	if code == 0 {
		t.Fatalf("history rewritten, re-signed and extended by 1: witness audit exit 0:\n%s", strings.TrimSpace(out))
	}
}

// ── T3: a third party with only published material ──────────────────────────

// The head's signature is checkable with nothing but the public key.
func TestC07_T3_HeadSignatureVerifiesWithPublicKeyOnly(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 5)
	h := readHead(t, dir)
	pub, _ := hex.DecodeString(h.SignerKey)
	root := decodeRoot(t, h.Root)
	if !ed25519.Verify(pub, sigInput(h.Size, root), mustHex(t, h.Signature)) {
		t.Fatal("published head signature does not verify with the public key")
	}
}

// Probe: with the published head and the log file, but without the machine
// key, a third party cannot recompute the root: every record is encrypted
// under a key derived from the machine.
func TestC07_T3_Probe_ThirdPartyRecomputesRootWithoutMachineKey(t *testing.T) {
	key := machineKey(t)
	dir := writeLog(t, key, newSigner(t), 5)
	h := readHead(t, dir)
	outsiderKey := make([]byte, 32) // not the machine key
	e, _ := store.ReadAll(dir, outsiderKey)
	root := merkle.Root(leaves(e))
	if hex.EncodeToString(root[:]) != h.Root {
		t.Fatalf("third party without the machine key reads %d of %d records and cannot recompute the published root", len(e), h.Size)
	}
}

// ── 7.5.1 schema fields are execution facts ─────────────────────────────────

func TestC07_7_5_1_EntrySchemaIsExecutionFactsOnly(t *testing.T) {
	want := []string{"seq", "ts", "level", "event", "source", "data,omitempty"}
	var got []string
	ty := reflect.TypeOf(store.Entry{})
	for i := 0; i < ty.NumField(); i++ {
		got = append(got, ty.Field(i).Tag.Get("json"))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("store.Entry fields changed: %v (re-review C7.5.1)", got)
	}
}

// ── 7.6.4 access control on the evidence store ──────────────────────────────

func TestC07_7_6_4_StoreFilesAreOwnerOnly(t *testing.T) {
	key := machineKey(t)
	dir := filepath.Join(t.TempDir(), "primary") // created by the store itself
	st, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Append("INFO", "a", "gateway", nil)
	_ = st.Close()
	for _, p := range []string{dir, filepath.Join(dir, "witness.log"), filepath.Join(dir, "tree-head.json")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is %v: readable or writable beyond its owner", filepath.Base(p), fi.Mode().Perm())
		}
	}
}

// ── 7.6.1 pipeline failures ─────────────────────────────────────────────────

// Probe: a write error is returned to the caller, but nothing records it as a
// failure event in a second durable log (callers mostly discard it).
func TestC07_7_6_1_Probe_WriteFailureIsRecordedElsewhere(t *testing.T) {
	key := machineKey(t)
	dir := writeLog(t, key, newSigner(t), 1)
	st, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0500) // the head can no longer be replaced
	defer os.Chmod(dir, 0700)
	werr := st.Append("INFO", "action", "gateway", nil)
	_ = st.Close()
	if werr == nil {
		t.Skip("write did not fail on this filesystem (running as root?)")
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), "*failure*"))
	if len(matches) == 0 {
		t.Fatalf("Append failed (%v) and no failure record exists outside the store; "+
			"the store has no secondary failure log or alert hook", werr)
	}
}

// ── 7.7 interoperability ────────────────────────────────────────────────────

// Probe: digests and signatures carry no algorithm identifier.
func TestC07_7_7_3_Probe_HeadNamesItsAlgorithms(t *testing.T) {
	key := machineKey(t)
	dir := writeLog(t, key, newSigner(t), 2)
	raw, _ := os.ReadFile(filepath.Join(dir, "tree-head.json"))
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"alg", "hash_alg", "sig_alg", "root_alg"} {
		if _, ok := m[k]; ok {
			return
		}
	}
	t.Fatalf("tree head has no algorithm identifier for root (BLAKE3), MAC (keyed BLAKE3) or signature (ed25519): keys %v", keysOf(m))
}

// Probe: duplicate JSON keys in a feed line are resolved last-wins, so the
// same evidence line can mean different things to different readers.
func TestC07_7_7_5_Probe_DuplicateKeysAreRejected(t *testing.T) {
	var evt map[string]any
	line := `{"source":"h","kind":"alarm","kind":"reading"}`
	if err := json.Unmarshal([]byte(line), &evt); err == nil {
		t.Fatalf("feed decoding (encoding/json, as internal/pipelock/tailer.go uses) accepted duplicate keys and kept kind=%v", evt["kind"])
	}
}

func keysOf(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
