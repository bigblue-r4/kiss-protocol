//go:build poc_c07

package poc_c07

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/bits"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// ── 7.3.1 modifying, inserting or reordering any record invalidates the log ──

func TestC07_7_3_1_ModifyInsertReorderDeleteAreDetected(t *testing.T) {
	key := machineKey(t)
	cases := map[string]func([]store.Entry) []store.Entry{
		"modify": func(e []store.Entry) []store.Entry {
			e[3].Data = json.RawMessage(`{"n":999}`)
			return e
		},
		"insert": func(e []store.Entry) []store.Entry {
			forged := e[2]
			forged.Event = "forged"
			return append(e[:3:3], append([]store.Entry{forged}, e[3:]...)...)
		},
		"reorder": func(e []store.Entry) []store.Entry {
			e[1], e[5] = e[5], e[1]
			return e
		},
		"delete": func(e []store.Entry) []store.Entry { return append(e[:4:4], e[5:]...) },
		"replay": func(e []store.Entry) []store.Entry { return append(e, e[0]) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSigner(t)
			dir := writeLog(t, key, s, 8)
			rewriteLog(t, dir, key, tamper(readEntries(t, dir, key)))
			_, err := store.Open(dir, key, s)
			if err == nil {
				t.Fatalf("%s: tampered log opened cleanly", name)
			}
		})
	}
}

// The verifier must also catch a flipped byte in the encrypted file itself,
// not only a well-formed rewrite.
func TestC07_7_3_1_FlippedCiphertextByteIsDetected(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 6)
	p := filepath.Join(dir, "witness.log")
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 0x01
	_ = os.WriteFile(p, b, 0600)
	if _, err := store.Open(dir, key, s); err == nil {
		t.Fatal("a flipped ciphertext byte went unnoticed")
	}
}

// ── 7.3.2 records signed by the mechanism's key ─────────────────────────────

func TestC07_7_3_2_HeadSignedByAnotherKeyIsRejected(t *testing.T) {
	key := machineKey(t)
	witness, attacker := newSigner(t), newSigner(t)
	dir := writeLog(t, key, witness, 5)
	e := readEntries(t, dir, key)
	rewriteLog(t, dir, key, append(e[:2:2], e[3:]...))
	forgeHead(t, dir, key, attacker)
	if _, err := store.Open(dir, key, witness); !errors.Is(err, store.ErrUnexpectedSigner) {
		t.Fatalf("head signed by a foreign key: got %v, want ErrUnexpectedSigner", err)
	}
}

// Probe: C7.3.2 wants keys that the operator cannot access. The MAC key is
// derived from /etc/machine-id, which every local account can read.
func TestC07_7_3_2_Probe_MACKeyInputIsNotSecret(t *testing.T) {
	fi, err := os.Stat("/etc/machine-id")
	if err != nil {
		t.Skip("no /etc/machine-id on this host")
	}
	if fi.Mode().Perm()&0o004 != 0 {
		t.Fatalf("the MAC/encryption key is HKDF(/etc/machine-id) and /etc/machine-id is world-readable (%v): "+
			"any local account can derive it (internal/encrypt/encrypt.go DeriveKey, internal/machid)", fi.Mode().Perm())
	}
}

// Probe: a reader that opens the log without a signer (witness verify, audit,
// prove) has nothing to pin to, so a head signed by any key passes there.
func TestC07_7_3_2_Probe_PublishedVerifierPinsTheSigner(t *testing.T) {
	key := machineKey(t)
	witness, attacker := newSigner(t), newSigner(t)
	dir := writeLog(t, key, witness, 5)
	e := readEntries(t, dir, key)
	rewriteLog(t, dir, key, append(e[:2:2], e[3:]...))
	forgeHead(t, dir, key, attacker)
	if _, err := store.Open(dir, key, nil); err == nil {
		t.Fatal("verifier path with no signer (store.Open(dir, key, nil), as cmd/witness/verify.go:30 calls it) " +
			"accepted a rewritten log re-signed with an attacker's key")
	}
}

// ── 7.3.4 single-record inclusion proof against a published root ────────────

func TestC07_7_3_4_InclusionProofVerifiesWithIndependentTooling(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 37)
	head := readHead(t, dir)
	root := decodeRoot(t, head.Root)
	entries := readEntries(t, dir, key)
	lv := leaves(entries)
	for i := range entries {
		p, err := merkle.Prove(lv, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		// Third-party leaf hash, from the disclosed record alone.
		b, _ := json.Marshal(entries[i])
		leaf := ivLeaf(b)
		if !ivVerifyInclusion(uint64(i), head.Size, leaf, p.Path, root) {
			t.Fatalf("record %d: inclusion proof does not verify with independent RFC 6962 code", i)
		}
		// A changed record must not verify against the same proof.
		other := entries[i]
		other.Event += "x"
		ob, _ := json.Marshal(other)
		if ivVerifyInclusion(uint64(i), head.Size, ivLeaf(ob), p.Path, root) {
			t.Fatalf("record %d: an altered record verified", i)
		}
	}
}

func TestC07_7_3_4_ProofSizeIsLogarithmic(t *testing.T) {
	var lv [][32]byte
	for n := 1; n <= 4096; n++ {
		var h [32]byte
		binary.BigEndian.PutUint64(h[:], uint64(n))
		lv = append(lv, h)
		if n&(n-1) != 0 && n%97 != 0 {
			continue // spot-check powers of two and a spread of other sizes
		}
		for _, i := range []uint64{0, uint64(n / 2), uint64(n - 1)} {
			p, err := merkle.Prove(lv, i)
			if err != nil {
				t.Fatal(err)
			}
			limit := bits.Len(uint(n - 1)) // ceil(log2 n)
			if len(p.Path) > limit {
				t.Fatalf("n=%d i=%d: path %d > ceil(log2 n)=%d", n, i, len(p.Path), limit)
			}
		}
	}
}

// ── 7.3.5 rewritten-and-re-signed history (attack A9) ───────────────────────

// Locally, a rewrite re-signed with the witness's own key is indistinguishable
// from the real log: this is the attack C7.3.5 exists for. The local verifier
// has no earlier root to compare against.
func TestC07_7_3_5_Probe_LocalVerifierRejectsReSignedRewrite(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 8)
	e := readEntries(t, dir, key)
	e[2].Data = json.RawMessage(`{"n":-1}`)
	rewriteLog(t, dir, key, e)
	forgeHead(t, dir, key, s)
	if _, err := store.Open(dir, key, s); err == nil {
		t.Fatal("a historical record altered and re-signed with the witness key verifies cleanly: " +
			"nothing local compares against a previously published root (no consistency proof exists in internal/merkle)")
	}
}

// Rolling the whole log back to an earlier consistent state (older log + its
// own signed head) is also invisible locally.
func TestC07_7_3_5_Probe_LocalVerifierRejectsRollback(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 4)
	old, _ := os.ReadFile(filepath.Join(dir, "witness.log"))
	oldHead, _ := os.ReadFile(filepath.Join(dir, "tree-head.json"))
	st, err := store.Open(dir, key, s)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = st.Append("WARN", "later", "gateway", nil)
	}
	_ = st.Close()
	_ = os.WriteFile(filepath.Join(dir, "witness.log"), old, 0600)
	_ = os.WriteFile(filepath.Join(dir, "tree-head.json"), oldHead, 0600)
	if _, err := store.Open(dir, key, s); err == nil {
		t.Fatal("rolling back to an earlier signed (log, head) pair verifies cleanly; only a mirror holding a later head can tell")
	}
}

// ── Crash mid-write ─────────────────────────────────────────────────────────

// A witness killed mid-Append can leave a torn record at the end of
// witness.log. The record and head before it must survive, and later writes
// must not be lost behind it.
func TestC07_Crash_TornWriteDoesNotLoseLaterRecords(t *testing.T) {
	key := machineKey(t)
	s := newSigner(t)
	dir := writeLog(t, key, s, 3)
	p := filepath.Join(dir, "witness.log")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0600)
	torn := binary.BigEndian.AppendUint32(nil, 500) // length says 500, only 6 bytes follow
	_, _ = f.Write(append(torn, []byte("abcdef")...))
	_ = f.Close()

	st, err := store.Open(dir, key, s)
	if err != nil {
		t.Fatalf("log with a torn tail did not reopen: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := st.Append("INFO", "after-crash", "gateway", nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()

	got, _ := store.ReadAll(dir, key)
	if len(got) != 5 {
		t.Errorf("after a torn write and 2 new records, ReadAll returns %d records, want 5", len(got))
	}
	if _, err := store.Open(dir, key, s); err != nil {
		t.Errorf("after a torn write and 2 new records the log no longer opens: %v", err)
	}
}
