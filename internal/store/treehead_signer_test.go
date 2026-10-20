package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

// The head's signature used to be checked against the signer_key written in
// the head file itself, so anyone holding the machine key could sign a
// rewritten log with a key of their own and pass. These pin the fix: a store
// opened with the witness's signer accepts only that signer's heads.

// signedLog writes three entries with the given signer and returns the dir.
func signedLog(t *testing.T, s *testDevSigner) string {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir, testKey(), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"a", "b", "c"} {
		if err := st.Append("INFO", ev, "test", nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()
	return dir
}

// forgeHead rewrites tree-head.json for the current log, with a valid MAC
// (the attacker has the machine key) and signed by the given key, or unsigned
// when s is nil.
func forgeHead(t *testing.T, dir string, s *testDevSigner) {
	t.Helper()
	entries, err := ReadAll(dir, testKey())
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}
	root := merkle.Root(leaves)
	mac := computeMAC(testKey(), uint64(len(leaves)), root)
	head := TreeHead{Size: uint64(len(leaves)), Root: hex.EncodeToString(root[:]), MAC: hex.EncodeToString(mac[:])}
	if s != nil {
		sig, _ := s.Sign(treeHeadSigInput(uint64(len(leaves)), root))
		head.Signature = hex.EncodeToString(sig)
		head.SignerKey = hex.EncodeToString(s.PublicKey())
	}
	b, _ := json.Marshal(head)
	if err := os.WriteFile(filepath.Join(dir, treeHeadFilename), b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHeadSignedByAnotherKeyIsRejected(t *testing.T) {
	witness, attacker := newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, witness)
	forgeHead(t, dir, attacker)

	_, err := Open(dir, testKey(), witness)
	if !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("head signed by another key: got %v, want ErrUnexpectedSigner", err)
	}
}

// A key rotation: the old head is signed by the previous key. With that key in
// the trust allowlist it opens, and the next Append signs with the new key.
func TestRotatedKeyOpensWhenTheOldKeyIsTrusted(t *testing.T) {
	oldKey, newKey := newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, oldKey)

	if _, err := Open(dir, testKey(), newKey); !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("rotation without trusting the old key: got %v, want ErrUnexpectedSigner", err)
	}
	st, err := OpenTrusting(dir, testKey(), newKey, []ed25519.PublicKey{oldKey.PublicKey()})
	if err != nil {
		t.Fatalf("rotation with the old key trusted: %v", err)
	}
	if err := st.Append("INFO", "after-rotation", "test", nil); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	// Now signed by the new key: opens without the allowlist.
	st, err = Open(dir, testKey(), newKey)
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	_ = st.Close()
}

func TestTrustedListDoesNotLetAnAttackerIn(t *testing.T) {
	witness, other, attacker := newTestDevSigner(t), newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, witness)
	forgeHead(t, dir, attacker)
	_, err := OpenTrusting(dir, testKey(), witness, []ed25519.PublicKey{other.PublicKey()})
	if !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("got %v, want ErrUnexpectedSigner", err)
	}
}

func TestVerifyIntegrityAlsoPinsTheSigner(t *testing.T) {
	witness, attacker := newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, witness)
	st, err := Open(dir, testKey(), witness)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	forgeHead(t, dir, attacker) // swapped while the store is open
	if _, err := st.VerifyIntegrity(); !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatalf("got %v, want ErrUnexpectedSigner", err)
	}
}

func TestOwnSignerStillOpens(t *testing.T) {
	witness := newTestDevSigner(t)
	dir := signedLog(t, witness)
	st, err := Open(dir, testKey(), witness)
	if err != nil {
		t.Fatalf("own head rejected: %v", err)
	}
	defer st.Close()
	if st.OpenedWithUnsignedHead() {
		t.Fatal("a signed head reported as unsigned")
	}
}

// Without the witness's signer there is no key to pin to: a reader opening
// with nil still checks the MAC and that the signature matches its own key
// field, as before. Pinned here so a change to it is deliberate.
func TestReaderWithoutSignerCannotPin(t *testing.T) {
	witness, attacker := newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, witness)
	forgeHead(t, dir, attacker)
	st, err := Open(dir, testKey(), nil)
	if err != nil {
		t.Fatalf("nil-signer open: %v", err)
	}
	_ = st.Close()
}

// Stripping the signature is the other way round the pin. An unsigned head is
// still accepted (logs from before signing was configured must keep opening),
// but the store reports it so the daemon can record a warning, and the next
// Append signs the head again.
func TestUnsignedHeadIsReportedAndResigned(t *testing.T) {
	witness := newTestDevSigner(t)
	dir := signedLog(t, witness)
	forgeHead(t, dir, nil)

	st, err := Open(dir, testKey(), witness)
	if err != nil {
		t.Fatalf("unsigned head should still open: %v", err)
	}
	if !st.OpenedWithUnsignedHead() {
		t.Fatal("unsigned head not reported")
	}
	if err := st.Append("WARN", "tree_head_unsigned", "witness", nil); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	st, err = Open(dir, testKey(), witness)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.OpenedWithUnsignedHead() {
		t.Fatal("head still unsigned after an Append with a signer")
	}
}

func TestUnsignedHeadWithoutSignerIsNotReported(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Append("INFO", "a", "test", nil)
	_ = st.Close()
	st, err = Open(dir, testKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.OpenedWithUnsignedHead() {
		t.Fatal("MAC-only mode is not a downgrade")
	}
}

func TestOpenPinned(t *testing.T) {
	witness, attacker := newTestDevSigner(t), newTestDevSigner(t)
	for _, tc := range []struct {
		name string
		head *testDevSigner
		pins []ed25519.PublicKey
		want error
	}{
		{"legitimate", witness, []ed25519.PublicKey{witness.PublicKey()}, nil},
		{"rotation set", witness, []ed25519.PublicKey{attacker.PublicKey(), witness.PublicKey()}, nil},
		{"attacker", attacker, []ed25519.PublicKey{witness.PublicKey()}, ErrUnexpectedSigner},
		{"unsigned", nil, []ed25519.PublicKey{witness.PublicKey()}, ErrHeadNotSigned},
		{"legacy signed", attacker, nil, nil},
		{"legacy unsigned", nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := signedLog(t, witness)
			forgeHead(t, dir, tc.head)
			st, err := OpenPinned(dir, testKey(), tc.pins)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if st != nil {
				defer st.Close()
				if _, err := st.VerifyIntegrity(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPinnedIntegrityRejectsReplacedHead(t *testing.T) {
	witness, attacker := newTestDevSigner(t), newTestDevSigner(t)
	dir := signedLog(t, witness)
	st, err := OpenPinned(dir, testKey(), []ed25519.PublicKey{witness.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	forgeHead(t, dir, attacker)
	if _, err := st.VerifyIntegrity(); !errors.Is(err, ErrUnexpectedSigner) {
		t.Fatal(err)
	}
	forgeHead(t, dir, nil)
	if _, err := st.VerifyIntegrity(); !errors.Is(err, ErrHeadNotSigned) {
		t.Fatal(err)
	}
}

func TestPinnedRequiresHeadEvenForEmptyLog(t *testing.T) {
	_, err := OpenPinned(t.TempDir(), testKey(), []ed25519.PublicKey{newTestDevSigner(t).PublicKey()})
	if !errors.Is(err, ErrHeadNotSigned) {
		t.Fatalf("got %v", err)
	}
}

func TestPinnedRejectsInvalidSignature(t *testing.T) {
	witness := newTestDevSigner(t)
	dir := signedLog(t, witness)
	head, err := readStoredHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	head.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	data, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, treeHeadFilename), data, 0600); err != nil {
		t.Fatal(err)
	}
	if st, err := OpenPinned(dir, testKey(), []ed25519.PublicKey{witness.PublicKey()}); err == nil {
		st.Close()
		t.Fatal("accepted invalid signature")
	}
}

func TestPinnedCrashTailRecovery(t *testing.T) {
	witness := newTestDevSigner(t)
	dir := signedLog(t, witness)
	appendRaw(t, dir, []byte{0, 0})
	st, err := OpenPinned(dir, testKey(), []ed25519.PublicKey{witness.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Recovered().Bytes != 2 {
		t.Fatalf("recovery: %+v", st.Recovered())
	}
	if n, err := st.VerifyIntegrity(); err != nil || n != 3 {
		t.Fatalf("%d, %v", n, err)
	}
}
