// Package rekor anchors pilot checkpoints in a Rekor v1 transparency log
// (such as the public Sigstore instance) and verifies those anchors offline.
//
// An anchor is a hashedrekord entry whose artifact is a checkpoint body
// (origin, size, root). Rekor's signed entry timestamp says the body existed
// by the entry's integrated time; its inclusion proof and signed checkpoint
// say the entry is in Rekor's log. Rekor does not compare one anchor with
// another, so it says nothing about append-only growth by itself: the
// verifier gets that by recomputing each anchored root from the records.
//
// Written from the Rekor v1 OpenAPI description and the Sigstore client
// specification, and checked against an entry fetched from the public
// instance (testdata). Rekor v2 (no signed entry timestamp) is not supported.
package rekor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// MaxResponse bounds a Rekor response.
const MaxResponse = 1 << 20

// Entry is one Rekor log entry as the API returns it.
type Entry struct {
	Body           string `json:"body"` // base64 of the canonical entry
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

// Anchor is what the log publishes for one anchored checkpoint.
type Anchor struct {
	Format string          `json:"format"`
	Size   uint64          `json:"size"` // the anchored checkpoint's tree size
	Rekor  string          `json:"rekor"`
	UUID   string          `json:"uuid"`
	Entry  json.RawMessage `json:"entry"` // exactly as Rekor returned it
}

// AnchorFormat identifies the anchor file layout.
const AnchorFormat = "harborlight-rekor-anchor/1"

// Result is what a verified anchor establishes.
type Result struct {
	IntegratedTime int64  // Unix seconds, from Rekor's signed entry timestamp
	LogIndex       int64  // global index in Rekor
	TreeID         string // Rekor shard, from its checkpoint origin
}

// Digest is the artifact hash anchored for a checkpoint body.
func Digest(checkpointBody []byte) [32]byte { return sha256.Sum256(checkpointBody) }

// ParsePublicKey reads an ECDSA P-256 public key (PEM "PUBLIC KEY").
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("rekor: expected a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("rekor: only ECDSA P-256 keys are supported")
	}
	return ek, nil
}

// ParsePrivateKey reads an ECDSA P-256 private key (PEM PKCS#8).
func ParsePrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("rekor: expected a PEM PRIVATE KEY (PKCS#8)")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("rekor: only ECDSA P-256 keys are supported")
	}
	return ek, nil
}

// GenerateKey makes an anchoring key and returns it as PKCS#8 and PKIX PEM.
func GenerateKey() (privPEM, pubPEM []byte, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}

// LogID is Rekor's identifier for a log key: hex SHA-256 of its PKIX DER.
func LogID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

// ProposedEntry builds the hashedrekord request for a digest, signed by key.
func ProposedEntry(digest [32]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{"hash": map[string]string{"algorithm": "sha256", "value": hex.EncodeToString(digest[:])}},
			"signature": map[string]any{
				"content":   base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]string{"content": base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	})
}

// Upload submits an anchor for digest and returns the entry's UUID and the
// entry exactly as Rekor returned it. An entry Rekor already holds (409) is
// fetched instead. If the response has no inclusion proof, the entry is
// fetched once more by UUID.
func Upload(ctx context.Context, hc *http.Client, base string, digest [32]byte, key *ecdsa.PrivateKey) (string, json.RawMessage, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	base = strings.TrimRight(base, "/")
	body, err := ProposedEntry(digest, key)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	resp.Body.Close()
	if err != nil {
		return "", nil, err
	}
	switch resp.StatusCode {
	case http.StatusCreated:
		uuid, raw, err := single(b)
		if err != nil {
			return "", nil, err
		}
		var e Entry
		if json.Unmarshal(raw, &e) == nil && e.Verification.InclusionProof != nil {
			return uuid, raw, nil
		}
		return Fetch(ctx, hc, base, uuid)
	case http.StatusConflict:
		loc := resp.Header.Get("Location")
		uuid := loc[strings.LastIndex(loc, "/")+1:]
		if !isHex(uuid) {
			return "", nil, errors.New("rekor: 409 without a usable Location header")
		}
		return Fetch(ctx, hc, base, uuid)
	default:
		return "", nil, fmt.Errorf("rekor: upload: HTTP %d: %s", resp.StatusCode, firstLine(b))
	}
}

// Fetch gets one entry by UUID.
func Fetch(ctx context.Context, hc *http.Client, base, uuid string) (string, json.RawMessage, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if !isHex(uuid) {
		return "", nil, errors.New("rekor: bad UUID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/api/v1/log/entries/"+uuid, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	resp.Body.Close()
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("rekor: fetch: HTTP %d: %s", resp.StatusCode, firstLine(b))
	}
	return single(b)
}

func single(b []byte) (string, json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return "", nil, fmt.Errorf("rekor: response: %w", err)
	}
	if len(m) != 1 {
		return "", nil, fmt.Errorf("rekor: response has %d entries, want 1", len(m))
	}
	for k, v := range m {
		return k, v, nil
	}
	panic("unreachable")
}

// VerifyEntry checks everything Rekor itself attests about an entry, with
// only Rekor's public key: the log ID, the signed entry timestamp, the
// UUID, and inclusion under a checkpoint Rekor signed. It returns the
// entry's decoded body.
func VerifyEntry(uuid string, raw json.RawMessage, rekorKey *ecdsa.PublicKey) (*Entry, []byte, Result, error) {
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&e); err != nil {
		return nil, nil, Result{}, fmt.Errorf("rekor: entry: %w", err)
	}
	logID, err := LogID(rekorKey)
	if err != nil {
		return nil, nil, Result{}, err
	}
	if e.LogID != logID {
		return nil, nil, Result{}, errors.New("rekor: entry is from a different log key than the pinned one")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(e.Body)
	if err != nil || len(body) == 0 {
		return nil, nil, Result{}, errors.New("rekor: entry body is not base64")
	}

	// Signed entry timestamp: ECDSA over the canonical JSON of these four
	// fields (keys sorted, no whitespace; every value here is a plain string
	// or integer, so this is also its RFC 8785 form).
	set, err := base64.StdEncoding.Strict().DecodeString(e.Verification.SignedEntryTimestamp)
	if err != nil || len(set) == 0 {
		return nil, nil, Result{}, errors.New("rekor: missing or malformed signed entry timestamp")
	}
	canon := fmt.Sprintf(`{"body":%s,"integratedTime":%d,"logID":%s,"logIndex":%d}`,
		jsonString(e.Body), e.IntegratedTime, jsonString(e.LogID), e.LogIndex)
	h := sha256.Sum256([]byte(canon))
	if !ecdsa.VerifyASN1(rekorKey, h[:], set) {
		return nil, nil, Result{}, errors.New("rekor: signed entry timestamp does not verify")
	}

	leaf := tlog.HashLeaf(body)
	uuidLeaf := uuid
	if len(uuid) == 80 {
		uuidLeaf = uuid[16:]
	}
	if len(uuidLeaf) != 64 || uuidLeaf != hex.EncodeToString(leaf[:]) {
		return nil, nil, Result{}, errors.New("rekor: UUID does not name this entry's body")
	}

	ip := e.Verification.InclusionProof
	if ip == nil {
		return nil, nil, Result{}, errors.New("rekor: entry has no inclusion proof")
	}
	if ip.LogIndex < 0 || ip.TreeSize <= 0 || ip.LogIndex >= ip.TreeSize {
		return nil, nil, Result{}, errors.New("rekor: inclusion proof index out of range")
	}
	root, err := decodeHex32(ip.RootHash)
	if err != nil {
		return nil, nil, Result{}, fmt.Errorf("rekor: inclusion proof root: %w", err)
	}
	path := make([]tlog.Hash, len(ip.Hashes))
	for i, s := range ip.Hashes {
		if path[i], err = decodeHex32(s); err != nil {
			return nil, nil, Result{}, fmt.Errorf("rekor: inclusion proof hash %d: %w", i, err)
		}
	}
	if err := tlog.VerifyInclusion(root, leaf, uint64(ip.LogIndex), uint64(ip.TreeSize), path); err != nil {
		return nil, nil, Result{}, fmt.Errorf("rekor: inclusion proof: %w", err)
	}
	cp, err := verifyCheckpoint([]byte(ip.Checkpoint), rekorKey)
	if err != nil {
		return nil, nil, Result{}, err
	}
	if cp.size != uint64(ip.TreeSize) || cp.root != root {
		return nil, nil, Result{}, errors.New("rekor: inclusion proof does not match Rekor's signed checkpoint")
	}
	return &e, body, Result{IntegratedTime: e.IntegratedTime, LogIndex: e.LogIndex, TreeID: cp.treeID}, nil
}

// VerifyAnchor checks an anchor: VerifyEntry, then that the entry is a
// hashedrekord of exactly digest, signed by the pinned anchoring key.
func VerifyAnchor(a Anchor, digest [32]byte, rekorKey, anchorKey *ecdsa.PublicKey) (Result, error) {
	if a.Format != AnchorFormat {
		return Result{}, fmt.Errorf("rekor: anchor format %q", a.Format)
	}
	_, body, res, err := VerifyEntry(a.UUID, a.Entry, rekorKey)
	if err != nil {
		return Result{}, err
	}
	got, err := AnchoredDigest(body, anchorKey)
	if err != nil {
		return Result{}, err
	}
	if got != digest {
		return Result{}, errors.New("rekor: anchored hash is not this checkpoint")
	}
	return res, nil
}

type rekorCheckpoint struct {
	treeID string
	size   uint64
	root   tlog.Hash
}

// verifyCheckpoint checks a Rekor signed note: "<host> - <treeID>", size,
// base64 root, optional extension lines, a blank line, then signature lines;
// one of them must be an ECDSA signature by the pinned key (key hint = the
// first four bytes of SHA-256 of its PKIX DER) over the note body.
func verifyCheckpoint(raw []byte, key *ecdsa.PublicKey) (rekorCheckpoint, error) {
	bad := func(why string) (rekorCheckpoint, error) {
		return rekorCheckpoint{}, errors.New("rekor: checkpoint: " + why)
	}
	if !utf8.Valid(raw) || len(raw) > 64<<10 {
		return bad("not UTF-8 or too large")
	}
	i := bytes.LastIndex(raw, []byte("\n\n"))
	if i < 0 || raw[len(raw)-1] != '\n' {
		return bad("malformed note")
	}
	text, block := raw[:i+1], raw[i+2:]
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) < 3 {
		return bad("too few lines")
	}
	host, treeID, ok := strings.Cut(lines[0], " - ")
	if !ok || host == "" || treeID == "" {
		return bad("unexpected origin " + strconv.Quote(lines[0]))
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return bad("size")
	}
	rb, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(rb) != 32 {
		return bad("root")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return rekorCheckpoint{}, err
	}
	hint := sha256.Sum256(der)
	digest := sha256.Sum256(text)
	for _, line := range strings.Split(string(block[:len(block)-1]), "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			return bad("malformed signature line")
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok {
			return bad("malformed signature line")
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(b64)
		if err != nil || len(sig) < 5 {
			return bad("malformed signature")
		}
		if name != host || binary.BigEndian.Uint32(sig) != binary.BigEndian.Uint32(hint[:4]) {
			continue
		}
		if ecdsa.VerifyASN1(key, digest[:], sig[4:]) {
			var c rekorCheckpoint
			c.treeID, c.size = treeID, size
			copy(c.root[:], rb)
			return c, nil
		}
		return bad("signature does not verify")
	}
	return bad("no signature from the pinned Rekor key")
}

// SignCheckpoint makes a Rekor-style signed note; used by the test server.
func SignCheckpoint(host, treeID string, size uint64, root tlog.Hash, key *ecdsa.PrivateKey) (string, error) {
	text := fmt.Sprintf("%s - %s\n%d\n%s\n", host, treeID, size, base64.StdEncoding.EncodeToString(root[:]))
	d := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hint := sha256.Sum256(der)
	return text + "\n— " + host + " " + base64.StdEncoding.EncodeToString(append(hint[:4:4], sig...)) + "\n", nil
}

// SignEntryTimestamp makes a signed entry timestamp; used by the test server.
func SignEntryTimestamp(e *Entry, key *ecdsa.PrivateKey) error {
	canon := fmt.Sprintf(`{"body":%s,"integratedTime":%d,"logID":%s,"logIndex":%d}`,
		jsonString(e.Body), e.IntegratedTime, jsonString(e.LogID), e.LogIndex)
	h := sha256.Sum256([]byte(canon))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return err
	}
	e.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func decodeHex32(s string) (tlog.Hash, error) {
	var h tlog.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, errors.New("not 32 bytes of hex")
	}
	copy(h[:], b)
	return h, nil
}

func isHex(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// MaxSearchResults bounds how many entries Search will return.
const MaxSearchResults = 10000

// Search asks Rekor's index for every entry made with key. The index is a
// convenience Rekor keeps, not part of what it signs: a result is checked
// like any entry, but an empty or short answer proves nothing.
func Search(ctx context.Context, hc *http.Client, base string, key *ecdsa.PublicKey) ([]string, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	q, _ := json.Marshal(map[string]any{"publicKey": map[string]string{"format": "x509", "content": base64.StdEncoding.EncodeToString(pubPEM)}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/v1/index/retrieve", bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor: search: HTTP %d: %s", resp.StatusCode, firstLine(b))
	}
	var uuids []string
	if err := json.Unmarshal(b, &uuids); err != nil {
		return nil, fmt.Errorf("rekor: search: %w", err)
	}
	if len(uuids) > MaxSearchResults {
		return nil, fmt.Errorf("rekor: search returned %d entries, more than %d", len(uuids), MaxSearchResults)
	}
	for _, u := range uuids {
		if !isHex(u) {
			return nil, errors.New("rekor: search returned a malformed UUID")
		}
	}
	return uuids, nil
}

// AnchoredDigest checks that a verified entry body is a hashedrekord made
// with anchorKey and returns the digest it anchors.
func AnchoredDigest(body []byte, anchorKey *ecdsa.PublicKey) ([32]byte, error) {
	var d [32]byte
	var hr hashedRekord
	if err := json.Unmarshal(body, &hr); err != nil {
		return d, fmt.Errorf("rekor: entry body: %w", err)
	}
	if hr.Kind != "hashedrekord" || hr.Spec.Data.Hash.Algorithm != "sha256" {
		return d, fmt.Errorf("rekor: entry is %s/%s, want hashedrekord/sha256", hr.Kind, hr.Spec.Data.Hash.Algorithm)
	}
	b, err := hex.DecodeString(hr.Spec.Data.Hash.Value)
	if err != nil || len(b) != 32 {
		return d, errors.New("rekor: anchored hash is not 32 bytes of hex")
	}
	copy(d[:], b)
	pubPEM, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return d, errors.New("rekor: entry public key is not base64")
	}
	k, err := ParsePublicKey(pubPEM)
	if err != nil || !k.Equal(anchorKey) {
		return d, errors.New("rekor: entry was not made with the pinned anchoring key")
	}
	sig, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.Content)
	if err != nil || !ecdsa.VerifyASN1(anchorKey, d[:], sig) {
		return d, errors.New("rekor: anchoring signature does not verify")
	}
	return d, nil
}

type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}
