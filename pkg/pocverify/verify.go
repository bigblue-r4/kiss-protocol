// Package pocverify is a clean-room verifier for Proof-of-Control Evidence
// tokens (JSON rendering), written from the specification text only:
// schema/README.md, schema/canonicalization.md, schema/poc-evidence.cddl and
// schema/poc-evidence.schema.json of LFDT-ProofOfControl/ov-poc-standard at
// 54a7bc67140b39c9107216cd390dd47c1d42946d (Working Draft v0.1). No upstream
// implementation code was read; upstream vectors are used as test data only.
//
// Checks, in order (the first failure is reported with its code):
//
//	parse / duplicate-key  strict RFC 8259, duplicate member names rejected
//	float-in-claims        no fraction or exponent anywhere in the token
//	hex-case               no tagged digest with uppercase hex, extensions included
//	schema                 required claims, types, enums, digest tags and widths,
//	                       profile URI, absent-not-empty
//	unsupported-alg        only EdDSA (Ed25519) signatures are checked
//	signature              Ed25519 over RFC 8785 canonical(token \ {signature})
//	tree-size              step_index must be a leaf of a tree of tree_size
//	modify-unbound         MODIFY must carry dispatched_snapshot_hash
//	leaf-root              tree_size 1: merkle_root must equal the step's leaf,
//	                       SHA-256(0x00 || canonical({"snapshot","verdict"}))
//
// What a valid result does not mean is listed in Result.Notes.
package pocverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Profile is the only EAT profile whose claims this verifier interprets.
const Profile = "https://advancedaisociety.org/poc/v0.1"

// Rejection codes.
const (
	CodeParse          = "parse"
	CodeDuplicateKey   = "duplicate-key"
	CodeFloat          = "float-in-claims"
	CodeHexCase        = "hex-case"
	CodeSchema         = "schema"
	CodeUnsupportedAlg = "unsupported-alg"
	CodeSignature      = "signature"
	CodeTreeSize       = "tree-size"
	CodeModifyUnbound  = "modify-unbound"
	CodeLeafRoot       = "leaf-root"
)

// Result is the outcome of verifying one token.
type Result struct {
	Code   string   // "" when the token is valid
	Detail string   // why it was rejected
	Notes  []string // what was not (or could not be) checked
}

// OK reports whether the token passed every check.
func (r Result) OK() bool { return r.Code == "" }

func reject(code, format string, a ...any) Result {
	return Result{Code: code, Detail: fmt.Sprintf(format, a...)}
}

var (
	digestRE    = regexp.MustCompile(`^(sha-256:[0-9a-f]{64}|sha-384:[0-9a-f]{96}|sha-512:[0-9a-f]{128}|sha3-256:[0-9a-f]{64})$`)
	taggedAnyRE = regexp.MustCompile(`^(sha-256|sha-384|sha-512|sha3-256):[0-9A-Fa-f]+$`)
	lowerHexRE  = regexp.MustCompile(`^[0-9a-f]+$`)
)

var (
	interceptionPoints = set("TASK_INITIALIZATION", "CONTEXT_ASSEMBLY", "PLAN_GENERATION",
		"PRE_CALL_TOOL_INVOCATION", "POST_CALL_TOOL_RESULT", "MEMORY_WRITE",
		"SUBAGENT_DELEGATION", "TASK_COMPLETION")
	verdicts  = set("ALLOW", "DENY", "MODIFY", "ESCALATE")
	algs      = set("EdDSA", "ES256", "ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-44")
	platforms = set("INTEL_TDX", "AMD_SEV_SNP", "ARM_CCA", "AWS_NITRO", "SOFTWARE")
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Verify checks a token's bytes against the pinned signer keys.
func Verify(token []byte, keys []ed25519.PublicKey) Result {
	v, err := Parse(token)
	if errors.Is(err, ErrDuplicateKey) {
		return reject(CodeDuplicateKey, "%v", err)
	}
	if err != nil {
		return reject(CodeParse, "%v", err)
	}
	if path, lit, ok := findFloat(v, "$"); ok {
		return reject(CodeFloat, "%s is %s: the claim set forbids floating point", path, lit)
	}
	if path, ok := findUpperHexDigest(v, "$"); ok {
		return reject(CodeHexCase, "%s: tagged digest with uppercase hex", path)
	}
	c, r := checkSchema(v)
	if !r.OK() {
		return r
	}
	if c.alg != "EdDSA" {
		return reject(CodeUnsupportedAlg, "alg %s: this verifier checks EdDSA (Ed25519) only", c.alg)
	}
	if r := checkSignature(v, keys); !r.OK() {
		return r
	}
	if c.stepIndex >= c.treeSize {
		return reject(CodeTreeSize, "step_index %d is not a leaf of a tree of %d leaves", c.stepIndex, c.treeSize)
	}
	if c.verdict == "MODIFY" && !c.hasDispatched {
		return reject(CodeModifyUnbound, "verdict MODIFY without dispatched_snapshot_hash")
	}

	var notes []string
	if c.treeSize == 1 {
		if r := checkLeafRoot(c); !r.OK() {
			return r
		}
	} else {
		notes = append(notes, "leaf-to-root binding not checked: tree_size > 1 needs an inclusion proof")
	}
	notes = append(notes, "chain_head not checked: the draft does not define the previous head for step 0")
	if c.platform == "SOFTWARE" {
		notes = append(notes, "platform SOFTWARE: no hardware isolation; evidence supports Tier 2 at most")
	} else {
		notes = append(notes, "platform "+c.platform+": hardware attestation not verified (measurement not compared to reference values)")
	}
	if c.hasDispatched && c.verdict != "MODIFY" {
		notes = append(notes, "dispatched_snapshot_hash present with verdict "+c.verdict)
	}
	return Result{Notes: notes}
}

type claims struct {
	alg, verdict, platform string
	stepIndex, treeSize    uint64
	hasDispatched          bool
	merkleRoot, snapshot   string
}

func checkSchema(tok Value) (claims, Result) {
	var c claims
	bad := func(format string, a ...any) (claims, Result) { return c, reject(CodeSchema, format, a...) }
	if tok.Kind != KindObject {
		return bad("token is not an object")
	}
	for _, k := range []string{"iss", "iat", "nonce", "eat_profile", "poc_claims", "submods"} {
		if _, ok := tok.Get(k); !ok {
			return bad("missing %s", k)
		}
	}
	if p, _ := tok.Get("eat_profile"); p.Kind != KindString || p.Str != Profile {
		return bad("eat_profile is not %s: claims must not be interpreted under an unknown profile", Profile)
	}
	if iss, _ := tok.Get("iss"); !isURI(iss) {
		return bad("iss is not a URI")
	}
	if iat, _ := tok.Get("iat"); iat.Kind != KindNumber {
		return bad("iat is not a number")
	} else if _, err := strconv.ParseInt(iat.Num, 10, 64); err != nil {
		return bad("iat is not an integer")
	}
	if n, _ := tok.Get("nonce"); n.Kind != KindString || utf8.RuneCountInString(n.Str) < 8 {
		return bad("nonce must be a string of at least 8 characters")
	}
	if s, ok := tok.Get("signature"); ok && (s.Kind != KindString || !lowerHexRE.MatchString(s.Str)) {
		return bad("signature is not lowercase hex")
	}

	pc, _ := tok.Get("poc_claims")
	if pc.Kind != KindObject {
		return bad("poc_claims is not an object")
	}
	for _, k := range []string{"agent_id", "initiating_user", "agbom_digest", "interception_point",
		"step_index", "chain_head", "merkle_root", "tree_size", "policy_bundle_hash",
		"target_resource", "canonical_snapshot_hash", "path_summary_hash", "verdict", "alg"} {
		if _, ok := pc.Get(k); !ok {
			return bad("poc_claims.%s is missing", k)
		}
	}
	for _, k := range []string{"agbom_digest", "chain_head", "merkle_root", "policy_bundle_hash",
		"canonical_snapshot_hash", "path_summary_hash", "dispatched_snapshot_hash"} {
		d, ok := pc.Get(k)
		if !ok {
			continue
		}
		if d.Kind != KindString || !digestRE.MatchString(d.Str) {
			return bad("poc_claims.%s is not an algorithm-tagged digest of the right width", k)
		}
	}
	for _, k := range []string{"agent_id", "initiating_user"} {
		if s, _ := pc.Get(k); s.Kind != KindString || s.Str == "" {
			return bad("poc_claims.%s must be a non-empty string", k)
		}
	}
	if s, _ := pc.Get("target_resource"); s.Kind != KindString {
		return bad("poc_claims.target_resource is not a string")
	}
	if s, ok := pc.Get("reason"); ok && (s.Kind != KindString || s.Str == "") {
		return bad("poc_claims.reason present but empty: absent is not empty")
	}
	if s, _ := pc.Get("interception_point"); s.Kind != KindString || !interceptionPoints[s.Str] {
		return bad("poc_claims.interception_point is not one of the eight C7.1 hooks")
	}
	if s, _ := pc.Get("verdict"); s.Kind != KindString || !verdicts[s.Str] {
		return bad("poc_claims.verdict is not ALLOW, DENY, MODIFY or ESCALATE")
	} else {
		c.verdict = s.Str
	}
	if s, _ := pc.Get("alg"); s.Kind != KindString || !algs[s.Str] {
		return bad("poc_claims.alg is not a known signature algorithm")
	} else {
		c.alg = s.Str
	}
	var err error
	if c.stepIndex, err = uintClaim(pc, "step_index"); err != nil {
		return bad("poc_claims.step_index: %v", err)
	}
	if c.treeSize, err = uintClaim(pc, "tree_size"); err != nil || c.treeSize < 1 {
		return bad("poc_claims.tree_size must be an integer >= 1")
	}
	_, c.hasDispatched = pc.Get("dispatched_snapshot_hash")
	mr, _ := pc.Get("merkle_root")
	sn, _ := pc.Get("canonical_snapshot_hash")
	c.merkleRoot, c.snapshot = mr.Str, sn.Str

	sm, _ := tok.Get("submods")
	if sm.Kind != KindObject {
		return bad("submods is not an object")
	}
	at, ok := sm.Get("attestation")
	if !ok || at.Kind != KindObject {
		return bad("submods.attestation is missing")
	}
	if p, _ := at.Get("platform"); p.Kind != KindString || !platforms[p.Str] {
		return bad("submods.attestation.platform is not a known platform")
	} else {
		c.platform = p.Str
	}
	if m, ok := at.Get("measurement"); !ok || m.Kind != KindString || !digestRE.MatchString(m.Str) {
		return bad("submods.attestation.measurement is not an algorithm-tagged digest")
	}
	if u, ok := at.Get("reference_values_uri"); ok && !isURI(u) {
		return bad("submods.attestation.reference_values_uri is not a URI")
	}
	return c, Result{}
}

func uintClaim(obj Value, k string) (uint64, error) {
	v, _ := obj.Get(k)
	if v.Kind != KindNumber {
		return 0, errors.New("not an integer")
	}
	n, err := strconv.ParseUint(v.Num, 10, 64)
	if err != nil {
		return 0, errors.New("not a non-negative integer")
	}
	return n, nil
}

func isURI(v Value) bool {
	if v.Kind != KindString {
		return false
	}
	u, err := url.Parse(v.Str)
	return err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "")
}

func checkSignature(tok Value, keys []ed25519.PublicKey) Result {
	if len(keys) == 0 {
		return reject(CodeSignature, "no signer key pinned")
	}
	sigV, ok := tok.Get("signature")
	if !ok {
		return reject(CodeSignature, "token is not signed")
	}
	sig, _ := hex.DecodeString(sigV.Str)
	if len(sig) != ed25519.SignatureSize {
		return reject(CodeSignature, "signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	unsigned := Value{Kind: KindObject}
	for _, m := range tok.Members {
		if m.Key != "signature" {
			unsigned.Members = append(unsigned.Members, m)
		}
	}
	msg, err := Canonical(unsigned)
	if err != nil {
		return reject(CodeSignature, "canonicalize: %v", err)
	}
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return Result{}
		}
	}
	return reject(CodeSignature, "signature does not verify under any pinned key")
}

// LeafHash is the Merkle leaf for one step (canonicalization.md, "The leaf
// and the tree"): SHA-256(0x00 || canonical({"snapshot": hex, "verdict": v})),
// where hex is the snapshot digest without its algorithm tag.
func LeafHash(snapshotHex, verdict string) [32]byte {
	obj := Value{Kind: KindObject, Members: []Member{
		{"snapshot", Value{Kind: KindString, Str: snapshotHex}},
		{"verdict", Value{Kind: KindString, Str: verdict}},
	}}
	b, _ := Canonical(obj)
	return sha256.Sum256(append([]byte{0x00}, b...))
}

func checkLeafRoot(c claims) Result {
	alg, rootHex, _ := strings.Cut(c.merkleRoot, ":")
	if alg != "sha-256" {
		return Result{Notes: []string{"leaf-to-root binding not checked: merkle_root is not sha-256"}}
	}
	_, snapHex, _ := strings.Cut(c.snapshot, ":")
	leaf := LeafHash(snapHex, c.verdict)
	root, _ := hex.DecodeString(rootHex)
	if !bytes.Equal(leaf[:], root) {
		return reject(CodeLeafRoot, "tree_size 1 but merkle_root is not the leaf of (canonical_snapshot_hash, %s)", c.verdict)
	}
	return Result{}
}

func findFloat(v Value, path string) (string, string, bool) {
	switch v.Kind {
	case KindNumber:
		if strings.ContainsAny(v.Num, ".eE") {
			return path, v.Num, true
		}
	case KindArray:
		for i, it := range v.Items {
			if p, l, ok := findFloat(it, fmt.Sprintf("%s[%d]", path, i)); ok {
				return p, l, true
			}
		}
	case KindObject:
		for _, m := range v.Members {
			if p, l, ok := findFloat(m.Val, path+"."+m.Key); ok {
				return p, l, true
			}
		}
	}
	return "", "", false
}

func findUpperHexDigest(v Value, path string) (string, bool) {
	switch v.Kind {
	case KindString:
		if taggedAnyRE.MatchString(v.Str) && strings.ToLower(v.Str) != v.Str {
			return path, true
		}
	case KindArray:
		for i, it := range v.Items {
			if p, ok := findUpperHexDigest(it, fmt.Sprintf("%s[%d]", path, i)); ok {
				return p, true
			}
		}
	case KindObject:
		for _, m := range v.Members {
			if p, ok := findUpperHexDigest(m.Val, path+"."+m.Key); ok {
				return p, true
			}
		}
	}
	return "", false
}
