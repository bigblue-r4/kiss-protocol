// Package rekortest is an in-process stand-in for a Rekor v1 server that
// accepts hashedrekord entries. It is a test double: it checks the request's
// shape and signature, keeps an RFC 6962 tree, and answers like Rekor
// (UUID-keyed entry, signed entry timestamp, inclusion proof, signed
// checkpoint). It is not Rekor.
package rekortest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// Server is a fake Rekor.
type Server struct {
	Key  *ecdsa.PrivateKey
	Now  func() time.Time
	Down bool // answer 503 to everything

	mu      sync.Mutex
	leaves  []tlog.Hash
	bodies  [][]byte
	times   []int64
	byLeaf  map[tlog.Hash]int
	keys    []string // base64 PEM of the signing key, per entry
	Uploads int
}

const treeID = "1234567890"

// New makes a fake Rekor with a fresh key.
func New() *Server {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Server{Key: k, Now: time.Now, byLeaf: map[tlog.Hash]int{}}
}

// Public is the server's log key.
func (s *Server) Public() *ecdsa.PublicKey { return &s.Key.PublicKey }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
		s.add(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/index/retrieve":
		var q struct {
			PublicKey struct{ Format, Content string } `json:"publicKey"`
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if json.Unmarshal(b, &q) != nil || q.PublicKey.Format != "x509" {
			http.Error(w, `{"code":400}`, http.StatusBadRequest)
			return
		}
		out := []string{}
		for i, k := range s.keys {
			if k == q.PublicKey.Content {
				out = append(out, treeIDHex()+hex.EncodeToString(s.leaves[i][:]))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/log/entries/"):
		u := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
		b, err := hex.DecodeString(u[len(u)-64:])
		if err != nil || len(u) < 64 {
			http.Error(w, "bad uuid", http.StatusBadRequest)
			return
		}
		var h tlog.Hash
		copy(h[:], b)
		i, ok := s.byLeaf[h]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		s.reply(w, http.StatusOK, i)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var p struct {
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
	if json.Unmarshal(b, &p) != nil || p.Kind != "hashedrekord" || p.APIVersion != "0.0.1" || p.Spec.Data.Hash.Algorithm != "sha256" {
		http.Error(w, `{"code":400,"message":"bad entry"}`, http.StatusBadRequest)
		return
	}
	digest, err := hex.DecodeString(p.Spec.Data.Hash.Value)
	pemb, err2 := base64.StdEncoding.DecodeString(p.Spec.Signature.PublicKey.Content)
	sig, err3 := base64.StdEncoding.DecodeString(p.Spec.Signature.Content)
	if err != nil || err2 != nil || err3 != nil || len(digest) != 32 {
		http.Error(w, `{"code":400,"message":"bad encoding"}`, http.StatusBadRequest)
		return
	}
	k, err := rekor.ParsePublicKey(pemb)
	if err != nil || !ecdsa.VerifyASN1(k, digest, sig) {
		http.Error(w, `{"code":400,"message":"signature"}`, http.StatusBadRequest)
		return
	}
	// Rekor stores its own canonical form of the entry; re-marshalling the
	// parsed request stands in for that.
	body, _ := json.Marshal(p)
	leaf := tlog.HashLeaf(body)
	s.Uploads++
	if i, ok := s.byLeaf[leaf]; ok {
		w.Header().Set("Location", "/api/v1/log/entries/"+treeIDHex()+hex.EncodeToString(s.leaves[i][:]))
		http.Error(w, `{"code":409,"message":"exists"}`, http.StatusConflict)
		return
	}
	s.byLeaf[leaf] = len(s.leaves)
	s.leaves = append(s.leaves, leaf)
	s.bodies = append(s.bodies, body)
	s.keys = append(s.keys, p.Spec.Signature.PublicKey.Content)
	s.times = append(s.times, s.Now().Unix())
	s.reply(w, http.StatusCreated, len(s.leaves)-1)
}

func treeIDHex() string { return "0000000000003039" }

func (s *Server) reply(w http.ResponseWriter, code, i int) {
	logID, _ := rekor.LogID(s.Public())
	var e rekor.Entry
	e.Body = base64.StdEncoding.EncodeToString(s.bodies[i])
	e.IntegratedTime = s.times[i]
	e.LogID = logID
	e.LogIndex = int64(i) + 1000 // global index differs from the shard index, as in Rekor
	size := uint64(len(s.leaves))
	path, _ := tlog.ProveInclusion(s.leaves, uint64(i))
	root := tlog.Root(s.leaves)
	cp, _ := rekor.SignCheckpoint("rekor.test", treeID, size, root, s.Key)
	hs := make([]string, len(path))
	for j, h := range path {
		hs[j] = hex.EncodeToString(h[:])
	}
	e.Verification.InclusionProof = &struct {
		Checkpoint string   `json:"checkpoint"`
		Hashes     []string `json:"hashes"`
		LogIndex   int64    `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   int64    `json:"treeSize"`
	}{cp, hs, int64(i), hex.EncodeToString(root[:]), int64(size)}
	_ = rekor.SignEntryTimestamp(&e, s.Key)
	uuid := treeIDHex() + hex.EncodeToString(s.leaves[i][:])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]rekor.Entry{uuid: e})
}

// Digest is a convenience for tests.
func Digest(b []byte) [32]byte { return sha256.Sum256(b) }
