// Package testwitness is a minimal in-process C2SP tlog-witness used by the
// pilot's tests and adversarial runner. It is a test double: the pilot demo
// runs transparency-dev/witness (omniwitness), an independent implementation.
//
// It follows the add-checkpoint rules of c2sp.org/tlog-witness: 404 unknown
// origin, 403 no valid log signature, 400 old > size, 409 old size mismatch
// (body = held size, text/x.tlog.size), 422 bad consistency proof, and it
// persists the new state before it answers.
package testwitness

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// Witness is one cosigner.
type Witness struct {
	Name string
	priv ed25519.PrivateKey
	Now  func() time.Time

	mu    sync.Mutex
	logs  map[string]string // origin -> log verifier key
	state map[string]held
	Down  bool // answer 503 to everything (a witness outage)
}

type held struct {
	size uint64
	root tlog.Hash
}

// New makes a witness with a fresh key.
func New(name string) *Witness {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return &Witness{Name: name, priv: priv, Now: time.Now, logs: map[string]string{}, state: map[string]held{}}
}

// Key returns the witness's verifier key.
func (w *Witness) Key() checkpoint.CosignerKey {
	return checkpoint.NewCosignerKey(w.Name, w.priv.Public().(ed25519.PublicKey))
}

// PrivateKey exposes the key so adversarial cases can model a compromised
// witness.
func (w *Witness) PrivateKey() ed25519.PrivateKey { return w.priv }

// AddLog trusts a log origin with its verifier key.
func (w *Witness) AddLog(origin, vkey string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs[origin] = vkey
}

// Held returns the latest cosigned size for an origin.
func (w *Witness) Held(origin string) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state[origin].size
}

// ServeHTTP implements POST /add-checkpoint.
func (w *Witness) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	down := w.Down
	w.mu.Unlock()
	if down {
		http.Error(rw, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/add-checkpoint" {
		http.NotFound(rw, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(rw, "read", http.StatusBadRequest)
		return
	}
	line, status, size := w.Add(body)
	switch status {
	case http.StatusOK:
		_, _ = io.WriteString(rw, line)
	case http.StatusConflict:
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(status)
		fmt.Fprintf(rw, "%d\n", size)
	default:
		http.Error(rw, http.StatusText(status), status)
	}
}

// Add processes one add-checkpoint body and returns the cosignature line,
// the HTTP status, and for 409 the held size.
func (w *Witness) Add(body []byte) (string, int, uint64) {
	oldSize, proof, signed, err := checkpoint.ParseAddCheckpointBody(body)
	if err != nil {
		return "", http.StatusBadRequest, 0
	}
	s, err := checkpoint.Open(signed)
	if err != nil {
		return "", http.StatusBadRequest, 0
	}
	c := s.Checkpoint
	w.mu.Lock()
	defer w.mu.Unlock()
	vkey, ok := w.logs[c.Origin]
	if !ok {
		return "", http.StatusNotFound, 0
	}
	if s.VerifyLog(vkey) != nil {
		return "", http.StatusForbidden, 0
	}
	if oldSize > c.Size {
		return "", http.StatusBadRequest, 0
	}
	h := w.state[c.Origin]
	if oldSize != h.size {
		return "", http.StatusConflict, h.size
	}
	oldRoot := h.root
	if h.size == 0 {
		oldRoot = tlog.EmptyRoot
	}
	if c.Size == 0 && c.Root != tlog.EmptyRoot {
		return "", http.StatusUnprocessableEntity, 0
	}
	if err := tlog.VerifyConsistency(oldSize, c.Size, oldRoot, c.Root, proof); err != nil {
		return "", http.StatusUnprocessableEntity, 0
	}
	w.state[c.Origin] = held{size: c.Size, root: c.Root}
	ts := uint64(w.Now().Unix())
	return checkpoint.Cosign(w.Name, w.priv, s.Text, ts).String(), http.StatusOK, 0
}
