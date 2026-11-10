package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/core"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// MaxBody bounds every request body.
const MaxBody = 64 << 10

// DecideRequest is the /v1/decide body. Request and each approval must be in
// canonical form (proto.Canonical): the gate hashes exactly what it is sent.
type DecideRequest struct {
	Request   json.RawMessage   `json:"request"`
	Approvals []json.RawMessage `json:"approvals,omitempty"`
}

type ctxKey struct{}

// Handler returns the API. allowed lists the uids that may call it (checked
// with SO_PEERCRED on every connection); an empty list allows only the
// gate's own uid.
func (d *Daemon) Handler(allowed []int) http.Handler {
	ok := map[int]bool{os.Getuid(): true}
	for _, u := range allowed {
		ok[u] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decide", d.handleDecide)
	mux.HandleFunc("/v1/epoch", d.handleEpoch)
	mux.HandleFunc("/v1/status", d.handleStatus)
	mux.HandleFunc("/v1/reset", d.handleReset)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, known := r.Context().Value(ctxKey{}).(int)
		if !known || !ok[uid] {
			http.Error(w, "caller uid not allowed", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		mux.ServeHTTP(w, r)
	})
}

// Serve listens on the unix socket at path (mode 0660; group access is how
// a protected service is let in) until ctx ends.
func (d *Daemon) Serve(ctx context.Context, path string, allowed []int) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path) // stale socket from a previous run
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{
		Handler:           d.Handler(allowed),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      3 * time.Minute, // longer than the longest commit-wait timeout
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if uid, ok := peerUID(c); ok {
				return context.WithValue(ctx, ctxKey{}, uid)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx) // Serve returns ErrServerClosed either way
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // status already sent; nothing left to report to
}

func (d *Daemon) handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	bad := func(err error) {
		writeJSON(w, http.StatusBadRequest, Decision{Outcome: string(core.Deny),
			Reasons: []string{string(core.RequestInvalid)}, Detail: err.Error()})
	}
	var body DecideRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		bad(err)
		return
	}
	req, err := proto.DecodeActionRequest(body.Request)
	if err != nil {
		bad(err)
		return
	}
	if len(body.Approvals) > 16 {
		bad(errors.New("at most 16 approvals"))
		return
	}
	var apps []proto.Approval
	for _, raw := range body.Approvals {
		a, err := proto.DecodeApproval(raw)
		if err != nil {
			bad(err)
			return
		}
		apps = append(apps, a)
	}
	writeJSON(w, http.StatusOK, d.Decide(r.Context(), req, apps))
}

func (d *Daemon) handleEpoch(w http.ResponseWriter, r *http.Request) {
	raw, err := d.Epoch()
	if err != nil || raw == nil {
		http.Error(w, "no signed epoch", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.Status())
}

func (d *Daemon) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := proto.DecodeResetBundle(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ev, err := d.Reset(b)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": ev.Scope.String(), "epoch": ev.Epoch, "approvers": ev.Approvers})
}
