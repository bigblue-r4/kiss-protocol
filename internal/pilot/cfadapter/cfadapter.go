// Package cfadapter receives Cloudflare Logpush HTTP-destination uploads
// and writes each record to the pilot's NDJSON feed, normalised and tagged
// with its batch, so the evidence log records it and the verifier can show
// missing or repeated batch entries.
//
// It is a sink only (shadow mode): it holds no Cloudflare credential, makes
// no outbound request, and a failure here loses evidence, never traffic.
//
// Built from Cloudflare's public Logpush documentation only (HTTP destination,
// output options, the ai_gateway_events dataset, read 2026-11-25). Where the
// documentation is silent (Content-Encoding header, retries, duplicates,
// expected status), the adapter is defensive: it detects gzip by its magic
// bytes, answers 200 only after the batch is on disk, and names each batch by
// the hash of its content so a re-delivered batch is visible as a duplicate.
package cfadapter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Defaults.
const (
	DefaultMaxCompressed   = 64 << 20
	DefaultMaxUncompressed = 512 << 20
	DefaultMaxLine         = 60 << 10
	Source                 = "cf-logpush"
)

// DefaultDropFields are replaced by their SHA-256: the ai_gateway_events
// request and response bodies are documented as encrypted blobs, and the
// pilot does not need their content to show they were received.
var DefaultDropFields = []string{"RequestBody", "ResponseBody"}

// Handler is the HTTP sink.
type Handler struct {
	Feed            string // NDJSON file the evidence log ingests
	Token           string // required bearer token (Logpush: header_Authorization)
	Dataset         string // default dataset name if the request has none
	DropFields      []string
	MaxCompressed   int64
	MaxUncompressed int64
	MaxLine         int
	Now             func() time.Time

	mu sync.Mutex
}

// Entry is one feed line.
type Entry struct {
	Source       string          `json:"source"`
	Dataset      string          `json:"dataset"`
	Batch        string          `json:"batch"`
	BatchIndex   int             `json:"batch_index"`
	BatchCount   int             `json:"batch_count"`
	Received     string          `json:"adapter_received"`
	Control      string          `json:"control,omitempty"`
	Fields       json.RawMessage `json:"fields,omitempty"`
	InvalidLine  string          `json:"invalid_line_sha256,omitempty"`
	InvalidCause string          `json:"invalid_cause,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorised(r) {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	maxC, maxU := h.MaxCompressed, h.MaxUncompressed
	if maxC == 0 {
		maxC = DefaultMaxCompressed
	}
	if maxU == 0 {
		maxU = DefaultMaxUncompressed
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxC+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(raw)) > maxC {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	body := raw
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		body, err = io.ReadAll(io.LimitReader(zr, maxU+1))
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxU {
			http.Error(w, "batch too large uncompressed", http.StatusRequestEntityTooLarge)
			return
		}
	}
	dataset := r.URL.Query().Get("dataset")
	if dataset == "" {
		dataset = h.Dataset
	}
	entries := h.Normalise(body, dataset)
	if err := h.write(entries); err != nil {
		// Not on disk: tell the sender, so a retry (if it makes one) can succeed.
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) authorised(r *http.Request) bool {
	if h.Token == "" {
		return false // never run open
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(h.Token)) == 1
}

// Normalise turns one decompressed upload into feed entries.
func (h *Handler) Normalise(body []byte, dataset string) []Entry {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	maxLine := h.MaxLine
	if maxLine == 0 {
		maxLine = DefaultMaxLine
	}
	drop := h.DropFields
	if drop == nil {
		drop = DefaultDropFields
	}
	sum := sha256.Sum256(body)
	batch := hex.EncodeToString(sum[:16])
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64<<10), len(body)+1)
	for sc.Scan() {
		if l := bytes.TrimSpace(sc.Bytes()); len(l) > 0 {
			lines = append(lines, append([]byte(nil), l...))
		}
	}
	ts := now().UTC().Format(time.RFC3339Nano)
	out := make([]Entry, 0, len(lines))
	for i, l := range lines {
		e := Entry{Source: Source, Dataset: dataset, Batch: batch, BatchIndex: i, BatchCount: len(lines), Received: ts}
		if len(lines) == 1 && bytes.Equal(l, []byte(`{"content":"tests"}`)) {
			e.Control = "destination_validation"
			out = append(out, e)
			continue
		}
		var m map[string]json.RawMessage
		switch {
		case len(l) > maxLine:
			e.InvalidCause = fmt.Sprintf("record longer than %d bytes", maxLine)
		case json.Unmarshal(l, &m) != nil:
			e.InvalidCause = "not a JSON object"
		}
		if e.InvalidCause != "" {
			s := sha256.Sum256(l)
			e.InvalidLine = hex.EncodeToString(s[:])
			out = append(out, e)
			continue
		}
		for _, f := range drop {
			if v, ok := m[f]; ok {
				s := sha256.Sum256(v)
				delete(m, f)
				m[f+"_sha256"], _ = json.Marshal(hex.EncodeToString(s[:]))
			}
		}
		e.Fields, _ = json.Marshal(m)
		out = append(out, e)
	}
	return out
}

func (h *Handler) write(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	f, err := os.OpenFile(h.Feed, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
