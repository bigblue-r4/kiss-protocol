package mirror

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestFileBackendRoundtrip(t *testing.T) {
	dir := t.TempDir()
	m, err := newFileBackend(dir)
	if err != nil {
		t.Fatalf("newFileBackend: %v", err)
	}

	head := json.RawMessage(`{"size":5,"root":"abcdef","ts":"2026-01-01T00:00:00Z","mac":"123456"}`)
	if err := m.Push(head); err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := m.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != string(head) {
		t.Errorf("Fetch = %s, want %s", got, head)
	}
}

func TestFileBackendSecondPushWins(t *testing.T) {
	dir := t.TempDir()
	m, _ := newFileBackend(dir)

	_ = m.Push(json.RawMessage(`{"size":1,"root":"aaa"}`))
	_ = m.Push(json.RawMessage(`{"size":2,"root":"bbb"}`))

	got, _ := m.Fetch()
	var head struct {
		Root string `json:"root"`
	}
	_ = json.Unmarshal(got, &head)
	if head.Root != "bbb" {
		t.Errorf("second push should win: got root=%q", head.Root)
	}
}

func TestFileBackendFetchMissing(t *testing.T) {
	dir := t.TempDir()
	m, _ := newFileBackend(dir)
	if _, err := m.Fetch(); err == nil {
		t.Error("expected error fetching before any push, got nil")
	}
}

func TestHTTPBackendRoundtrip(t *testing.T) {
	var mu sync.Mutex
	var stored json.RawMessage

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			mu.Lock()
			stored = json.RawMessage(data)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			mu.Lock()
			data := stored
			mu.Unlock()
			if data == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	m, err := newHTTPBackend(srv.URL)
	if err != nil {
		t.Fatalf("newHTTPBackend: %v", err)
	}

	head := json.RawMessage(`{"size":3,"root":"deadbeef","ts":"2026-01-01T00:00:00Z","mac":"cafe"}`)
	if err := m.Push(head); err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := m.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != string(head) {
		t.Errorf("Fetch = %s, want %s", got, head)
	}
}

func TestHTTPBackendFetch404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m, _ := newHTTPBackend(srv.URL)
	if _, err := m.Fetch(); err == nil {
		t.Error("expected error on 404, got nil")
	}
}

func TestHTTPBackendPush5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	m, _ := newHTTPBackend(srv.URL)
	if err := m.Push(json.RawMessage(`{}`)); err == nil {
		t.Error("expected error on 500, got nil")
	}
}

func TestOpenFileURL(t *testing.T) {
	dir := t.TempDir()
	m, err := Open("file://" + dir)
	if err != nil {
		t.Fatalf("Open file://: %v", err)
	}
	if m == nil {
		t.Fatal("Open returned nil mirror")
	}
}

func TestOpenHTTPURL(t *testing.T) {
	m, err := Open("https://example.com/witness")
	if err != nil {
		t.Fatalf("Open https://: %v", err)
	}
	if m == nil {
		t.Fatal("Open returned nil mirror")
	}
}

func TestOpenS3URLWithoutTag(t *testing.T) {
	_, err := Open("s3://mybucket/prefix")
	// Without -tags s3, this should return an error about the missing build tag.
	if err == nil {
		t.Error("expected error for s3:// without -tags s3, got nil")
	}
}

func TestOpenUnknownScheme(t *testing.T) {
	if _, err := Open("ftp://example.com"); err == nil {
		t.Error("expected error for unknown scheme, got nil")
	}
}
