package mirror

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// FuzzPushJSON fuzzes the HTTP backend's Push method with arbitrary JSON payloads.
// Must not panic regardless of input.
func FuzzPushJSON(f *testing.F) {
	f.Add([]byte(`{"size":1,"root":"aa","ts":"2026-01-01T00:00:00Z","mac":"bb"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte{})
	f.Add([]byte(`"string"`))
	f.Add([]byte(`{"size":` + string(make([]byte, 64)) + `}`))

	var mu sync.Mutex
	var stored []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			mu.Lock()
			stored = data
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
		}
	}))
	defer srv.Close()

	m, err := newHTTPBackend(srv.URL)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Push must not panic.
		_ = m.Push(json.RawMessage(data))
	})
}

// FuzzOpen fuzzes the Open dispatcher with arbitrary URL strings.
// Must not panic regardless of input.
func FuzzOpen(f *testing.F) {
	f.Add("file:///tmp/x")
	f.Add("https://example.com")
	f.Add("s3://bucket/key")
	f.Add("ftp://example.com")
	f.Add("")
	f.Add("://")
	f.Add(string(make([]byte, 256)))

	f.Fuzz(func(t *testing.T, rawURL string) {
		// Open must not panic regardless of input.
		_, _ = Open(rawURL)
	})
}

// FuzzFileBackend fuzzes the file backend's Push/Fetch cycle.
func FuzzFileBackend(f *testing.F) {
	f.Add([]byte(`{"size":1,"root":"aa"}`))
	f.Add([]byte{})
	f.Add([]byte("\x00\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		m, err := newFileBackend(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Push then Fetch must not panic.
		if err := m.Push(json.RawMessage(data)); err == nil {
			_, _ = m.Fetch()
		}
	})
}
