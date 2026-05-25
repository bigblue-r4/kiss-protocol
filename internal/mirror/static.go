package mirror

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ── File backend ──────────────────────────────────────────────────────────────

// fileBackend writes tree-head.json into a local directory.
// Writes are atomic (write-to-temp + rename).
type fileBackend struct{ dir string }

func newFileBackend(dir string) (*fileBackend, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mirror file: create dir %q: %w", dir, err)
	}
	return &fileBackend{dir: dir}, nil
}

func (b *fileBackend) Push(data json.RawMessage) error {
	tmp := filepath.Join(b.dir, "tree-head.json.tmp")
	dst := filepath.Join(b.dir, "tree-head.json")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("mirror file: write: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("mirror file: rename: %w", err)
	}
	return nil
}

func (b *fileBackend) Fetch() (json.RawMessage, error) {
	data, err := os.ReadFile(filepath.Join(b.dir, "tree-head.json"))
	if err != nil {
		return nil, fmt.Errorf("mirror file: read: %w", err)
	}
	return json.RawMessage(data), nil
}

// ── HTTP/HTTPS backend ────────────────────────────────────────────────────────
//
// Push:  PUT  <base>/tree-head.json  (Content-Type: application/json)
// Fetch: GET  <base>/tree-head.json
// Auth:  Bearer token from WITNESS_MIRROR_TOKEN env var (optional).

type httpBackend struct {
	base   string
	client *http.Client
}

func newHTTPBackend(base string) (*httpBackend, error) {
	return &httpBackend{
		base: strings.TrimRight(base, "/"),
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

func (b *httpBackend) Push(data json.RawMessage) error {
	req, err := http.NewRequest(http.MethodPut, b.base+"/tree-head.json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("mirror http: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	b.setAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("mirror http: push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("mirror http: push: server %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (b *httpBackend) Fetch() (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodGet, b.base+"/tree-head.json", nil)
	if err != nil {
		return nil, fmt.Errorf("mirror http: build request: %w", err)
	}
	b.setAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mirror http: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("mirror http: fetch: server %d: %s", resp.StatusCode, body)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("mirror http: fetch: read body: %w", err)
	}
	return json.RawMessage(data), nil
}

func (b *httpBackend) setAuth(req *http.Request) {
	if tok := os.Getenv("WITNESS_MIRROR_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}
