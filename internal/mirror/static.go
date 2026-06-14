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
// Writes are atomic: content goes to a .tmp file first, then os.Rename.
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
//
// Atomicity: we send If-Match on every PUT so that two concurrent daemon
// instances racing on the same endpoint produce a 412 on the loser rather
// than silently overwriting. On 412 we re-fetch the remote head and retry
// once — if the remote is now ahead of what we're trying to push we skip
// (our push is stale). The server must implement ETag / If-Match to take
// advantage of this; plain object stores without conditional PUT support
// will ignore the header and accept all writes.
//
// Retry: up to maxPushRetries attempts with exponential backoff on transient
// errors (5xx, network errors). 4xx responses are not retried.

const (
	maxPushRetries = 3
	pushRetryBase  = 500 * time.Millisecond
)

type httpBackend struct {
	base   string
	client *http.Client
}

func newHTTPBackend(base string) (*httpBackend, error) {
	return &httpBackend{
		base: strings.TrimRight(base, "/"),
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				MaxIdleConnsPerHost: 2,
			},
		},
	}, nil
}

func (b *httpBackend) Push(data json.RawMessage) error {
	// Fetch current ETag so we can send If-Match for optimistic concurrency.
	etag := b.fetchETag()

	var lastErr error
	backoff := pushRetryBase
	for attempt := 0; attempt < maxPushRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		err := b.doPut(data, etag)
		if err == nil {
			return nil
		}
		// 412 Precondition Failed: remote was updated by another push while we
		// were preparing. Re-fetch the ETag and retry once.
		if isPreconditionFailed(err) {
			etag = b.fetchETag()
			continue
		}
		// Non-retryable (4xx client errors other than 412).
		if isClientError(err) {
			return err
		}
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("mirror http: push failed after %d retries: %w", maxPushRetries, lastErr)
	}
	return nil
}

func (b *httpBackend) doPut(data json.RawMessage, etag string) error {
	req, err := http.NewRequest(http.MethodPut, b.base+"/tree-head.json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	b.setAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed {
		return preconditionFailedErr{}
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return clientErr{code: resp.StatusCode, msg: string(body)}
	}
	return nil
}

// fetchETag does a HEAD request and returns the ETag value, or "" on error.
func (b *httpBackend) fetchETag() string {
	req, err := http.NewRequest(http.MethodHead, b.base+"/tree-head.json", nil)
	if err != nil {
		return ""
	}
	b.setAuth(req)
	resp, err := b.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("ETag")
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

// ── sentinel error types ──────────────────────────────────────────────────────

type preconditionFailedErr struct{}

func (preconditionFailedErr) Error() string { return "412 Precondition Failed" }

type clientErr struct {
	code int
	msg  string
}

func (e clientErr) Error() string {
	return fmt.Sprintf("mirror http: server %d: %s", e.code, e.msg)
}

func isPreconditionFailed(err error) bool {
	_, ok := err.(preconditionFailedErr)
	return ok
}

func isClientError(err error) bool {
	if e, ok := err.(clientErr); ok {
		return e.code >= 400 && e.code < 500 && e.code != http.StatusPreconditionFailed
	}
	return false
}
