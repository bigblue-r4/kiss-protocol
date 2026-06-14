//go:build s3

package mirror

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	s3Service        = "s3"
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// s3Backend writes tree-head.json to any S3-compatible object store using
// path-style requests and AWS Signature Version 4.
//
// Required environment variables:
//
//	AWS_ACCESS_KEY_ID      — access key
//	AWS_SECRET_ACCESS_KEY  — secret key
//	AWS_DEFAULT_REGION     — region (default: us-east-1)
//	AWS_ENDPOINT_URL       — custom endpoint for non-AWS services (R2, MinIO, …)
type s3Backend struct {
	bucket   string
	key      string // object key, e.g. "prefix/tree-head.json"
	endpoint string // base URL, e.g. "https://s3.us-east-1.amazonaws.com"
	host     string // Host header value (hostname only)
	region   string
	accessID string
	secret   string
	client   *http.Client
}

func newS3Backend(rawURL string) (*s3Backend, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("s3 mirror: parse url: %w", err)
	}
	bucket := u.Host
	prefix := strings.TrimPrefix(strings.TrimSuffix(u.Path, "/"), "/")
	key := "tree-head.json"
	if prefix != "" {
		key = prefix + "/" + key
	}

	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	accessID := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessID == "" || secret == "" {
		return nil, fmt.Errorf("s3 mirror: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}

	endpoint := strings.TrimRight(os.Getenv("AWS_ENDPOINT_URL"), "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://s3.%s.amazonaws.com", region)
	}
	epURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("s3 mirror: parse endpoint: %w", err)
	}

	return &s3Backend{
		bucket:   bucket,
		key:      key,
		endpoint: endpoint,
		host:     epURL.Host,
		region:   region,
		accessID: accessID,
		secret:   secret,
		client:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (b *s3Backend) objectURL() string {
	return fmt.Sprintf("%s/%s/%s", b.endpoint, b.bucket, b.key)
}

// Push writes the tree head to S3 with version metadata and exponential-backoff
// retry on transient failures. We include an x-amz-meta-witness-size header
// derived from the JSON payload so that operators can script monotonicity
// checks server-side (e.g. via S3 Object Lambda or a custom authorizer).
func (b *s3Backend) Push(data json.RawMessage) error {
	// Extract size from the payload for version metadata — best-effort.
	var head struct {
		Size uint64 `json:"size"`
	}
	_ = json.Unmarshal(data, &head)

	var lastErr error
	backoff := pushRetryBase
	for attempt := 0; attempt < maxPushRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		if err := b.doPut(data, head.Size); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("s3 push: failed after %d retries: %w", maxPushRetries, lastErr)
}

func (b *s3Backend) doPut(data json.RawMessage, treeSize uint64) error {
	body := []byte(data)
	payHash := hexSHA256(body)

	req, err := http.NewRequest(http.MethodPut, b.objectURL(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("s3 push: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-amz-content-sha256", payHash)
	// Monotonicity hint: operators can use this metadata in lifecycle policies
	// or Lambda authorizers to reject out-of-order writes.
	req.Header.Set("x-amz-meta-witness-size", fmt.Sprintf("%d", treeSize))
	b.sigV4(req, payHash)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3 push: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusNoContent {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 push: server %d: %s", resp.StatusCode, rb)
	}
	return nil
}

func (b *s3Backend) Fetch() (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodGet, b.objectURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("s3 fetch: %w", err)
	}
	req.Header.Set("x-amz-content-sha256", emptyPayloadHash)
	b.sigV4(req, emptyPayloadHash)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("s3 fetch: server %d: %s", resp.StatusCode, rb)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("s3 fetch: read body: %w", err)
	}
	return json.RawMessage(data), nil
}

// sigV4 adds AWS Signature Version 4 authentication headers to req.
// ref: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
func (b *s3Backend) sigV4(req *http.Request, payloadHashHex string) {
	now := time.Now().UTC()
	date := now.Format("20060102")
	datetime := now.Format("20060102T150405Z")
	req.Header.Set("x-amz-date", datetime)

	// Build canonical headers (sorted, lowercase names, trimmed values).
	hdrs := map[string]string{
		"host":                 b.host,
		"x-amz-content-sha256": payloadHashHex,
		"x-amz-date":           datetime,
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		hdrs["content-type"] = ct
	}

	keys := make([]string, 0, len(hdrs))
	for k := range hdrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canHdr strings.Builder
	for _, k := range keys {
		canHdr.WriteString(k)
		canHdr.WriteByte(':')
		canHdr.WriteString(hdrs[k])
		canHdr.WriteByte('\n')
	}
	signedHdrs := strings.Join(keys, ";")

	// Canonical URI: path-style, segments individually percent-encoded.
	canURI := "/" + b.bucket + "/" + s3CanonPath(b.key)

	canReq := strings.Join([]string{
		req.Method,
		canURI,
		"", // no query string
		canHdr.String(),
		signedHdrs,
		payloadHashHex,
	}, "\n")

	credScope := strings.Join([]string{date, b.region, s3Service, "aws4_request"}, "/")
	toSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		datetime,
		credScope,
		hexSHA256([]byte(canReq)),
	}, "\n")

	sigKey := s3DeriveKey(b.secret, date, b.region)
	sig := hex.EncodeToString(s3HMAC(sigKey, []byte(toSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		b.accessID, credScope, signedHdrs, sig,
	))
}

// s3CanonPath percent-encodes each path segment but preserves '/'.
func s3CanonPath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(url.QueryEscape(p), "+", "%20")
	}
	return strings.Join(parts, "/")
}

func s3DeriveKey(secret, date, region string) []byte {
	k := s3HMAC([]byte("AWS4"+secret), []byte(date))
	k = s3HMAC(k, []byte(region))
	k = s3HMAC(k, []byte(s3Service))
	return s3HMAC(k, []byte("aws4_request"))
}

func s3HMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hexSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
