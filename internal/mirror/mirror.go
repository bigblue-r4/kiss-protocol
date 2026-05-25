// Package mirror implements backends for publishing and fetching the Witness
// Merkle tree head to an operator-controlled external store.
//
// The mirror stores the signed tree head JSON (< 1 KiB). It does not store
// the full encrypted log. The tree head is self-authenticating: it contains
// an ed25519 signature and a BLAKE3-keyed MAC, so any holder of the operator's
// public key can verify it independently of this daemon.
//
// Supported backends:
//
//	file:///path/to/dir          — local filesystem; useful for syncing to
//	                               a remote via rsync/scp
//	https://host/path            — HTTP(S) PUT/GET; Bearer token via
//	                               WITNESS_MIRROR_TOKEN env var
//	s3://bucket/prefix           — S3-compatible object store; requires
//	                               -tags s3 and AWS_* env vars
//
// See docs/mirror-setup.md for configuration details.
package mirror

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Mirror pushes and fetches the Merkle tree head as opaque JSON.
// The JSON is not interpreted by this package; callers unmarshal as needed.
type Mirror interface {
	// Push uploads the tree head JSON to the mirror.
	Push(head json.RawMessage) error
	// Fetch downloads the latest tree head JSON from the mirror.
	Fetch() (json.RawMessage, error)
}

// Open parses rawURL and returns the appropriate backend.
// Returns an error if the scheme is unknown or the backend cannot be
// initialised (e.g. missing credentials).
func Open(rawURL string) (Mirror, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("mirror: parse url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "file":
		return newFileBackend(u.Path)
	case "http", "https":
		return newHTTPBackend(rawURL)
	case "s3":
		return newS3Backend(rawURL)
	default:
		return nil, fmt.Errorf("mirror: unsupported scheme %q (use file://, https://, or s3://)", u.Scheme)
	}
}
