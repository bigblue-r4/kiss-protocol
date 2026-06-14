// Package mirror implements backends for publishing and fetching the Witness
// Merkle tree head to an operator-controlled external store.
//
// The mirror stores only the signed tree head JSON (< 1 KiB). It does not
// store the encrypted log. The tree head is self-authenticating: it carries
// an ed25519 signature and a BLAKE3-keyed MAC, so any holder of the operator
// public key can verify it independently of the daemon.
//
// Supported backends:
//
//	file:///path/to/dir          — local filesystem; atomic rename write
//	https://host/path            — HTTP(S) conditional PUT/GET; Bearer token
//	                               via WITNESS_MIRROR_TOKEN env var
//	s3://bucket/prefix           — S3-compatible object store; requires
//	                               -tags s3 and AWS_* env vars
//
// Atomicity guarantee: every backend uses write-then-atomic-rename (file) or
// an equivalent conditional PUT so that concurrent drift ticks cannot produce
// a partial or torn tree-head on the mirror side.
//
// Exit-code semantics for `witness audit`:
//
//	0  — local and mirror agree
//	1  — mirror disagrees (root mismatch at equal size, or mirror is ahead)
//	2  — mirror unreachable, misconfigured, or lag exceeds AuditMaxLag
//
// See docs/mirror-setup.md for configuration details.
package mirror

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// AuditStatus describes the outcome of comparing a local tree head against
// a mirror-fetched tree head.
type AuditStatus int

const (
	// AuditOK: mirror root and size match local — clean.
	AuditOK AuditStatus = iota
	// AuditTamper: mirror disagrees with local at the same tree size, or the
	// mirror claims more entries than the local log. Hard failure.
	AuditTamper
	// AuditBehind: mirror has fewer entries than local. This is expected under
	// S3/HTTP eventual consistency and is not a tamper signal on its own.
	// Treat as exit 2 (warn) unless lag exceeds the configured maximum.
	AuditBehind
	// AuditUnreachable: network or auth error prevented fetching the mirror.
	AuditUnreachable
)

// Mirror pushes and fetches the Merkle tree head as opaque JSON.
// Implementations must guarantee that Push is atomic: the remote object is
// either fully updated or unchanged. A successful Push must be immediately
// visible on a subsequent Fetch from the same backend instance (local reads).
// Remote replication lag (S3 eventual consistency) is handled by the audit
// layer, not here.
type Mirror interface {
	// Push atomically uploads the tree head JSON to the mirror.
	Push(head json.RawMessage) error
	// Fetch downloads the latest tree head JSON from the mirror.
	// Returns ErrMirrorUnreachable if the endpoint cannot be contacted.
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
