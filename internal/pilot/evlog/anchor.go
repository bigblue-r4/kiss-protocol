package evlog

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
)

// AnchorConfig turns on Rekor anchoring. Off unless set: an anchor is a
// permanent public record (the log's origin, a tree size and root, and the
// anchoring public key), so pointing this at a public Rekor is a decision
// for the operator, not a default.
type AnchorConfig struct {
	URL      string            // Rekor base URL
	Key      *ecdsa.PrivateKey // ECDSA P-256; a key used for nothing else
	Interval time.Duration     // at most one anchor per interval (0: every new size)
}

// AnchorStatus is the outcome of the anchoring step of a checkpoint round.
type AnchorStatus struct {
	OK      bool   `json:"ok"`
	Size    uint64 `json:"anchored_size"` // latest size anchored, this round or earlier
	At      string `json:"at"`
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
}

type anchorState struct {
	Size uint64    `json:"size"`
	At   time.Time `json:"at"`
}

func (l *Log) loadAnchorState() error {
	if l.cfg.Anchor == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(l.cfg.PublicDir, "anchors"), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(l.cfg.DataDir, "anchor-state.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &l.anchor); err != nil {
		return fmt.Errorf("evlog: anchor-state.json: %w", err)
	}
	return nil
}

// anchorRound submits checkpoint c to Rekor if it is new and the interval has
// passed. A failure is reported, never fatal: anchoring adds evidence, and
// its absence is something the verifier discloses.
func (l *Log) anchorRound(ctx context.Context, c checkpoint.Checkpoint) *AnchorStatus {
	st := l.anchorStep(ctx, c)
	l.lastAnchor = st
	return st
}

// LastAnchor is the anchoring outcome of the latest checkpoint round (nil if
// anchoring is off).
func (l *Log) LastAnchor() *AnchorStatus { return l.lastAnchor }

func (l *Log) anchorStep(ctx context.Context, c checkpoint.Checkpoint) *AnchorStatus {
	a := l.cfg.Anchor
	if a == nil {
		return nil
	}
	now := l.cfg.Now()
	st := &AnchorStatus{Size: l.anchor.Size, At: now.UTC().Format(time.RFC3339)}
	switch {
	case c.Size == 0:
		st.Skipped = "empty log"
	case c.Size == l.anchor.Size:
		st.Skipped = "this size is already anchored"
	case !l.anchor.At.IsZero() && now.Sub(l.anchor.At) < a.Interval:
		st.Skipped = "next anchor due after " + l.anchor.At.Add(a.Interval).UTC().Format(time.RFC3339)
	}
	if st.Skipped != "" {
		st.OK = true
		return st
	}
	uuid, raw, err := rekor.Upload(ctx, l.cfg.HTTP, a.URL, rekor.Digest(c.Text()), a.Key)
	if err == nil {
		var b []byte
		b, err = json.MarshalIndent(rekor.Anchor{Format: rekor.AnchorFormat, Size: c.Size, Rekor: a.URL, UUID: uuid, Entry: raw}, "", "  ")
		if err == nil {
			err = writeAtomic(filepath.Join(l.cfg.PublicDir, "anchors", strconv.FormatUint(c.Size, 10)+".json"), b)
		}
		if err == nil {
			err = writeAtomic(filepath.Join(l.cfg.PublicDir, "anchor.json"), b)
		}
	}
	if err == nil {
		l.anchor = anchorState{Size: c.Size, At: now}
		var b []byte
		b, err = json.Marshal(l.anchor)
		if err == nil {
			err = writeAtomic(filepath.Join(l.cfg.DataDir, "anchor-state.json"), b)
		}
	}
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.OK, st.Size = true, c.Size
	return st
}

// anchorPublicKeyPEM returns the anchoring public key, for the descriptor.
func anchorPublicKeyPEM(k *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
