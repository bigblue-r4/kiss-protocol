package evlog

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor/rekortest"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

func TestAnchoring(t *testing.T) {
	srv := rekortest.New()
	ts := httptest.NewServer(srv)
	defer ts.Close()
	priv, _, _ := rekor.GenerateKey()
	key, _ := rekor.ParsePrivateKey(priv)
	now := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	cfg := testCfg(t, t.TempDir())
	cfg.Now = func() time.Time { return now }
	cfg.Anchor = &AnchorConfig{URL: ts.URL, Key: key, Interval: time.Hour}
	ctx := context.Background()

	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	round := func(wantSize uint64, wantSkip bool, wantErr bool) {
		t.Helper()
		if _, err := l.Checkpoint(ctx); err != nil {
			t.Fatal(err)
		}
		a := l.LastAnchor()
		if a == nil || a.Size != wantSize || (a.Skipped != "") != wantSkip || (a.Error != "") != wantErr {
			t.Fatalf("anchor status %+v, want size %d skip %v err %v", a, wantSize, wantSkip, wantErr)
		}
	}
	round(0, true, false) // empty log: nothing to anchor
	_ = l.Append(json.RawMessage(`{"n":1}`), json.RawMessage(`{"n":2}`))
	round(2, false, false) // first anchor
	round(2, true, false)  // same size
	_ = l.Append(json.RawMessage(`{"n":3}`))
	round(2, true, false) // within the interval
	now = now.Add(time.Hour)
	srv.Down = true
	round(2, false, true) // Rekor down: reported, checkpoint still published
	if _, err := os.Stat(filepath.Join(cfg.PublicDir, "checkpoints", "3")); err != nil {
		t.Fatal("checkpoint not published while Rekor was down")
	}
	srv.Down = false
	l.Close()

	// The anchor state survives a restart.
	if l, err = Open(cfg); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	round(3, false, false)
	if srv.Uploads != 2 {
		t.Fatalf("%d uploads, want 2", srv.Uploads)
	}

	// The published anchor verifies against the records.
	b, err := os.ReadFile(filepath.Join(cfg.PublicDir, "anchor.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a rekor.Anchor
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	c := checkpoint.Checkpoint{Origin: cfg.Signer.Name(), Size: 3, Root: tlog.Root(l.leaves)}
	if _, err := rekor.VerifyAnchor(a, rekor.Digest(c.Text()), srv.Public(), &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.PublicDir, "anchors", "2.json")); err != nil {
		t.Fatal("earlier anchor not kept")
	}
}
