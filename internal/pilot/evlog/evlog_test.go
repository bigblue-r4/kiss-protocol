package evlog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func testCfg(t *testing.T, dir string) Config {
	t.Helper()
	skey, vkey, err := note.GenerateKey(nil, "pilot.example/unit")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.NewSigner(skey)
	return Config{DataDir: filepath.Join(dir, "data"), PublicDir: filepath.Join(dir, "pub"), Signer: s, VerifierKey: vkey, MaxRecord: 100}
}

func appendFeed(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func records(t *testing.T, cfg Config) []string {
	b, _ := os.ReadFile(filepath.Join(cfg.PublicDir, "records.jsonl"))
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestIngestResumesWithoutDuplicatesOrLoss(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(t, dir)
	feed := filepath.Join(dir, "feed")
	l, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendFeed(t, feed, "{\"n\":1}\n{\"n\":2}\n{\"n\":3")
	if n, _ := l.Ingest(feed); n != 2 {
		t.Fatalf("ingested %d, want 2 (the partial third line waits)", n)
	}
	if _, err := l.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	appendFeed(t, feed, "}\n{\"n\":4}\n")
	l, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := l.Ingest(feed); n != 2 {
		t.Fatalf("after restart ingested %d, want 2", n)
	}
	if n, _ := l.Ingest(feed); n != 0 {
		t.Fatalf("re-ingest gave %d new records", n)
	}
	rs := records(t, cfg)
	if len(rs) != 4 || !strings.Contains(rs[2], `"n":3`) || !strings.Contains(rs[3], `"n":4`) {
		t.Fatalf("records: %q", rs)
	}
	// Garbage, oversize and a shrunken feed.
	appendFeed(t, feed, "nope\n{\"big\":\""+strings.Repeat("x", 200)+"\"}\n\n")
	if n, _ := l.Ingest(feed); n != 2 {
		t.Fatalf("garbage: %d records, want 2 rejected", n)
	}
	if err := os.WriteFile(feed, []byte("{\"n\":5}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, _ := l.Ingest(feed); n != 2 {
		t.Fatalf("shrunken feed: %d records, want feed_reset + 1", n)
	}
	rs = records(t, cfg)
	for i, want := range []string{`"rejected":"not a JSON object"`, `"rejected":"line longer than 100 bytes"`, `"kind":"feed_reset"`, `"n":5`} {
		if !strings.Contains(rs[4+i], want) {
			t.Fatalf("record %d = %s, want %s", 4+i, rs[4+i], want)
		}
	}
	if strings.Contains(rs[5], "xxxx") {
		t.Fatal("a rejected line's content was stored")
	}
	l.Close()
}

func TestRefusesAlteredOrLostEvidence(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(t, dir)
	l, _ := Open(cfg)
	_ = l.Append([]byte(`{"a":1}`), []byte(`{"a":2}`))
	if _, err := l.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	p := filepath.Join(cfg.PublicDir, "records.jsonl")
	orig, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(orig, []byte(`"a":2`), []byte(`"a":3`), 1), 0o644)
	if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("altered record: %v", err)
	}
	_ = os.WriteFile(p, orig[:bytes.IndexByte(orig, '\n')+1], 0o644)
	if _, err := Open(cfg); err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("lost record: %v", err)
	}
	// A checkpoint signed by another key is refused too.
	_ = os.WriteFile(p, orig, 0o644)
	other := testCfg(t, dir)
	if _, err := Open(other); err == nil {
		t.Fatal("opened with a different log key")
	}
}
