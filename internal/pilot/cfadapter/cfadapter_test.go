package cfadapter_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/cfadapter"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/evlog"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/testwitness"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/verify"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = io.WriteString(w, s)
	_ = w.Close()
	return b.Bytes()
}

func feedLines(t *testing.T, path string) []cfadapter.Entry {
	t.Helper()
	b, _ := os.ReadFile(path)
	var out []cfadapter.Entry
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		var e cfadapter.Entry
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestSinkRules(t *testing.T) {
	feed := filepath.Join(t.TempDir(), "feed.jsonl")
	h := &cfadapter.Handler{Feed: feed, Token: "s3cret", Dataset: "ai_gateway_events", MaxLine: 200}
	srv := httptest.NewServer(h)
	defer srv.Close()
	do := func(method, auth string, body []byte) int {
		req, _ := http.NewRequest(method, srv.URL+"/?dataset=ai_gateway_events", bytes.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("POST", "", gz(`{"a":1}`)); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c := do("POST", "Bearer wrong", gz(`{"a":1}`)); c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	if c := do("GET", "Bearer s3cret", nil); c != 405 {
		t.Fatalf("GET: %d", c)
	}
	if c := do("POST", "Bearer s3cret", []byte{0x1f, 0x8b, 0, 0}); c != 400 {
		t.Fatalf("bad gzip: %d", c)
	}
	if c := do("POST", "Bearer s3cret", gz(`{"content":"tests"}`)); c != 200 {
		t.Fatalf("validation upload: %d", c)
	}
	big := `{"x":"` + strings.Repeat("y", 300) + `"}`
	if c := do("POST", "Bearer s3cret", gz(`{"Model":"m","RequestBody":{"type":"encrypted","data":"QUJD"}}`+"\nnot json\n"+big+"\n")); c != 200 {
		t.Fatalf("batch: %d", c)
	}
	if c := do("POST", "Bearer s3cret", []byte(`{"plain":"uncompressed"}`)); c != 200 {
		t.Fatalf("uncompressed batch: %d", c)
	}
	es := feedLines(t, feed)
	if len(es) != 5 {
		t.Fatalf("want 5 feed lines, got %d", len(es))
	}
	if es[0].Control != "destination_validation" {
		t.Fatal("validation upload not recorded as control")
	}
	if strings.Contains(string(es[1].Fields), "QUJD") || !strings.Contains(string(es[1].Fields), "RequestBody_sha256") {
		t.Fatalf("RequestBody not replaced by its hash: %s", es[1].Fields)
	}
	if es[2].InvalidCause != "not a JSON object" || es[3].InvalidCause == "" || es[2].InvalidLine == "" {
		t.Fatal("invalid lines not marked")
	}
	if es[1].Batch != es[3].Batch || es[1].BatchCount != 3 || es[3].BatchIndex != 2 {
		t.Fatal("batch tagging wrong")
	}
	h2 := &cfadapter.Handler{Feed: feed}
	if c := httptestDo(h2); c != 401 {
		t.Fatalf("adapter without a token must refuse everything, got %d", c)
	}
}

func httptestDo(h http.Handler) int {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/", strings.NewReader(`{"a":1}`)))
	return rr.Code
}

// TestEndToEnd: synthetic Logpush uploads -> adapter -> evidence log ->
// witness -> standalone verifier. A batch delivered twice is reported.
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.jsonl")
	ad := httptest.NewServer(&cfadapter.Handler{Feed: feed, Token: "tok", Dataset: "ai_gateway_events"})
	defer ad.Close()
	err := cfadapter.Synth(context.Background(), cfadapter.SynthOptions{URL: ad.URL, Token: "tok", Events: 1234, BatchSize: 200, Seed: 7, RedeliverBatch: 3}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	skey, vkey, _ := note.GenerateKey(nil, "pilot.example/e2e")
	signer, _ := note.NewSigner(skey)
	w := testwitness.New("pilot.example/e2e-witness")
	w.AddLog("pilot.example/e2e", vkey)
	ws := httptest.NewServer(w)
	defer ws.Close()
	l, err := evlog.Open(evlog.Config{DataDir: filepath.Join(dir, "data"), PublicDir: filepath.Join(dir, "pub"), Signer: signer, VerifierKey: vkey,
		Witnesses: []evlog.Witness{{URL: ws.URL, Key: w.Key()}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Ingest(feed); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := verify.Run(context.Background(), verify.Options{Source: filepath.Join(dir, "pub"), LogKey: vkey, WitnessKeys: []checkpoint.CosignerKey{w.Key()}, Quorum: 1, MaxAge: time.Minute})
	if r.Overall != verify.Verified {
		t.Fatalf("%s: %s", r.Overall, r.Summary)
	}
	c := r.Completeness
	if c.Events != 1+1234+200 || c.BySource["cf-logpush"] != c.Events || c.Batches != 8 || len(c.DuplicateBatch) != 1 || len(c.IncompleteBatch) != 0 {
		t.Fatalf("completeness: %+v", c)
	}
	var html bytes.Buffer
	if err := r.WriteHTML(&html); err != nil || !strings.Contains(html.String(), "delivered again") {
		t.Fatalf("report does not show the redelivered batch: %v", err)
	}
}
