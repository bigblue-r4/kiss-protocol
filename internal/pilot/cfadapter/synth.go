package cfadapter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// SynthOptions configure the synthetic ai_gateway_events generator.
type SynthOptions struct {
	URL       string // adapter endpoint
	Token     string
	Events    int
	BatchSize int
	Seed      uint64
	Interval  time.Duration // between batches
	// Fault injection for the completeness demonstration.
	RedeliverBatch int // re-send this batch number (1-based) once; 0 = never
	HTTP           *http.Client
}

// SynthRecord makes one synthetic record with only the field names
// documented for the ai_gateway_events dataset. Every value is invented and
// marked synthetic; no real gateway, model call or user is represented.
func SynthRecord(r *rand.Rand, t time.Time) map[string]any {
	models := []string{"synthetic/model-small", "synthetic/model-large", "synthetic/model-vision"}
	providers := []string{"synthetic-provider-a", "synthetic-provider-b"}
	endpoints := []string{"chat/completions", "embeddings", "images/generations"}
	status := 200
	switch x := r.IntN(100); {
	case x < 3:
		status = 429
	case x < 5:
		status = 500
	}
	m := models[r.IntN(len(models))]
	blob := make([]byte, 48)
	for i := range blob {
		blob[i] = byte(r.IntN(256))
	}
	return map[string]any{
		"Cached":            r.IntN(10) == 0,
		"Endpoint":          endpoints[r.IntN(len(endpoints))],
		"Gateway":           "synthetic-gateway",
		"Metadata":          map[string]any{"synthetic": true, "tenant": fmt.Sprintf("demo-%d", r.IntN(5))},
		"Metrics":           map[string]any{"cost": float64(r.IntN(5000)) / 1e6, "durationMs": 50 + r.IntN(3000)},
		"Model":             m,
		"Provider":          providers[r.IntN(len(providers))],
		"RateLimited":       status == 429,
		"RequestBody":       map[string]any{"type": "encrypted", "data": base64.StdEncoding.EncodeToString(blob)},
		"RequestedModel":    m,
		"ResponseBody":      map[string]any{"type": "encrypted", "data": base64.StdEncoding.EncodeToString(blob[:32])},
		"RoutingDecisionID": "",
		"RoutingReason":     "",
		"StatusCode":        status,
		"Timestamp":         t.UnixNano(),
		"UserAgent":         "synthetic-client/1.0",
	}
}

// Synth posts the destination-validation upload and then Events records in
// gzip-compressed NDJSON batches, the way a Logpush HTTP job delivers them.
func Synth(ctx context.Context, o SynthOptions, log io.Writer) error {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 500
	}
	r := rand.New(rand.NewPCG(o.Seed, o.Seed^0x9e3779b97f4a7c15))
	if err := post(ctx, o, []byte(`{"content":"tests"}`)); err != nil {
		return fmt.Errorf("validation upload: %w", err)
	}
	fmt.Fprintln(log, "sent destination validation upload")
	t := time.Now()
	for b, sent := 1, 0; sent < o.Events; b++ {
		var buf bytes.Buffer
		n := min(o.BatchSize, o.Events-sent)
		for i := 0; i < n; i++ {
			line, _ := json.Marshal(SynthRecord(r, t.Add(time.Duration(sent+i)*time.Millisecond)))
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if err := post(ctx, o, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b, err)
		}
		if b == o.RedeliverBatch {
			if err := post(ctx, o, buf.Bytes()); err != nil {
				return fmt.Errorf("batch %d redelivery: %w", b, err)
			}
			fmt.Fprintf(log, "batch %d delivered twice (fault injection)\n", b)
		}
		sent += n
		fmt.Fprintf(log, "batch %d: %d records (%d total)\n", b, n, sent)
		if o.Interval > 0 && sent < o.Events {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.Interval):
			}
		}
	}
	return nil
}

func post(ctx context.Context, o SynthOptions, ndjson []byte) error {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(ndjson)
	_ = zw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.URL, &z)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+o.Token)
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("adapter answered HTTP %d", resp.StatusCode)
	}
	return nil
}
