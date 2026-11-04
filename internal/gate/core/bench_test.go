package core

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// BenchmarkDecide measures steps 1–6 plus Release (no fsync, no signing),
// with 10k signals indexed and 1k known edges, every request admitted
// (20k x 1 unit stays under the test budgets). It reports p50/p99.
func BenchmarkDecide(b *testing.B) {
	h := newHarness(&testing.T{}, "")
	for i := 0; i < 10000; i++ {
		h.ev.add(evidence.KindFeed, h.clock().Add(-time.Duration(i)*time.Second), false, map[string]any{"n": i})
	}
	h.c.Sync()
	for i := 0; i < 1000; i++ {
		h.c.LearnEdges(fmt.Sprintf("origin_host:h%d->wallet-svc", i))
	}
	reqs := make([]proto.ActionRequest, b.N)
	for i := range reqs {
		reqs[i] = h.req("hot", func(r *proto.ActionRequest) { r.Amount, r.Principal = "1", fmt.Sprintf("p%d", i%50) })
	}
	lat := make([]time.Duration, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t := time.Now()
		d := h.c.Decide(reqs[i], nil)
		if d.Res == nil {
			b.Fatalf("request %d not admitted: %v %s", i, d.Reasons, d.Detail)
		}
		h.c.Release(d.Res, true)
		lat[i] = time.Since(t)
	}
	b.StopTimer()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	b.ReportMetric(float64(lat[len(lat)/2].Microseconds()), "p50-µs")
	b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds()), "p99-µs")
}
