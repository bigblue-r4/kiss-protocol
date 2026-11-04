package sim

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// BenchmarkDecide measures the entire HTTP-over-unix /v1/decide round trip,
// including feed fsync, signatures and (when enabled) the real bridge's EOF
// polling and the daemon's default one-second evidence polling. Setup and
// teardown are excluded. Use -benchtime=20x or larger for useful percentiles.
func BenchmarkDecide(b *testing.B) {
	for _, commit := range []bool{false, true} {
		name := "without_commit_wait"
		if commit {
			name = "with_commit_wait"
		}
		b.Run(name, func(b *testing.B) {
			e := running(b, commit, func(p string) string {
				p = strings.ReplaceAll(p, `max_value = "100"`, `max_value = "1000000000000"`)
				return strings.ReplaceAll(p, `max_value = "1000"`, `max_value = "1000000000000"`)
			})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); e.Gate.Run(ctx) }()
			defer func() { cancel(); <-done }()
			samples := make([]time.Duration, 0, b.N)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r := e.Request("hot", "1")
				start := time.Now()
				d := e.Decide(r)
				samples = append(samples, time.Since(start))
				allowed(b, d)
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			if len(samples) > 0 { // nearest-rank percentiles, including network and fsync
				rank := func(p int) time.Duration { return samples[(p*len(samples)+99)/100-1] }
				b.ReportMetric(float64(rank(50).Nanoseconds())/1e6, "p50-ms")
				b.ReportMetric(float64(rank(99).Nanoseconds())/1e6, "p99-ms")
			}
		})
	}
}
