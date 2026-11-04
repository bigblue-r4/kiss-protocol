package evidence

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// benchEntries returns n routine records. Logs are written with forge, not
// store.Append: Append recomputes the root over the whole log on every call,
// so building a large log through it is quadratic.
func benchEntries(n int) []store.Entry {
	es := make([]store.Entry, n)
	t0 := time.Now().UTC()
	for i := range es {
		es[i] = store.Entry{Seq: uint64(i + 1), Timestamp: t0.Add(time.Duration(i) * time.Millisecond),
			Level: "INFO", Event: "drift_clean", Source: "drift"}
	}
	return es
}

const benchSize = 50_000

// BenchmarkPollIncremental: verifying one new record on a 50,000-record log.
func BenchmarkPollIncremental(b *testing.B) {
	t := &testing.T{}
	wk := newSigner(5)
	dir := b.TempDir()
	es := benchEntries(benchSize + b.N)
	forge(t, dir, es[:benchSize], wk)
	v, _ := New(Config{Dir: dir, Key: logKey, Pins: []ed25519.PublicKey{wk.PublicKey()}, Now: time.Now})
	if err := v.Poll(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		forge(t, dir, es[:benchSize+i+1], wk)
		b.StartTimer()
		if err := v.Poll(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBootstrap: the first full verify of a 50,000-record log.
func BenchmarkBootstrap(b *testing.B) {
	t := &testing.T{}
	wk := newSigner(5)
	dir := b.TempDir()
	forge(t, dir, benchEntries(benchSize), wk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v, _ := New(Config{Dir: dir, Key: logKey, Pins: []ed25519.PublicKey{wk.PublicKey()}, Now: time.Now})
		if err := v.Poll(); err != nil {
			b.Fatal(err)
		}
	}
}
