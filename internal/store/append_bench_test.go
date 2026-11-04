package store

import (
	"os"
	"testing"
)

// benchLog writes n records straight to a log (frames + head), skipping
// Append, which is what is being measured.
func benchLog(b *testing.B, n int) (string, *testDevSigner) {
	b.Helper()
	t := &testing.T{}
	s := newTestDevSigner(t)
	dir := b.TempDir()
	var buf []byte
	leaves := make([][32]byte, n)
	for i := 0; i < n; i++ {
		e := Entry{Seq: uint64(i + 1), Level: "INFO", Event: "drift_clean", Source: "drift"}
		buf = append(buf, frameFor(t, e)...)
		leaves[i] = leafHash(e)
	}
	if err := os.WriteFile(logPath(dir), buf, 0600); err != nil {
		b.Fatal(err)
	}
	if err := writeTreeHead(dir, testKey(), s, leaves); err != nil {
		b.Fatal(err)
	}
	return dir, s
}

// BenchmarkAppend100k: one Append on a log that already holds 100,000 records.
func BenchmarkAppend100k(b *testing.B) {
	dir, s := benchLog(b, 100_000)
	st, err := Open(dir, testKey(), s)
	if err != nil {
		b.Fatal(err)
	}
	defer st.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := st.Append("INFO", "drift_clean", "drift", nil); err != nil {
			b.Fatal(err)
		}
	}
}
