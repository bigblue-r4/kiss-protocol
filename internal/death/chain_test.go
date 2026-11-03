package death

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func latest(t *testing.T, dir string) savedRecord {
	t.Helper()
	paths, err := recordNames(dir)
	if err != nil || len(paths) == 0 {
		t.Fatalf("record names: %v", err)
	}
	s, err := loadRecord(paths[len(paths)-1])
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func fireRecord(t *testing.T, dir string) savedRecord {
	t.Helper()
	if err := New(dir, "machine").Fire("test"); err != nil {
		t.Fatal(err)
	}
	return latest(t, dir)
}
func appendLog(t *testing.T, dir string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "witness.log"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
func rewriteRecord(t *testing.T, dir string, s savedRecord) {
	t.Helper()
	data, err := json.MarshalIndent(s.Record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, s.Name), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func verifyOK(t *testing.T, dir string, withLog bool) {
	t.Helper()
	var out bytes.Buffer
	log := ""
	if withLog {
		log = filepath.Join(dir, "witness.log")
	}
	if err := Verify(dir, log, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

func TestChainFourRecordsAndReadOnlyVerification(t *testing.T) {
	dir, log, _, _ := fixture(t)
	prev := fireRecord(t, dir)
	if prev.HashMode != "full" || prev.TailSHA256 != digest(log[len(log)-int(tailBytes):]) {
		t.Fatalf("anchor: %+v", prev)
	}
	for _, segment := range [][]byte{[]byte("append one"), []byte("append two"), nil} {
		appendLog(t, dir, segment)
		next := fireRecord(t, dir)
		if next.HashMode != "segment" || next.LogHash.Status != "complete" || next.LogHash.SHA256 != "" || next.SegmentSHA256 != digest(segment) || next.SegmentStart != prev.LogBytes {
			t.Fatalf("segment: %+v", next)
		}
		if next.PrevRecord == nil || *next.PrevRecord != prev.Reference || next.ChainSHA256 != chainDigest(prev.anchor(), digest(segment), next.LogBytes) {
			t.Fatalf("chain: %+v", next)
		}
		prev = next
	}
	// Pin directory contents and bytes before verifying to prove read-only behavior.
	paths, _ := filepath.Glob(filepath.Join(dir, "*"))
	before := map[string][]byte{}
	for _, path := range paths {
		before[path], _ = os.ReadFile(path)
	}
	verifyOK(t, dir, false)
	verifyOK(t, dir, true)
	after, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(paths) != len(after) {
		t.Fatal("checker created files")
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("checker changed %s: %v", path, err)
		}
	}
}

func TestTailChangeAndShrinkFallback(t *testing.T) {
	for _, shrink := range []bool{false, true} {
		t.Run(map[bool]string{true: "shrink", false: "tail mutation"}[shrink], func(t *testing.T) {
			dir, log, _, _ := fixture(t)
			prev := fireRecord(t, dir)
			if shrink {
				log = log[:len(log)/2]
			} else {
				log[len(log)-20] ^= 0xff
			}
			if err := os.WriteFile(filepath.Join(dir, "witness.log"), log, 0600); err != nil {
				t.Fatal(err)
			}
			next := fireRecord(t, dir)
			if next.HashMode != "full" || next.LogHash.SHA256 != digest(log) || next.LogShrank != shrink || next.PrefixChanged == shrink || next.PrevRecord.Name != prev.Name {
				t.Fatalf("fallback: %+v", next)
			}
			verifyOK(t, dir, false)
			var out bytes.Buffer
			if Verify(dir, filepath.Join(dir, "witness.log"), &out) == nil {
				t.Fatal("checker missed old evidence mismatch")
			}
		})
	}
}

func TestOutsideTailMutationIsNotClaimedDetected(t *testing.T) {
	dir, log, _, _ := fixture(t)
	fireRecord(t, dir)
	log[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, "witness.log"), log, 0600); err != nil {
		t.Fatal(err)
	}
	next := fireRecord(t, dir)
	if next.HashMode != "segment" || next.PrefixChanged {
		t.Fatal("tail check should not claim whole-prefix verification")
	}
	var out bytes.Buffer
	if Verify(dir, filepath.Join(dir, "witness.log"), &out) == nil {
		t.Fatal("offline full anchor verification missed old byte change")
	}
}

func TestMissingCorruptIncompletePreviousFallback(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "incomplete", "error", "corrupt newest with older valid", "missing ancestor", "corrupt ancestor"} {
		t.Run(kind, func(t *testing.T) {
			dir, _, _, _ := fixture(t)
			prev := fireRecord(t, dir)
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(dir, prev.Name)); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(dir, prev.Name), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "incomplete", "error":
				prev.LogHash = Hash{Status: kind}
				rewriteRecord(t, dir, prev)
			case "corrupt newest with older valid":
				next := fireRecord(t, dir)
				if err := os.WriteFile(filepath.Join(dir, next.Name), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing ancestor", "corrupt ancestor":
				fireRecord(t, dir)
				if kind == "missing ancestor" {
					if err := os.Remove(filepath.Join(dir, prev.Name)); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(filepath.Join(dir, prev.Name), []byte("broken"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			appendLog(t, dir, []byte("new"))
			next := fireRecord(t, dir)
			if next.HashMode != "full" || next.LogHash.Status != "complete" || next.FallbackReason == "" {
				t.Fatalf("expected fallback: %+v", next)
			}
			if strings.HasPrefix(kind, "corrupt") && !strings.Contains(kind, "ancestor") && len(next.SkippedRecords) == 0 {
				t.Fatal("corrupt record not disclosed")
			}
		})
	}
}

func TestV1HandoverAndSubsequentSegment(t *testing.T) {
	dir, _, _, _ := fixture(t)
	prev := fireRecord(t, dir)
	prev.Format = "witness-death/1"
	prev.HashMode = ""
	prev.TailSHA256 = ""
	prev.TailHash = Hash{}
	prev.FallbackReason = ""
	rewriteRecord(t, dir, prev)
	appendLog(t, dir, []byte("handover"))
	next := fireRecord(t, dir)
	if next.HashMode != "full" || next.FallbackReason != "previous_record_has_no_tail" || next.PrevRecord == nil {
		t.Fatalf("handover: %+v", next)
	}
	appendLog(t, dir, []byte("incremental"))
	next = fireRecord(t, dir)
	if next.HashMode != "segment" {
		t.Fatal("did not resume chaining")
	}
	verifyOK(t, dir, true)
}

func TestIncompleteAfterChainAndRecovery(t *testing.T) {
	dir, _, _, _ := fixture(t)
	fireRecord(t, dir)
	appendLog(t, dir, []byte("append"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(dir, "machine").fire(ctx, "deadline"); err != nil {
		t.Fatal(err)
	}
	last := latest(t, dir)
	if last.LogHash.Status != "incomplete" || last.LogHash.SHA256 != "" || last.SegmentSHA256 != "" || last.ChainSHA256 != "" {
		t.Fatalf("partial hash: %+v", last)
	}
	h := hashRange(ctx, filepath.Join(dir, "witness.log"), last.LogBytes-6, 6)
	if h.Status != "incomplete" || h.SHA256 != "" {
		t.Fatalf("segment deadline: %+v", h)
	}
	next := fireRecord(t, dir)
	if next.HashMode != "full" || next.FallbackReason != "previous_hash_incomplete" {
		t.Fatalf("recovery: %+v", next)
	}
}

func TestCheckerRejectsBrokenEvidence(t *testing.T) {
	for _, kind := range []string{"record bytes", "segment bytes", "chain", "missing link", "out of bounds", "path traversal", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			dir, _, _, _ := fixture(t)
			first := fireRecord(t, dir)
			appendLog(t, dir, []byte("append"))
			last := fireRecord(t, dir)
			log := ""
			switch kind {
			case "record bytes":
				data, _ := os.ReadFile(filepath.Join(dir, first.Name))
				if err := os.WriteFile(filepath.Join(dir, first.Name), append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "segment bytes":
				f, err := os.OpenFile(filepath.Join(dir, "witness.log"), os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte("X"), first.LogBytes)
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
				log = filepath.Join(dir, "witness.log")
			case "chain":
				last.ChainSHA256 = digest([]byte("wrong"))
				rewriteRecord(t, dir, last)
			case "missing link":
				if err := os.Remove(filepath.Join(dir, first.Name)); err != nil {
					t.Fatal(err)
				}
			case "out of bounds":
				last.SegmentStart = -1
				rewriteRecord(t, dir, last)
			case "path traversal":
				last.PrevRecord.Name = "../outside.json"
				rewriteRecord(t, dir, last)
			case "incomplete":
				last.LogHash = Hash{Status: "incomplete"}
				last.SegmentSHA256 = ""
				last.ChainSHA256 = ""
				rewriteRecord(t, dir, last)
			}
			var out bytes.Buffer
			if Verify(dir, log, &out) == nil {
				t.Fatalf("accepted %s\n%s", kind, out.String())
			}
		})
	}
}

// Run explicitly for the requested local timing; the normal suite stays small.
// Decimal GB/MB; the baseline is materialized, with warm cache after its full hash.
func BenchmarkDeathRecordIncremental(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "witness.log")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	block := bytes.Repeat([]byte("baseline"), 128*1024)
	for remaining := int64(1_400_000_000); remaining > 0; {
		n := int64(len(block))
		if remaining < n {
			n = remaining
		}
		written, err := f.Write(block[:n])
		if err != nil {
			b.Fatal(err)
		}
		remaining -= int64(written)
	}
	if err := f.Sync(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tree-head.json"), []byte(`{"size":1}`), 0600); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "genesis.enc"), bytes.Repeat([]byte("g"), 600_000), 0600); err != nil {
		b.Fatal(err)
	}
	writer := New(dir, "benchmark")
	fullStart := time.Now()
	if err := writer.Fire("baseline"); err != nil {
		b.Fatal(err)
	}
	b.Logf("materialized 1.4 GB full anchor: %s", time.Since(fullStart))
	paths, _ := recordNames(dir)
	anchor, err := loadRecord(paths[0])
	if err != nil || anchor.LogHash.Status != "complete" {
		b.Fatalf("baseline: %v %+v", err, anchor.LogHash)
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("s"), 10_000_000)); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(10_000_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writer.Fire("timing"); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		paths, _ := recordNames(dir)
		last, err := loadRecord(paths[len(paths)-1])
		if err != nil || last.HashMode != "segment" || last.LogHash.Status != "complete" || last.SegmentStart != 1_400_000_000 {
			b.Fatalf("incremental: %v %+v", err, last)
		}
		if err := os.Remove(filepath.Join(dir, last.Name)); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func TestChainDigestEncodingVector(t *testing.T) {
	// Independently computed SHA256(raw SHA256("abc") || raw SHA256("def") || uint64be(6)).
	const want = "ffd452fb5a83de065b65e1a02b839ddff73b538d4cfb3b84f6c88cc250b8ad47"
	if got := chainDigest(digest([]byte("abc")), digest([]byte("def")), 6); got != want {
		t.Fatalf("chain encoding: %s != %s", got, want)
	}
}
