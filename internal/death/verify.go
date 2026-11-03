package death

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
)

// Verify walks death records in filename order using only read-only file APIs.
// With logPath it verifies captured ranges against that retained encrypted log.
// It does not verify Merkle signatures or authenticate the local record collection.
func Verify(dir, logPath string, out io.Writer) error {
	paths, err := recordNames(dir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no death records found in %s", dir)
	}
	issues := 0
	var previous *savedRecord
	for _, path := range paths {
		name := filepath.Base(path)
		fail := func(format string, args ...any) {
			issues++
			fmt.Fprintf(out, "FAIL %s: %s\n", name, fmt.Sprintf(format, args...))
		}
		before := issues
		s, err := loadRecord(path)
		if err != nil {
			fail("unreadable record: %v", err)
			continue
		}
		r := s.Record
		if r.Format == "witness-death/2" {
			if r.PrevRecord != nil {
				if err := checkLink(dir, name, r.PrevRecord); err != nil {
					fail("%v", err)
				}
				if previous == nil || r.PrevRecord.Name != previous.Name {
					fail("link does not name newest preceding parseable record")
				}
			} else if previous != nil {
				fail("missing prev_record link")
			}
			if r.HashMode == "segment" {
				if previous == nil || r.PrevRecord == nil {
					fail("segment has no previous record")
				} else {
					if r.SegmentStart != previous.LogBytes || r.LogBytes < r.SegmentStart {
						fail("invalid segment bounds")
					}
					if previous.LogHash.Status != "complete" || previous.Format != "witness-death/2" || !validDigest(previous.TailSHA256) {
						fail("segment extends an ineligible previous record")
					}
					if previous.MachineID != r.MachineID {
						fail("segment changes machine ID")
					}
					if r.LogHash.Status == "complete" && chainDigest(previous.anchor(), r.SegmentSHA256, r.LogBytes) != r.ChainSHA256 {
						fail("chain SHA-256 mismatch")
					}
				}
			}
			if r.PrefixChanged || r.LogShrank {
				fmt.Fprintf(out, "WARN %s: prefix_changed=%t log_shrank=%t (chain reset)\n", name, r.PrefixChanged, r.LogShrank)
			}
			for _, skipped := range r.SkippedRecords {
				fmt.Fprintf(out, "WARN %s: skipped %s: %s\n", name, skipped.Name, skipped.Error)
			}
			if !validDigest(r.TailSHA256) {
				fail("tail hash unavailable (%s)", r.TailHash.Status)
			}
		}
		if r.LogHash.Status != "complete" {
			fail("log hash %s; cannot verify captured range", r.LogHash.Status)
		}
		if logPath != "" && r.LogBytes >= 0 {
			ctx := context.Background()
			start := int64(0)
			want := r.LogHash.SHA256
			if r.HashMode == "segment" {
				start = r.SegmentStart
				want = r.SegmentSHA256
			}
			if start < 0 || start > r.LogBytes {
				fail("invalid log range")
			} else if r.LogHash.Status == "complete" {
				h := hashRange(ctx, logPath, start, r.LogBytes-start)
				if h.Status != "complete" || h.SHA256 != want {
					fail("log range [%d,%d) SHA-256 mismatch or read failure: %s", start, r.LogBytes, h.Error)
				}
			}
			if r.Format == "witness-death/2" && validDigest(r.TailSHA256) {
				start := tailStart(r.LogBytes)
				h := hashRange(ctx, logPath, start, r.LogBytes-start)
				if h.Status != "complete" || h.SHA256 != r.TailSHA256 {
					fail("tail SHA-256 mismatch or read failure: %s", h.Error)
				}
			}
		}
		if issues == before {
			fmt.Fprintf(out, "OK %s (%s, %s)\n", name, r.Format, r.LogHash.Status)
		}
		copy := s
		previous = &copy
	}
	if issues > 0 {
		return fmt.Errorf("death verification failed: %d issue(s)", issues)
	}
	if logPath == "" {
		fmt.Fprintln(out, "Record links and chain arithmetic checked; log bytes and Merkle signatures NOT verified.")
	}
	return nil
}
