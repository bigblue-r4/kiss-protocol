package checkpoint_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// TestInteropOmniwitness runs our tlog-witness client against an unmodified
// transparency-dev/witness omniwitness binary. It runs only when
// HL_OMNIWITNESS and HL_GENERATE_KEYS name the two binaries, e.g.
//
//	go install github.com/transparency-dev/witness/cmd/omniwitness@<pinned>
//	go install github.com/transparency-dev/witness/cmd/generate_keys@<pinned>
func TestInteropOmniwitness(t *testing.T) {
	bin, gen := os.Getenv("HL_OMNIWITNESS"), os.Getenv("HL_GENERATE_KEYS")
	if bin == "" || gen == "" {
		t.Skip("HL_OMNIWITNESS / HL_GENERATE_KEYS not set")
	}
	dir := t.TempDir()
	out, err := exec.Command(gen, "--origin=pilot.example/interop-witness", "--print").Output()
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Split(strings.TrimSpace(string(out)), "\n")
	if err := os.WriteFile(filepath.Join(dir, "w.sec"), []byte(keys[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	wkey, err := checkpoint.ParseCosignerKey(keys[1])
	if err != nil {
		t.Fatal(err)
	}
	signer, vkey := logKey(t, "pilot.example/interop-log")
	yaml := fmt.Sprintf("Logs:\n  - Origin: pilot.example/interop-log\n    PublicKey: %s\n    URL: http://unused.invalid/\n", vkey)
	if err := os.WriteFile(filepath.Join(dir, "logs.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	cmd := exec.Command(bin, "--listen="+addr, "--metrics_listen=", "--db_file="+filepath.Join(dir, "w.db"),
		"--private_key_path="+filepath.Join(dir, "w.sec"), "--additional_logs="+filepath.Join(dir, "logs.yaml"), "--logtostderr")
	logf, _ := os.Create(filepath.Join(dir, "omniwitness.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "omniwitness.log"))
			t.Logf("omniwitness log:\n%s", b)
		}
	}()
	url := "http://" + addr
	for i := 0; ; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		if i > 100 {
			t.Fatal("omniwitness did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	ctx := context.Background()
	hc := &http.Client{Timeout: 5 * time.Second}
	all := leaves(70)
	submit := func(old uint64, n int, l []tlog.Hash) ([]byte, []checkpoint.SigLine, error) {
		c := checkpoint.Checkpoint{Origin: "pilot.example/interop-log", Size: uint64(n), Root: tlog.Root(l[:n])}
		raw, err := checkpoint.SignLog(c, signer)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := tlog.ProveConsistency(l[:n], old)
		lines, err := checkpoint.AddCheckpoint(ctx, hc, url, old, p, raw)
		return raw, lines, err
	}
	check := func(raw []byte, lines []checkpoint.SigLine) {
		t.Helper()
		for _, l := range lines {
			raw = append(raw, l.String()...)
		}
		s, err := checkpoint.Open(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := s.Cosignatures([]checkpoint.CosignerKey{wkey})
		if !r[0].Valid {
			t.Fatalf("omniwitness cosignature does not verify: %+v", r[0])
		}
		if d := time.Since(time.Unix(int64(r[0].Timestamp), 0)); d < -time.Minute || d > time.Minute {
			t.Fatalf("cosignature timestamp off by %v", d)
		}
	}
	old := uint64(0)
	for _, n := range []int{1, 2, 3, 7, 8, 9, 33, 64, 70} {
		raw, lines, err := submit(old, n, all)
		if err != nil {
			t.Fatalf("%d->%d: %v", old, n, err)
		}
		check(raw, lines)
		old = uint64(n)
	}
	// Stale old size: 409 carrying the witness's size.
	var ce *checkpoint.ConflictError
	if _, _, err := submit(33, 70, all); !errors.As(err, &ce) || ce.Size != 70 {
		t.Fatalf("want conflict at 70, got %v", err)
	}
	// Rewritten history, re-signed with the real log key: refused.
	more := append(append([]tlog.Hash(nil), all...), leaves(80)[70:]...)
	forked := append([]tlog.Hash(nil), more...)
	forked[3] = tlog.HashLeaf([]byte("rewritten"))
	var we *checkpoint.WitnessError
	if _, _, err := submit(70, 80, forked); !errors.As(err, &we) || we.Status != http.StatusUnprocessableEntity {
		t.Fatalf("rewrite: want 422, got %v", err)
	}
	// Signed by a key the witness does not trust: refused.
	other, _ := logKey(t, "pilot.example/interop-log")
	c := checkpoint.Checkpoint{Origin: "pilot.example/interop-log", Size: 80, Root: tlog.Root(more)}
	raw, _ := checkpoint.SignLog(c, other)
	p, _ := tlog.ProveConsistency(more, 70)
	if _, err := checkpoint.AddCheckpoint(ctx, hc, url, 70, p, raw); !errors.As(err, &we) || we.Status != http.StatusForbidden {
		t.Fatalf("untrusted key: want 403, got %v", err)
	}
	// The honest extension still works afterwards.
	raw, lines, err := submit(70, 80, more)
	if err != nil {
		t.Fatal(err)
	}
	check(raw, lines)
}
