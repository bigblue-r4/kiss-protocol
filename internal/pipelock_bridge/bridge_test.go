package pipelock_bridge

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	s, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBridgeStartFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := &pipelock.Config{
		ConfigFile: filepath.Join(dir, "pipelock.yaml"),
		AuditLog:   filepath.Join(dir, "pipelock-audit.log"),
		ProxyPort:  18889,
		BinPath:    "/nonexistent/pipelock-binary",
	}
	b := New(cfg, openTestStore(t))
	if err := b.Start(); err == nil {
		t.Error("expected error starting bridge with nonexistent binary")
		b.Stop()
	}
	if b.Enabled() {
		t.Error("bridge should not be enabled after start failure")
	}
	// Stop on a disabled bridge must be a no-op (not panic or hang).
	b.Stop()
}

func TestBridgeForwardEvents(t *testing.T) {
	s := openTestStore(t)
	dir := t.TempDir()
	cfg := pipelock.DefaultConfig(dir)
	b := New(cfg, s)

	// Start just the forwarding goroutine without the subprocess.
	b.enabled = true
	go b.forward()

	// Inject audit events directly through the internal channel.
	b.events <- pipelock.AuditEvent{"event": "connect", "level": "info"}
	b.events <- pipelock.AuditEvent{"event": "dlp_match", "level": "warn"}

	// Give forward() time to process then stop it.
	time.Sleep(50 * time.Millisecond)
	close(b.stopForward)
	<-b.done

	head := s.Head()
	if head.Size < 2 {
		t.Errorf("expected at least 2 leaves in store, got %d", head.Size)
	}
}

func TestBridgeForwardReceipts(t *testing.T) {
	s := openTestStore(t)
	dir := t.TempDir()
	cfg := pipelock.DefaultConfig(dir)
	b := New(cfg, s)

	// Start just the forwarding goroutine without the subprocess.
	b.enabled = true
	go b.forward()

	// Inject flight_recorder receipts directly through the evidence channel.
	b.evEvents <- pipelock.AuditEvent{"type": "action_receipt", "decision": "allow", "level": "info"}
	b.evEvents <- pipelock.AuditEvent{"type": "action_receipt", "decision": "block", "level": "warn"}

	time.Sleep(50 * time.Millisecond)
	close(b.stopForward)
	<-b.done

	if head := s.Head(); head.Size < 2 {
		t.Errorf("expected at least 2 receipt leaves in store, got %d", head.Size)
	}
}

func TestClassifyReceipt(t *testing.T) {
	level, event := classifyReceipt(pipelock.AuditEvent{"type": "action_receipt", "level": "warn"})
	if level != "WARN" || event != "pipelock_receipt:action_receipt" {
		t.Errorf("got (%s, %s), want (WARN, pipelock_receipt:action_receipt)", level, event)
	}
	// No recognizable label field falls back to the generic event name.
	_, event = classifyReceipt(pipelock.AuditEvent{"seq": 1})
	if event != "pipelock_receipt" {
		t.Errorf("got %s, want pipelock_receipt", event)
	}
}

func TestBridgeLevelNormalization(t *testing.T) {
	s := openTestStore(t)
	dir := t.TempDir()
	cfg := pipelock.DefaultConfig(dir)
	b := New(cfg, s)

	b.enabled = true
	go b.forward()

	// DEBUG and TRACE should be normalized to INFO without panicking.
	b.events <- pipelock.AuditEvent{"event": "trace_event", "level": "debug"}
	b.events <- pipelock.AuditEvent{"event": "trace_event2", "level": "trace"}

	time.Sleep(50 * time.Millisecond)
	close(b.stopForward)
	<-b.done

	head := s.Head()
	if head.Size < 2 {
		t.Errorf("expected at least 2 leaves, got %d", head.Size)
	}
}
