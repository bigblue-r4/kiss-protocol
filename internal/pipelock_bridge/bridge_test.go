package pipelock_bridge

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// testKey is the fixed all-zero store key used across the bridge tests, so a
// store opened by openTestStore can be reopened with store.ReadAll.
func testKey() []byte { return make([]byte, 32) }

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir, testKey(), nil)
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

// TestClassifyReceiptEnvelope covers the real Pipelock v3 flight_recorder
// envelope from the issue #10 live test: event_kind must win over the generic
// top-level type (so read/write isn't lost), lifecycle receipts label off
// session_control.kind, legacy rows fall back to action_type, and a blocking
// verdict elevates an INFO row to WARN.
func TestClassifyReceiptEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		evt       pipelock.AuditEvent
		wantLevel string
		wantEvent string
	}{
		{
			name: "action receipt keeps event_kind not type",
			evt: pipelock.AuditEvent{
				"type": "action_receipt", "event_kind": "write", "level": "info",
			},
			wantLevel: "INFO", wantEvent: "pipelock_receipt:write",
		},
		{
			name: "lifecycle heartbeat via session_control.kind",
			evt: pipelock.AuditEvent{
				"type": "action_receipt", "event_kind": "session_control", "level": "info",
				"detail": map[string]interface{}{
					"action_record": map[string]interface{}{
						"session_control": map[string]interface{}{"kind": "heartbeat"},
					},
				},
			},
			wantLevel: "INFO", wantEvent: "pipelock_receipt:heartbeat",
		},
		{
			name: "legacy row falls back to action_type",
			evt: pipelock.AuditEvent{
				"level": "info",
				"detail": map[string]interface{}{
					"action_record": map[string]interface{}{"action_type": "http_request"},
				},
			},
			wantLevel: "INFO", wantEvent: "pipelock_receipt:http_request",
		},
		{
			name: "blocking verdict elevates INFO to WARN",
			evt: pipelock.AuditEvent{
				"type": "action_receipt", "event_kind": "write", "level": "info",
				"detail": map[string]interface{}{
					"action_record": map[string]interface{}{"verdict": "block"},
				},
			},
			wantLevel: "WARN", wantEvent: "pipelock_receipt:write",
		},
		{
			// Live v3.1.0 v2 evidence_receipt: proxy_decision row carries the
			// verdict under detail.payload.verdict (not action_record).
			name: "v2 evidence_receipt proxy_decision verdict elevates via payload",
			evt: pipelock.AuditEvent{
				"type": "evidence_receipt", "event_kind": "proxy_decision",
				"record_type": "evidence_receipt_v2", "level": "info",
				"detail": map[string]interface{}{
					"payload": map[string]interface{}{
						"verdict": "denied", "action_type": "http_request", "target": "example.com",
					},
				},
			},
			wantLevel: "WARN", wantEvent: "pipelock_receipt:proxy_decision",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			level, event := classifyReceipt(tc.evt)
			if level != tc.wantLevel || event != tc.wantEvent {
				t.Errorf("got (%s, %s), want (%s, %s)", level, event, tc.wantLevel, tc.wantEvent)
			}
		})
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
