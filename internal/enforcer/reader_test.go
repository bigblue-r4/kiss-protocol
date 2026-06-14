package enforcer

import (
	"context"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

func makeTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := encrypt.DeriveKey("test-machine-id")
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	return key
}

func TestTailReaderDeliversNewEntries(t *testing.T) {
	dir := t.TempDir()
	key := makeTestKey(t)

	s, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Append("INFO", "test_event", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Append("INFO", "test_event_2", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = s.Close()

	events := make(chan Event, 16)
	r := NewTailReader(dir, key, 50*time.Millisecond, events)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go r.Run(ctx)

	got := make([]Event, 0, 2)
	deadline := time.After(1 * time.Second)
collect:
	for {
		select {
		case e := <-events:
			got = append(got, e)
			if len(got) == 2 {
				break collect
			}
		case <-deadline:
			t.Fatalf("timed out waiting for events; got %d", len(got))
		}
	}
	cancel()
	r.Wait()

	if got[0].Event != "test_event" {
		t.Errorf("first event: got %q want %q", got[0].Event, "test_event")
	}
	if got[1].Event != "test_event_2" {
		t.Errorf("second event: got %q want %q", got[1].Event, "test_event_2")
	}
	if got[0].LeafIndex != 0 {
		t.Errorf("first leaf index: got %d want 0", got[0].LeafIndex)
	}
	if got[1].LeafIndex != 1 {
		t.Errorf("second leaf index: got %d want 1", got[1].LeafIndex)
	}
	// Leaf hashes must be non-zero.
	var zero [32]byte
	if got[0].LeafHash == zero {
		t.Error("first leaf hash is zero")
	}
}

func TestTailReaderDeliverOnlyNewEntries(t *testing.T) {
	dir := t.TempDir()
	key := makeTestKey(t)

	s, err := store.Open(dir, key, nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Append("INFO", "existing", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}

	events := make(chan Event, 16)
	r := NewTailReader(dir, key, 50*time.Millisecond, events)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go r.Run(ctx)

	// Drain the initial event.
	select {
	case <-events:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for initial event")
	}

	// Now append a new entry while the reader is running.
	if err := s.Append("INFO", "new_entry", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = s.Close()

	select {
	case e := <-events:
		if e.Event != "new_entry" {
			t.Errorf("expected new_entry, got %q", e.Event)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for new entry")
	}

	cancel()
	r.Wait()
}

func TestTailReaderEmptyDir(t *testing.T) {
	dir := t.TempDir()
	key := makeTestKey(t)
	events := make(chan Event, 8)
	r := NewTailReader(dir, key, 50*time.Millisecond, events)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go r.Run(ctx)
	r.Wait()

	if len(events) != 0 {
		t.Errorf("expected no events from empty dir, got %d", len(events))
	}
}
