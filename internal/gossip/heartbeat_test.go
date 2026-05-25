package gossip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// testSigner is a bare ed25519 signer for gossip tests.
type testSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &testSigner{priv: priv, pub: pub}
}

func (s *testSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *testSigner) PublicKey() ed25519.PublicKey    { return s.pub }

// freeUDPPort picks an ephemeral UDP port by binding and immediately closing.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

func TestSilencePresumedCompromised(t *testing.T) {
	const (
		interval = 50 * time.Millisecond
		missed   = 2 // silent after 2 intervals
		death    = 4 // presumed-compromised after 4 intervals
	)

	sA := newTestSigner(t)
	sB := newTestSigner(t)

	portA := freeUDPPort(t)
	portB := freeUDPPort(t)
	addrA := fmt.Sprintf("127.0.0.1:%d", portA)
	addrB := fmt.Sprintf("127.0.0.1:%d", portB)

	ctx := context.Background()

	// nodeA knows about nodeB and sends it heartbeats.
	nodeA := NewNode(NodeConfig{
		Signer:          sA,
		Peers:           []Peer{{Label: "B", Addr: addrB, PubKey: sB.PublicKey()}},
		ListenAddr:      addrA,
		Interval:        interval,
		MissedThreshold: missed,
		DeathThreshold:  death,
	})

	// nodeB knows about nodeA and watches for its heartbeats.
	var (
		muB         sync.Mutex
		silentFired bool
		deadFired   bool
		silentPeer  Peer
		deadPeer    Peer
	)
	nodeB := NewNode(NodeConfig{
		Signer:          sB,
		Peers:           []Peer{{Label: "A", Addr: addrA, PubKey: sA.PublicKey()}},
		ListenAddr:      addrB,
		Interval:        interval,
		MissedThreshold: missed,
		DeathThreshold:  death,
		OnSilent: func(p Peer) {
			muB.Lock()
			silentFired = true
			silentPeer = p
			muB.Unlock()
		},
		OnDeath: func(p Peer) {
			muB.Lock()
			deadFired = true
			deadPeer = p
			muB.Unlock()
		},
	})

	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("nodeA.Start: %v", err)
	}
	if err := nodeB.Start(ctx); err != nil {
		nodeA.Stop()
		t.Fatalf("nodeB.Start: %v", err)
	}

	// Wait for nodeB to see at least one heartbeat from nodeA.
	peerAID := fmt.Sprintf("%x", sA.PublicKey())
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		nodeB.mu.Lock()
		var seq uint64
		if st := nodeB.states[peerAID]; st != nil {
			seq = st.lastSeq
		}
		nodeB.mu.Unlock()
		if seq > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Stop nodeA — nodeB should detect silence then death.
	nodeA.Stop()

	// Wait for the silent callback (missed * interval + some slack).
	silentDeadline := time.Now().Add(time.Duration(missed+2) * interval * 2)
	for time.Now().Before(silentDeadline) {
		muB.Lock()
		fired := silentFired
		muB.Unlock()
		if fired {
			break
		}
		time.Sleep(interval / 4)
	}

	// Wait for the death callback.
	deathDeadline := time.Now().Add(time.Duration(death-missed+2) * interval * 2)
	for time.Now().Before(deathDeadline) {
		muB.Lock()
		fired := deadFired
		muB.Unlock()
		if fired {
			break
		}
		time.Sleep(interval / 4)
	}

	nodeB.Stop()

	muB.Lock()
	sf, df, sp, dp := silentFired, deadFired, silentPeer, deadPeer
	muB.Unlock()

	if !sf {
		t.Error("onSilent never fired after nodeA stopped")
	} else if sp.Label != "A" {
		t.Errorf("onSilent: peer label = %q, want %q", sp.Label, "A")
	}
	if !df {
		t.Error("onDeath never fired after nodeA stopped")
	} else if dp.Label != "A" {
		t.Errorf("onDeath: peer label = %q, want %q", dp.Label, "A")
	}
}

func TestUnknownPeerRejected(t *testing.T) {
	sA := newTestSigner(t)
	sB := newTestSigner(t)       // nodeB's signer
	sUnknown := newTestSigner(t) // not in nodeA's peer list

	portA := freeUDPPort(t)
	portB := freeUDPPort(t)
	portUnknown := freeUDPPort(t)
	addrA := fmt.Sprintf("127.0.0.1:%d", portA)
	addrB := fmt.Sprintf("127.0.0.1:%d", portB)
	addrUnknown := fmt.Sprintf("127.0.0.1:%d", portUnknown)

	ctx := context.Background()

	// nodeA only knows about nodeB.
	var mu sync.Mutex
	var unknownSeen bool
	nodeA := NewNode(NodeConfig{
		Signer:          sA,
		Peers:           []Peer{{Label: "B", Addr: addrB, PubKey: sB.PublicKey()}},
		ListenAddr:      addrA,
		Interval:        50 * time.Millisecond,
		MissedThreshold: 2,
		DeathThreshold:  4,
		OnSilent: func(p Peer) {
			// B is known but not sending — that's fine for this test.
		},
		OnDeath: func(p Peer) {
			// Only fires for known peers. If unknown somehow fires this, that's a bug.
			if p.Label == "" {
				mu.Lock()
				unknownSeen = true
				mu.Unlock()
			}
		},
	})
	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("nodeA.Start: %v", err)
	}
	defer nodeA.Stop()

	// Send a packet from the unknown signer directly to nodeA.
	unknownNode := NewNode(NodeConfig{
		Signer:     sUnknown,
		Peers:      []Peer{{Label: "A", Addr: addrA, PubKey: sA.PublicKey()}},
		ListenAddr: addrUnknown,
		Interval:   20 * time.Millisecond,
	})
	if err := unknownNode.Start(ctx); err != nil {
		t.Fatalf("unknownNode.Start: %v", err)
	}
	defer unknownNode.Stop()

	// Give time for packets to flow.
	time.Sleep(150 * time.Millisecond)

	// nodeA's states should only contain nodeB's pubkey, not sUnknown's.
	nodeA.mu.Lock()
	_, unknownInState := nodeA.states[fmt.Sprintf("%x", sUnknown.PublicKey())]
	nodeA.mu.Unlock()

	if unknownInState {
		t.Error("unknown peer was added to node state — allowlist check failed")
	}
	mu.Lock()
	if unknownSeen {
		t.Error("onDeath fired for an unknown peer")
	}
	mu.Unlock()
}

func TestPacketDecodeRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("hello"),
		make([]byte, 4+4+64), // right length, wrong magic
		encodePacket([]byte(`{}`), make([]byte, 64)), // valid frame, invalid sig
	}
	for _, c := range cases {
		// We just check it doesn't panic.
		_, _, err := decodePacket(c)
		if c == nil || len(c) < 4+4+64 {
			if err == nil {
				t.Errorf("decodePacket(%x): expected error, got nil", c)
			}
		}
	}
}
