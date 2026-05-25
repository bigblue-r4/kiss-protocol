package gossip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

const (
	packetMagic    uint32 = 0x57495453 // "WITS"
	maxPacketBytes        = 512
	DefaultPort           = "9273"
)

// encodePacket builds the wire packet: [4 magic][4 paylen][payload][64 sig].
func encodePacket(payload, sig []byte) []byte {
	buf := make([]byte, 4+4+len(payload)+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(buf[0:4], packetMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(payload)))
	copy(buf[8:], payload)
	copy(buf[8+len(payload):], sig)
	return buf
}

// decodePacket splits a wire packet into payload and signature.
func decodePacket(data []byte) (payload, sig []byte, err error) {
	if len(data) < 4+4+ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("packet too short")
	}
	if binary.BigEndian.Uint32(data[0:4]) != packetMagic {
		return nil, nil, fmt.Errorf("bad magic")
	}
	payLen := int(binary.BigEndian.Uint32(data[4:8]))
	if 8+payLen+ed25519.SignatureSize != len(data) {
		return nil, nil, fmt.Errorf("length mismatch")
	}
	return data[8 : 8+payLen], data[8+payLen:], nil
}

// heartbeatMsg is the JSON payload for a regular heartbeat.
type heartbeatMsg struct {
	Type   string `json:"type"`    // "heartbeat"
	PeerID string `json:"peer_id"` // hex(pubkey)
	Seq    uint64 `json:"seq"`
	Ts     string `json:"ts"`    // RFC3339
	Nonce  string `json:"nonce"` // hex(16 random bytes) — anti-replay
}

// PeerStatus describes the liveness state of a remote peer.
type PeerStatus int

const (
	PeerAlive               PeerStatus = iota
	PeerSilent                         // no heartbeat for >= MissedThreshold intervals
	PeerPresumedCompromised            // no heartbeat for >= DeathThreshold intervals
)

type peerState struct {
	peer     Peer
	lastSeen time.Time
	lastSeq  uint64
	status   PeerStatus
}

// NodeConfig configures a gossip Node.
type NodeConfig struct {
	Signer          signer.Signer
	Peers           []Peer
	ListenAddr      string        // UDP bind addr; default ":9273"
	Interval        time.Duration // heartbeat send/watch interval; default 30s
	MissedThreshold int           // silent after N missed intervals; default 3
	DeathThreshold  int           // presumed-compromised after N missed; default 6
	OnSilent        func(Peer)    // called once when peer first goes silent
	OnDeath         func(Peer)    // called once when peer crosses death threshold
}

// Node is a gossip participant: it sends signed heartbeats to all peers and
// watches incoming heartbeats, firing callbacks when a peer goes silent.
type Node struct {
	s        signer.Signer
	peers    []Peer
	listenOn string
	interval time.Duration
	missed   int
	death    int
	onSilent func(Peer)
	onDeath  func(Peer)

	mu     sync.Mutex
	states map[string]*peerState // keyed by hex(pubkey)
	seq    uint64
	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan struct{}
}

// NewNode creates a gossip Node from cfg.
func NewNode(cfg NodeConfig) *Node {
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.MissedThreshold == 0 {
		cfg.MissedThreshold = 3
	}
	if cfg.DeathThreshold == 0 {
		cfg.DeathThreshold = 6
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":" + DefaultPort
	}

	n := &Node{
		s:        cfg.Signer,
		peers:    cfg.Peers,
		listenOn: cfg.ListenAddr,
		interval: cfg.Interval,
		missed:   cfg.MissedThreshold,
		death:    cfg.DeathThreshold,
		onSilent: cfg.OnSilent,
		onDeath:  cfg.OnDeath,
		states:   make(map[string]*peerState),
		done:     make(chan struct{}),
	}
	now := time.Now()
	for _, p := range cfg.Peers {
		id := hex.EncodeToString(p.PubKey)
		n.states[id] = &peerState{peer: p, lastSeen: now, status: PeerAlive}
	}
	return n
}

// Start binds the UDP socket and launches send/receive/watch goroutines.
func (n *Node) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", n.listenOn)
	if err != nil {
		return fmt.Errorf("gossip: resolve %q: %w", n.listenOn, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("gossip: listen: %w", err)
	}
	n.conn = conn

	ctx, n.cancel = context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); n.recvLoop(ctx) }()
	go func() { defer wg.Done(); n.sendLoop(ctx) }()
	go func() { defer wg.Done(); n.watchLoop(ctx) }()
	go func() { wg.Wait(); close(n.done) }()
	return nil
}

// Stop cancels the context and waits for all goroutines to exit.
func (n *Node) Stop() {
	if n.cancel != nil {
		n.cancel()
	}
	if n.conn != nil {
		n.conn.Close()
	}
	<-n.done
}

// LocalAddr returns the UDP address the node is listening on.
// Only valid after Start has been called.
func (n *Node) LocalAddr() net.Addr {
	if n.conn == nil {
		return nil
	}
	return n.conn.LocalAddr()
}

// PeerStatuses returns a snapshot of every peer's current liveness state.
func (n *Node) PeerStatuses() map[string]PeerStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string]PeerStatus, len(n.states))
	for id, st := range n.states {
		out[id] = st.status
	}
	return out
}

func (n *Node) sendLoop(ctx context.Context) {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	n.sendHeartbeat() // send immediately on start
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.sendHeartbeat()
		}
	}
}

func (n *Node) sendHeartbeat() {
	if n.s == nil {
		return
	}
	n.mu.Lock()
	n.seq++
	seq := n.seq
	n.mu.Unlock()

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])

	msg := heartbeatMsg{
		Type:   "heartbeat",
		PeerID: hex.EncodeToString(n.s.PublicKey()),
		Seq:    seq,
		Ts:     time.Now().UTC().Format(time.RFC3339),
		Nonce:  hex.EncodeToString(nonce[:]),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	sig, err := n.s.Sign(payload)
	if err != nil {
		return
	}
	pkt := encodePacket(payload, sig)

	for _, peer := range n.peers {
		raddr, err := net.ResolveUDPAddr("udp", peer.Addr)
		if err != nil {
			continue
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			continue
		}
		_, _ = conn.Write(pkt)
		conn.Close()
	}
}

func (n *Node) recvLoop(ctx context.Context) {
	buf := make([]byte, maxPacketBytes)
	for {
		_ = n.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		nr, _, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		n.handlePacket(buf[:nr])
	}
}

func (n *Node) handlePacket(data []byte) {
	payload, sig, err := decodePacket(data)
	if err != nil {
		return
	}

	// Unmarshal just enough to get the peer_id for allowlist lookup.
	var hdr struct {
		PeerID string `json:"peer_id"`
		Seq    uint64 `json:"seq"`
	}
	if err := json.Unmarshal(payload, &hdr); err != nil || hdr.PeerID == "" {
		return
	}

	pubBytes, err := hex.DecodeString(hdr.PeerID)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return
	}

	// Reject packets from unknown peers before verifying the signature.
	n.mu.Lock()
	st, known := n.states[hdr.PeerID]
	n.mu.Unlock()
	if !known {
		return
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sig) {
		log.Printf("[gossip] invalid signature from peer %s — dropping", st.peer.Label)
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	// Anti-replay: seq must be strictly greater than last seen.
	if hdr.Seq <= st.lastSeq {
		return
	}
	st.lastSeq = hdr.Seq
	st.lastSeen = time.Now()
	if st.status != PeerAlive {
		log.Printf("[gossip] peer %s is back online", st.peer.Label)
		st.status = PeerAlive
	}
}

func (n *Node) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.checkPeers()
		}
	}
}

func (n *Node) checkPeers() {
	now := time.Now()
	n.mu.Lock()
	var silent, dead []Peer
	for _, st := range n.states {
		missed := int(now.Sub(st.lastSeen) / n.interval)
		switch {
		case missed >= n.death && st.status != PeerPresumedCompromised:
			st.status = PeerPresumedCompromised
			dead = append(dead, st.peer)
		case missed >= n.missed && st.status == PeerAlive:
			st.status = PeerSilent
			silent = append(silent, st.peer)
		}
	}
	n.mu.Unlock()

	for _, p := range silent {
		log.Printf("[gossip] peer %s silent (missed %d intervals)", p.Label, n.missed)
		if n.onSilent != nil {
			n.onSilent(p)
		}
	}
	for _, p := range dead {
		log.Printf("[gossip] peer %s presumed compromised (missed %d intervals)", p.Label, n.death)
		if n.onDeath != nil {
			n.onDeath(p)
		}
	}
}
