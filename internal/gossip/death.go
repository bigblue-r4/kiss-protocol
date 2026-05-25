package gossip

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

// DeathReport is broadcast to all peers when the local node is terminating.
// It is a courtesy message — the actual death signal is the absence of future
// heartbeats, which peers detect independently.
type DeathReport struct {
	Type      string `json:"type"` // "death"
	MachineID string `json:"machine_id"`
	PeerID    string `json:"peer_id"` // hex(pubkey)
	Reason    string `json:"reason"`  // e.g. "sigterm", "peer-silent:<label>"
	Ts        string `json:"ts"`
	Seq       uint64 `json:"seq"`
}

// BroadcastDeath sends a signed DeathReport to all peers over UDP.
// It is best-effort — errors are silently ignored. Call it before exiting.
func BroadcastDeath(peers []Peer, s signer.Signer, machineID, reason string, seq uint64) {
	if s == nil || len(peers) == 0 {
		return
	}
	report := DeathReport{
		Type:      "death",
		MachineID: machineID,
		PeerID:    hex.EncodeToString(s.PublicKey()),
		Reason:    reason,
		Ts:        time.Now().UTC().Format(time.RFC3339),
		Seq:       seq,
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return
	}
	sig, err := s.Sign(payload)
	if err != nil {
		return
	}
	pkt := encodePacket(payload, sig)

	for _, peer := range peers {
		raddr, err := net.ResolveUDPAddr("udp", peer.Addr)
		if err != nil {
			continue
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(pkt)
		conn.Close()
	}
}
