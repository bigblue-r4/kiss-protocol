// Package gossip implements a lightweight peer-to-peer heartbeat mesh.
//
// Trust model: peers are operator-configured out-of-band. No automatic
// discovery, no TOFU. A peer's ed25519 public key must be recorded in the
// peer store before any packet from that peer is accepted. This is the SSH
// known_hosts model — simple, auditable, and immune to man-in-the-middle on
// first contact.
//
// Wire: [4 magic][4 payload-len][payload JSON][64 ed25519 sig]
// Port: UDP 9273 (configurable via GossipListenAddr in config.json).
package gossip

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Peer is a trusted gossip peer.
type Peer struct {
	Label  string
	Addr   string // "host:port" UDP address
	PubKey ed25519.PublicKey
}

type peerWire struct {
	Label  string `json:"label"`
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey"` // hex-encoded ed25519 public key
}

func (p Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(peerWire{
		Label:  p.Label,
		Addr:   p.Addr,
		PubKey: hex.EncodeToString(p.PubKey),
	})
}

func (p *Peer) UnmarshalJSON(data []byte) error {
	var w peerWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	b, err := hex.DecodeString(w.PubKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("peer %q: invalid pubkey", w.Label)
	}
	p.Label = w.Label
	p.Addr = w.Addr
	p.PubKey = ed25519.PublicKey(b)
	return nil
}

// PeerStore loads and persists the peer list.
type PeerStore struct {
	path  string
	peers []Peer
}

// LoadPeers reads peers from path. Returns an empty store if the file does
// not exist.
func LoadPeers(path string) (*PeerStore, error) {
	ps := &PeerStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ps, nil
		}
		return nil, err
	}
	return ps, json.Unmarshal(data, &ps.peers)
}

// All returns a copy of the peer list.
func (ps *PeerStore) All() []Peer {
	out := make([]Peer, len(ps.peers))
	copy(out, ps.peers)
	return out
}

// Add appends a peer, rejecting duplicates by label or public key.
func (ps *PeerStore) Add(p Peer) error {
	for _, e := range ps.peers {
		if e.Label == p.Label {
			return fmt.Errorf("peer with label %q already exists", p.Label)
		}
		if string(e.PubKey) == string(p.PubKey) {
			return fmt.Errorf("peer with this pubkey already exists (label: %q)", e.Label)
		}
	}
	ps.peers = append(ps.peers, p)
	return ps.save()
}

// Remove deletes a peer by label.
func (ps *PeerStore) Remove(label string) error {
	n := len(ps.peers)
	filtered := ps.peers[:0]
	for _, p := range ps.peers {
		if p.Label != label {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == n {
		return fmt.Errorf("peer %q not found", label)
	}
	ps.peers = filtered
	return ps.save()
}

func (ps *PeerStore) save() error {
	if err := os.MkdirAll(filepath.Dir(ps.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ps.peers, "", "  ")
	if err != nil {
		return err
	}
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ps.path)
}
