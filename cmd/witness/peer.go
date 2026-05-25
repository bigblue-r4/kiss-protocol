package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/bigblue-r4/kiss-protocol/internal/gossip"
)

// cmdPeer handles the "witness peer" sub-commands.
//
// Usage:
//
//	witness peer list
//	witness peer add  <label> <host:port> <hex-pubkey>
//	witness peer remove <label>
func cmdPeer() {
	sub := ""
	if len(os.Args) >= 3 {
		sub = os.Args[2]
	}
	switch sub {
	case "list":
		peerList()
	case "add":
		peerAdd()
	case "remove", "rm":
		peerRemove()
	default:
		fmt.Fprintf(os.Stderr, `Usage:
  witness peer list
  witness peer add    <label> <host:port> <hex-ed25519-pubkey>
  witness peer remove <label>

Peers are the gossip ring members this node sends heartbeats to and watches.
Each peer's ed25519 public key must be obtained out-of-band from the peer's
operator and verified before being added. There is no automatic discovery.

`)
		os.Exit(1)
	}
}

func peersPath() string {
	return filepath.Join(witnessDir(), "peers.json")
}

func peerList() {
	ps, err := gossip.LoadPeers(peersPath())
	if err != nil {
		fatal("load peers: %v", err)
	}
	peers := ps.All()
	if len(peers) == 0 {
		fmt.Println("No peers configured. Use 'witness peer add' to add one.")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LABEL\tADDR\tPUBKEY")
	for _, p := range peers {
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Label, p.Addr, hex.EncodeToString(p.PubKey))
	}
	w.Flush()
}

func peerAdd() {
	if len(os.Args) < 6 {
		fatal("usage: witness peer add <label> <host:port> <hex-pubkey>")
	}
	label := os.Args[3]
	addr := os.Args[4]
	pubHex := os.Args[5]

	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		fatal("invalid pubkey: must be %d hex-encoded bytes (got %q)", ed25519.PublicKeySize, pubHex)
	}

	ps, err := gossip.LoadPeers(peersPath())
	if err != nil {
		fatal("load peers: %v", err)
	}
	if err := ps.Add(gossip.Peer{
		Label:  label,
		Addr:   addr,
		PubKey: ed25519.PublicKey(pubBytes),
	}); err != nil {
		fatal("add peer: %v", err)
	}
	fmt.Printf("[witness] Peer %q added (%s)\n", label, addr)
	fmt.Println("Restart the daemon for changes to take effect.")
}

func peerRemove() {
	if len(os.Args) < 4 {
		fatal("usage: witness peer remove <label>")
	}
	label := os.Args[3]

	ps, err := gossip.LoadPeers(peersPath())
	if err != nil {
		fatal("load peers: %v", err)
	}
	if err := ps.Remove(label); err != nil {
		fatal("remove peer: %v", err)
	}
	fmt.Printf("[witness] Peer %q removed.\n", label)
	fmt.Println("Restart the daemon for changes to take effect.")
}
