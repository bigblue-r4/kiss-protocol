// enforcer — kiss-enforcer: the distributed enforcement layer for Harborlight.
//
// The enforcer is a privileged asynchronous reader of the kiss-core Merkle log.
// It handles everything that is "noisy" or network-facing:
//
//   - Gossip peer mesh (UDP heartbeats + liveness tracking)
//   - Peer death detection and cross-node alert broadcasting
//   - Loyalty policy evaluation against the live log stream
//   - Anomaly reporting to operator-controlled endpoints
//
// The enforcer NEVER writes to the kiss-core log. It reads the encrypted log
// at cfg.CoreLogDir via store.ReadAll and delivers events to its own pipeline.
// Compromise of the enforcer cannot corrupt or falsify the core witness record.
//
// Commands:
//
//	enforcer start              Start the enforcer daemon.
//	enforcer peer add           Register a gossip peer.
//	enforcer peer remove        Remove a gossip peer.
//	enforcer peer list          List configured peers and liveness.
//	enforcer status             Print enforcer daemon status.
//	enforcer version            Print version.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/enforcer"
	"github.com/bigblue-r4/kiss-protocol/internal/gossip"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
)

const version = "3.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "start":
		cmdStart()
	case "peer":
		cmdPeer()
	case "status":
		cmdStatus()
	case "version", "--version", "-v":
		fmt.Printf("SGAIL Labs Harborlight enforcer v%s\n", version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `SGAIL Labs Harborlight enforcer v%s

Usage:
  enforcer start [--dev]          Start the enforcer daemon
  enforcer peer add <l> <a> <k>  Add gossip peer (label, UDP addr, hex pubkey)
  enforcer peer remove <label>   Remove a gossip peer
  enforcer peer list             List configured peers
  enforcer status                Print last known enforcer status
  enforcer version               Print version

The enforcer reads the kiss-core log (default: ~/.witness/primary) but never
writes to it. Configure the core log path via --core-dir or WITNESS_CORE_DIR.
`, version)
}

// ── start ─────────────────────────────────────────────────────────────────────

func cmdStart() {
	devMode := false
	for _, a := range os.Args[2:] {
		if a == "--dev" {
			devMode = true
		}
	}

	// Load the soul so the enforcer carries the same identity as the core.
	agentSoul, err := soul.Load(soul.Path())
	if err != nil {
		fatal("soul: %v", err)
	}
	fmt.Printf("[enforcer] Soul: %s %s\n",
		agentSoul.Identity.AgentName, agentSoul.Identity.AgentVersion)

	// Derive the machine key — same derivation as kiss-core.
	mid := machid.Get()
	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	// Core log directory: use same primary dir as core config.
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load core config: %v", err)
	}
	coreDir := cfg.PrimaryDir

	// Resolve the signing key for gossip authentication.
	var signerInst signer.Signer
	if devMode {
		signerInst, err = signer.NewDev(enforcerDir())
		if err != nil {
			fatal("dev signer: %v", err)
		}
	} else {
		signerInst, err = signer.NewPIV()
		if err != nil {
			warn("hardware signer unavailable: %v (gossip will not send signed heartbeats)", err)
		}
	}

	// ── Gossip peer mesh ──────────────────────────────────────────────────
	peerStore, err := gossip.LoadPeers(peerFile())
	if err != nil {
		warn("load peers: %v (gossip disabled)", err)
	}
	peers := peerStore.All()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gossipNode *gossip.Node
	if len(peers) > 0 && signerInst != nil {
		gossipNode = gossip.NewNode(gossip.NodeConfig{
			Signer:     signerInst,
			Peers:      peers,
			ListenAddr: ":" + gossip.DefaultPort,
			OnSilent: func(p gossip.Peer) {
				warn("gossip: peer %q silent", p.Label)
			},
			OnDeath: func(p gossip.Peer) {
				warn("gossip: peer %q PRESUMED COMPROMISED — alerting", p.Label)
				// Fire a cross-node death broadcast back to remaining peers.
				gossip.BroadcastDeath(peers, signerInst, mid,
					"peer-presumed-compromised:"+p.Label, 0)
			},
		})
		if err := gossipNode.Start(ctx); err != nil {
			warn("gossip start: %v (gossip disabled)", err)
			gossipNode = nil
		} else {
			fmt.Printf("[enforcer] Gossip listening on %s (%d peer(s))\n",
				gossipNode.LocalAddr(), len(peers))
		}
	}

	// ── Core log tail reader ──────────────────────────────────────────────
	evtCh := make(chan enforcer.Event, 256)
	reader := enforcer.NewTailReader(coreDir, key, 5*time.Second, evtCh)
	go reader.Run(ctx)

	// ── Signal handling ───────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	fmt.Printf("[enforcer] Daemon started (PID %d), tailing %s\n", os.Getpid(), coreDir)

	for {
		select {
		case evt := <-evtCh:
			handleEvent(evt, peers, signerInst, mid)

		case sig := <-sigCh:
			fmt.Printf("[enforcer] Signal %s — shutting down\n", sig)
			cancel()
			reader.Wait()
			if gossipNode != nil {
				gossip.BroadcastDeath(peers, signerInst, mid, "enforcer-shutdown:"+sig.String(), 0)
				gossipNode.Stop()
			}
			return
		}
	}
}

// handleEvent evaluates a decoded core log entry against loyalty policy.
// Currently: DEATH-level events trigger a peer broadcast; DRIFT events are
// logged to stderr. A future policy engine replaces the switch.
func handleEvent(evt enforcer.Event, peers []gossip.Peer, s signer.Signer, mid string) {
	switch evt.Level {
	case "DEATH":
		fmt.Printf("[enforcer] DEATH event received from core: %s/%s\n",
			evt.Source, evt.Event)
		gossip.BroadcastDeath(peers, s, mid, "core-death:"+evt.Event, evt.Seq)

	case "DRIFT":
		fmt.Printf("[enforcer] DRIFT detected at seq=%d source=%s\n",
			evt.Seq, evt.Source)

	case "WARN":
		fmt.Printf("[enforcer] WARN seq=%d %s/%s\n", evt.Seq, evt.Source, evt.Event)
	}
}

// ── peer ──────────────────────────────────────────────────────────────────────

func cmdPeer() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: enforcer peer <add|remove|list>")
		os.Exit(1)
	}
	ps, err := gossip.LoadPeers(peerFile())
	if err != nil {
		fatal("load peers: %v", err)
	}
	switch os.Args[2] {
	case "add":
		// enforcer peer add <label> <addr> <hex-pubkey>
		if len(os.Args) < 6 {
			fatal("usage: enforcer peer add <label> <addr> <hex-pubkey>")
		}
		label, addr, pubHex := os.Args[3], os.Args[4], os.Args[5]
		raw, err := hex.DecodeString(pubHex)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			fatal("invalid pubkey %q: must be 64 hex chars (ed25519)", pubHex)
		}
		if err := ps.Add(gossip.Peer{Label: label, Addr: addr, PubKey: ed25519.PublicKey(raw)}); err != nil {
			fatal("add peer: %v", err)
		}
		fmt.Printf("[enforcer] Peer added: %s @ %s\n", label, addr)

	case "remove":
		if len(os.Args) < 4 {
			fatal("usage: enforcer peer remove <label>")
		}
		if err := ps.Remove(os.Args[3]); err != nil {
			fatal("remove peer: %v", err)
		}
		fmt.Printf("[enforcer] Peer removed: %s\n", os.Args[3])

	case "list":
		peers := ps.All()
		if len(peers) == 0 {
			fmt.Println("No peers configured.")
			return
		}
		fmt.Printf("%-20s  %-30s  %s\n", "LABEL", "ADDR", "PUBKEY")
		for _, p := range peers {
			pk := hex.EncodeToString(p.PubKey)
			fmt.Printf("%-20s  %-30s  %s\n", p.Label, p.Addr, pk[:16]+"…")
		}

	default:
		fatal("unknown peer subcommand: %s", os.Args[2])
	}
}

// ── status ────────────────────────────────────────────────────────────────────

func cmdStatus() {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not load core config.")
		os.Exit(1)
	}
	ps, _ := gossip.LoadPeers(peerFile())
	peers := ps.All()

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("Core log dir  : %s\n", cfg.PrimaryDir)
	fmt.Printf("Peer file     : %s\n", peerFile())
	fmt.Printf("Peers         : %d configured\n", len(peers))
	for _, p := range peers {
		fmt.Printf("  %-20s  %s\n", p.Label, p.Addr)
	}
	fmt.Println("─────────────────────────────────────────")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func enforcerDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".enforcer")
}

func peerFile() string {
	return filepath.Join(enforcerDir(), "peers.json")
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[enforcer] FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[enforcer] WARN: "+format+"\n", args...)
}
