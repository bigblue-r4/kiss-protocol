// witness — continuous machine-state witness client built on Pipelock.
//
// Commands:
//
//	witness init              Take genesis snapshot and initialize the witness log.
//	witness start             Start the witness daemon (blocks until signaled).
//	witness status            Print current status.
//	witness verify            Walk the Merkle log and verify integrity.
//	witness prove <index>     Emit an inclusion proof for the leaf at index.
//	witness migrate           Import a v1 log into the v2 Merkle log (one-shot).
//	witness enable-sync       Enable opt-in SGAIL remote sync.
//	witness watchdog <args>   Internal watchdog subprocess — do not call directly.
//	witness version           Print version.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/anomaly"
	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/death"
	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
	"github.com/bigblue-r4/kiss-protocol/internal/gossip"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/migrate"
	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock_bridge"
	"github.com/bigblue-r4/kiss-protocol/internal/sgail"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		cmdInit()
	case "start":
		cmdStart()
	case "status":
		cmdStatus()
	case "verify":
		cmdVerify()
	case "prove":
		cmdProve()
	case "migrate":
		cmdMigrate()
	case "soul":
		cmdSoul()
	case "audit":
		cmdAudit()
	case "peer":
		cmdPeer()
	case "enable-sync":
		cmdEnableSync()
	case "watchdog":
		cmdWatchdog()
	case "version", "--version", "-v":
		fmt.Println("SGAIL Labs Harborlight Firewall witness v" + version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `SGAIL Labs Harborlight Firewall witness v%s

Usage:
  witness init                    Take genesis snapshot, initialize Merkle log
  witness start [--dev]           Start the continuous witness daemon
  witness status                  Show current witness status
  witness verify                  Walk Merkle log and verify integrity
  witness prove <index>           Emit inclusion proof for leaf at index
  witness migrate                 Import v1 log into v2 Merkle log (one-shot)
  witness soul sign               Sign the soul file with the configured signer
  witness soul verify             Verify soul file signature against allowlist
  witness audit                   Compare local Merkle log to transparency mirror
  witness peer list               List configured gossip peers
  witness peer add <l> <addr> <k> Add a gossip peer (label, UDP addr, hex pubkey)
  witness peer remove <label>     Remove a gossip peer
  witness enable-sync             Configure opt-in SGAIL Labs remote sync [deprecated]
  witness version                 Print version

`, version)
}

// ── init ─────────────────────────────────────────────────────────────────────

func cmdInit() {
	// ── Soul file — load first, before anything else ──────────────────────
	// The soul is the agent's immutable identity. If it fails verification,
	// we halt here. Nothing happens until the soul is clean.
	fmt.Println()
	fmt.Println("  Loading soul file…")
	if !soul.Exists() {
		fmt.Println()
		fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("  ║  NO SOUL FILE FOUND                                          ║")
		fmt.Println("  ║                                                              ║")
		fmt.Println("  ║  Expected: ~/.witness/soul.toml                              ║")
		fmt.Println("  ║                                                              ║")
		fmt.Println("  ║  If you installed from GitHub, re-run install.sh — it will  ║")
		fmt.Println("  ║  fetch the default soul file automatically.                  ║")
		fmt.Println("  ║  USB installs: re-run the installer from the USB stick.      ║")
		fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
		os.Exit(1)
	}
	agentSoul, err := soul.Load(soul.Path())
	if err != nil {
		fmt.Println()
		fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("  ║  SOUL FILE INTEGRITY CHECK FAILED                            ║")
		fmt.Println("  ║  This agent will not run.                                    ║")
		fmt.Println("  ║  Do not proceed. Contact your administrator.                 ║")
		fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
		fmt.Printf("\n  Detail: %v\n\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Soul verified. Agent: %s %s (%s)\n",
		agentSoul.Identity.AgentName,
		agentSoul.Identity.AgentVersion,
		agentSoul.Identity.Organization,
	)
	fmt.Printf("  Prime law: \"%s\"\n", agentSoul.PrimeLaw.Text)
	fmt.Println()

	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v", err)
	}

	// ── Agent preflight scan ─────────────────────────────────────────────
	// Genesis must be taken BEFORE any AI agent is installed.
	// If agents are already present, the snapshot is compromised from the start.
	fmt.Println("[witness] Scanning for pre-existing AI agents…")
	agents := genesis.ScanForAgents()
	if len(agents) > 0 {
		fmt.Println()
		fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("  ║  WARNING: AI AGENTS DETECTED BEFORE GENESIS                 ║")
		fmt.Println("  ║                                                              ║")
		fmt.Println("  ║  The following agents already have access to this machine.  ║")
		fmt.Println("  ║  Genesis should be taken on a clean machine BEFORE agents   ║")
		fmt.Println("  ║  are installed. This snapshot will be marked COMPROMISED.   ║")
		fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
		fmt.Println()
		for _, a := range agents {
			fmt.Printf("  DETECTED  %-22s  %s\n", a.Name, a.Found)
		}
		fmt.Println()
		fmt.Print("  Proceed anyway? The genesis will be flagged [AGENTS_PRESENT]. [y/N]: ")
		var confirm string
		_, _ = fmt.Scanln(&confirm)
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			fmt.Println()
			fmt.Println("  Correct approach:")
			fmt.Println("  1. Start with a clean OS install")
			fmt.Println("  2. Run: witness init")
			fmt.Println("  3. Then install your AI agents")
			fmt.Println("  4. Run: witness start")
			fmt.Println()
			os.Exit(0)
		}
	} else {
		fmt.Println("[witness] Clean — no AI agents detected. Genesis is trustworthy.")
	}

	// ── Take genesis snapshot ─────────────────────────────────────────────
	fmt.Println("[witness] Taking genesis snapshot…")
	snap, err := genesis.Take(mid)
	if err != nil {
		fatal("genesis: %v", err)
	}
	if !snap.Verify() {
		fatal("genesis: integrity check failed immediately after creation")
	}
	snap.AgentsAtGenesis = agents // record what was present (may be empty)

	snapBytes, err := snap.Bytes()
	if err != nil {
		fatal("marshal genesis: %v", err)
	}

	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	snapEnc, err := encrypt.Seal(snapBytes, key)
	if err != nil {
		fatal("encrypt genesis: %v", err)
	}

	// ── Store genesis ─────────────────────────────────────────────────────
	if err := os.MkdirAll(cfg.PrimaryDir, 0700); err != nil {
		fatal("create primary dir: %v", err)
	}
	mustWrite(filepath.Join(cfg.PrimaryDir, "genesis.enc"), snapEnc)

	// ── Open the primary log and write genesis entry (entry zero) ─────────
	s, err := store.Open(cfg.PrimaryDir, key, nil)
	if err != nil {
		fatal("open store: %v", err)
	}
	genesisStatus := "CLEAN"
	if !snap.Clean() {
		genesisStatus = "COMPROMISED"
	}
	soulHash, _ := soul.Hash(soul.Path())
	if err := s.Append("SYSTEM", "genesis", "witness-init", map[string]interface{}{
		"machine_id":        mid,
		"genesis_hash":      snap.Hash,
		"genesis_ts":        snap.Timestamp,
		"files_watched":     len(snap.Files),
		"genesis_status":    genesisStatus,
		"agents_at_genesis": snap.AgentsAtGenesis,
		"soul_hash":         soulHash,
		"agent_name":        agentSoul.Identity.AgentName,
		"agent_version":     agentSoul.Identity.AgentVersion,
	}); err != nil {
		fatal("write genesis log entry: %v", err)
	}
	_ = s.Close()

	// ── Generate Pipelock config ──────────────────────────────────────────
	plCfg := pipelock.DefaultConfig(cfg.PrimaryDir)
	if err := plCfg.WriteConfig(); err != nil {
		warn("could not write pipelock config: %v (Pipelock integration disabled)", err)
	} else {
		fmt.Printf("  Pipelock   : config written → %s\n", plCfg.ConfigFile)
	}

	// ── Save config ───────────────────────────────────────────────────────
	if err := cfg.Save(config.Path()); err != nil {
		fatal("save config: %v", err)
	}

	fmt.Println()
	if snap.Clean() {
		fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("  ║  GENESIS: CLEAN                                              ║")
		fmt.Println("  ║  No agents present. Witness established before any agent.   ║")
		fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("  ║  GENESIS: COMPROMISED — AGENTS WERE PRESENT                 ║")
		fmt.Println("  ║  Witness installed after agents. Trust level: LOW.          ║")
		fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
	}
	fmt.Println()
	fmt.Printf("  Machine ID : %s\n", mid)
	fmt.Printf("  Hash       : %s\n", snap.Hash)
	fmt.Printf("  Files      : %d paths watched\n", len(snap.Files))
	fmt.Printf("  Log        : %s\n", cfg.PrimaryDir)
	fmt.Printf("\nNow install your AI agents, then run: witness start\n")
}

// ── start ─────────────────────────────────────────────────────────────────────

func cmdStart() {
	devMode := false
	for _, arg := range os.Args[2:] {
		if arg == "--dev" {
			devMode = true
		}
	}

	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v", err)
	}

	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	// ── Resolve signer ────────────────────────────────────────────────────
	signerInst := resolveSigner(devMode, witnessDir())

	// ── Soul signature verification ───────────────────────────────────────
	checkSoulSignature(soul.Path(), devMode)

	// Load and verify genesis.
	snapEncBytes, err := os.ReadFile(filepath.Join(cfg.PrimaryDir, "genesis.enc"))
	if err != nil {
		fatal("read genesis: %v\n\nRun 'witness init' first.", err)
	}
	snapBytes, err := encrypt.Open(snapEncBytes, key)
	if err != nil {
		fatal("decrypt genesis: %v", err)
	}
	snap, err := genesis.Load(snapBytes)
	if err != nil {
		fatal("parse genesis: %v", err)
	}
	if !snap.Verify() {
		fatal("CRITICAL: genesis integrity check failed — possible tampering detected")
	}

	// Open primary log with the configured signer.
	s, err := store.Open(cfg.PrimaryDir, key, signerInst)
	if err != nil {
		fatal("open store: %v", err)
	}

	// Build SGAIL client only if opted in.
	var sgailClient *sgail.Client
	if cfg.SGAILEnabled && cfg.SGAILEndpoint != "" {
		sgailClient = sgail.NewClient(cfg.SGAILEndpoint, cfg.SGAILToken)
		if err := sgailClient.Ping(); err != nil {
			warn("SGAIL server unreachable: %v (will retry on next sync cycle)", err)
		} else {
			fmt.Printf("[witness] SGAIL sync enabled → %s\n", cfg.SGAILEndpoint)
		}
	}

	broadcaster := death.New(cfg.PrimaryDir, mid, sgailClient)

	// ── Gossip heartbeat mesh ─────────────────────────────────────────────
	gossipCtx, gossipCancel := context.WithCancel(context.Background())
	var gossipNode *gossip.Node
	var gossipPeers []gossip.Peer
	peerStore, peerErr := gossip.LoadPeers(filepath.Join(witnessDir(), "peers.json"))
	if peerErr != nil {
		warn("load peers: %v (gossip disabled)", peerErr)
	} else if len(peerStore.All()) > 0 {
		gossipPeers = peerStore.All()
		listenAddr := cfg.GossipListenAddr
		if listenAddr == "" {
			listenAddr = ":" + gossip.DefaultPort
		}
		gossipNode = gossip.NewNode(gossip.NodeConfig{
			Signer:     signerInst,
			Peers:      gossipPeers,
			ListenAddr: listenAddr,
			OnSilent: func(p gossip.Peer) {
				_ = s.Append("WARN", "peer_silent", "gossip", map[string]string{"peer": p.Label, "addr": p.Addr})
				warn("Gossip: peer %q silent", p.Label)
			},
			OnDeath: func(p gossip.Peer) {
				_ = s.Append("WARN", "peer_presumed_compromised", "gossip", map[string]string{"peer": p.Label, "addr": p.Addr})
				warn("Gossip: peer %q presumed compromised — possible tampering or crash", p.Label)
			},
		})
		if err := gossipNode.Start(gossipCtx); err != nil {
			warn("gossip start: %v (gossip disabled)", err)
			gossipNode = nil
		} else {
			fmt.Printf("[witness] Gossip listening on %s (%d peer(s))\n", gossipNode.LocalAddr(), len(gossipPeers))
		}
	}

	// ── Transparency mirror ────────────────────────────────────────────────
	var mirrorBackend mirror.Mirror
	if cfg.MirrorURL != "" {
		if mb, err := mirror.Open(cfg.MirrorURL); err != nil {
			warn("mirror open: %v (mirror push disabled)", err)
		} else {
			mirrorBackend = mb
			fmt.Printf("[witness] Mirror push enabled → %s\n", cfg.MirrorURL)
		}
	}

	// ── Pipelock bridge ────────────────────────────────────────────────────
	plCfg := pipelock.DefaultConfig(cfg.PrimaryDir)
	bridge := pipelock_bridge.New(plCfg, s)
	if err := bridge.Start(); err != nil {
		warn("Pipelock unavailable: %v (agent events will not be forwarded)", err)
	} else {
		fmt.Printf("[witness] Pipelock proxy running → %s\n", bridge.ProxyAddr())
		fmt.Printf("[witness] Set HTTPS_PROXY=%s HTTP_PROXY=%s in your agent environment.\n",
			bridge.ProxyAddr(), bridge.ProxyAddr())
	}

	// ── Anomaly detector (storage + network) ──────────────────────────────
	anomalyCh := make(chan anomaly.Event, 8)
	adet := anomaly.New(cfg.PrimaryDir, 10*time.Second, anomalyCh)
	adet.Run()

	// ── External watchdog subprocess (handles SIGKILL) ────────────────────
	spawnWatchdog(mid, cfg.PrimaryDir, cfg.SGAILEndpoint, cfg.SGAILToken)

	// ── Signal handlers ───────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	_ = s.Append("INFO", "daemon_start", "witness", map[string]interface{}{
		"pid":          os.Getpid(),
		"genesis_hash": snap.Hash,
		"sgail":        cfg.SGAILEnabled,
		"pipelock":     plCfg.AuditLogPath(),
	})

	fmt.Printf("[witness] Daemon started (PID %d)\n", os.Getpid())
	fmt.Printf("[witness] Genesis: %s\n", snap.Hash)

	// tryPushMirror reads the on-disk tree-head.json and pushes it to the
	// configured mirror in a fire-and-forget goroutine. Errors are logged.
	tryPushMirror := func() {
		if mirrorBackend == nil {
			return
		}
		data, err := os.ReadFile(filepath.Join(cfg.PrimaryDir, "tree-head.json"))
		if err != nil {
			return
		}
		go func() {
			if err := mirrorBackend.Push(json.RawMessage(data)); err != nil {
				warn("mirror push: %v", err)
			}
		}()
	}
	// Push immediately after daemon_start so the mirror reflects the current head.
	tryPushMirror()

	driftTick := time.NewTicker(time.Duration(cfg.DriftIntervalSec) * time.Second)
	syncTick := time.NewTicker(time.Duration(cfg.SyncIntervalSec) * time.Second)
	defer driftTick.Stop()
	defer syncTick.Stop()

	// fireDeath tears everything down and broadcasts, then returns.
	var deathSeq uint64
	fireDeath := func(reason, detail string) {
		fmt.Printf("[witness] Death trigger: %s — broadcasting…\n", reason)
		_ = s.Append("DEATH", reason, "witness", map[string]string{"detail": detail})
		bridge.Stop()
		adet.Stop()
		gossipCancel()
		if gossipNode != nil {
			deathSeq++
			gossip.BroadcastDeath(gossipPeers, signerInst, mid, reason, deathSeq)
			gossipNode.Stop()
		}
		_ = s.Close()
		logData, _ := os.ReadFile(filepath.Join(cfg.PrimaryDir, "witness.log"))
		broadcaster.Fire(logData, snapEncBytes)
		fmt.Printf("[witness] Death broadcast complete.\n")
	}

	for {
		select {

		// ── Anomaly detection ──────────────────────────────────────────────
		case a := <-anomalyCh:
			_ = s.Append("WARN", string(a.Kind), "anomaly", a)
			warn("Anomaly detected: %s — %s", a.Kind, a.Detail)
			// Storage anomaly means we can't rely on the log — broadcast immediately.
			if a.Kind == anomaly.KindStorage {
				fireDeath(string(a.Kind), a.Detail)
				return
			}

		// ── Drift check ────────────────────────────────────────────────────
		case <-driftTick.C:
			changes, err := drift.Measure(snap)
			if err != nil {
				_ = s.Append("ERROR", "drift_check_error", "drift", map[string]string{"err": err.Error()})
				continue
			}
			if len(changes) > 0 {
				_ = s.Append("DRIFT", "drift_detected", "drift", changes)
				fmt.Printf("[witness] Drift: %d change(s) detected\n", len(changes))
			} else {
				_ = s.Append("INFO", "drift_clean", "drift", nil)
			}
			tryPushMirror()

		// ── SGAIL sync ─────────────────────────────────────────────────────
		case <-syncTick.C:
			if sgailClient == nil {
				continue
			}
			logData, err := s.Snapshot()
			if err != nil {
				continue
			}
			if err := sgailClient.Push(mid, snap.Hash, logData); err != nil {
				_ = s.Append("WARN", "sgail_sync_failed", "sgail", map[string]string{"err": err.Error()})
				warn("SGAIL sync: %v", err)
			} else {
				_ = s.Append("INFO", "sgail_sync_ok", "sgail", nil)
			}

		// ── Termination signal ─────────────────────────────────────────────
		case sig := <-sigCh:
			fireDeath("signal_received", sig.String())
			return
		}
	}
}

// ── enable-sync ───────────────────────────────────────────────────────────────
//
// Usage:
//   witness enable-sync                                     (interactive)
//   witness enable-sync --endpoint https://... [--token t]  (non-interactive)

func cmdEnableSync() {
	fmt.Fprintln(os.Stderr, "[witness] DEPRECATED: SGAIL remote sync is deprecated in favour of the")
	fmt.Fprintln(os.Stderr, "          gossip peer mesh (witness peer add). It will be removed in the")
	fmt.Fprintln(os.Stderr, "          next major release. See docs/migrating-from-sgail-sync.md.")
	fmt.Fprintln(os.Stderr, "")

	// Parse optional flags: --endpoint <url> --token <tok>
	var flagEndpoint, flagToken string
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				flagEndpoint = args[i+1]
				i++
			}
		case "--token":
			if i+1 < len(args) {
				flagToken = args[i+1]
				i++
			}
		}
	}

	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v", err)
	}

	var endpoint, token string

	if flagEndpoint != "" {
		// Non-interactive mode.
		endpoint = flagEndpoint
		token = flagToken
		if token == "" {
			token = os.Getenv("WITNESS_SGAIL_TOKEN")
		}
	} else {
		// Interactive mode.
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("SGAIL server endpoint (e.g. https://sgail.example.com): ")
		endpoint, _ = reader.ReadString('\n')
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			fatal("endpoint required")
		}
		fmt.Print("SGAIL auth token (leave blank if none): ")
		token, _ = reader.ReadString('\n')
		token = strings.TrimSpace(token)
	}

	cfg.SGAILEnabled = true
	cfg.SGAILEndpoint = endpoint
	cfg.SGAILToken = token

	// Verify connectivity before saving.
	client := sgail.NewClient(endpoint, token)
	if err := client.Ping(); err != nil {
		warn("Cannot reach SGAIL server: %v", err)
		if flagEndpoint == "" {
			// Interactive: ask to proceed.
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Save anyway? [y/N]: ")
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
				fmt.Println("Aborted.")
				return
			}
		}
		// Non-interactive: save anyway (caller's responsibility to ensure reachability).
	} else {
		fmt.Println("SGAIL server reachable.")
	}

	if err := cfg.Save(config.Path()); err != nil {
		fatal("save config: %v", err)
	}
	fmt.Printf("[witness] Remote sync enabled → %s\n", endpoint)
	fmt.Println("Restart the daemon for changes to take effect.")
}

// ── status ────────────────────────────────────────────────────────────────────

func cmdStatus() {
	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fmt.Fprintln(os.Stderr, "No witness config found. Run 'witness init' first.")
		os.Exit(1)
	}

	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	entries, err := store.ReadAll(cfg.PrimaryDir, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read log: %v\n", err)
		os.Exit(1)
	}

	driftCount := 0
	for _, e := range entries {
		if e.Level == "DRIFT" {
			driftCount++
		}
	}

	// Load genesis to show trust status.
	snapEncBytes, _ := os.ReadFile(filepath.Join(cfg.PrimaryDir, "genesis.enc"))
	genesisStatus := "unknown"
	var agentCount int
	if len(snapEncBytes) > 0 {
		if snapBytes, err := encrypt.Open(snapEncBytes, key); err == nil {
			if snap, err := genesis.Load(snapBytes); err == nil {
				if snap.Clean() {
					genesisStatus = "CLEAN"
				} else {
					genesisStatus = fmt.Sprintf("COMPROMISED (%d agents present at genesis)", len(snap.AgentsAtGenesis))
					agentCount = len(snap.AgentsAtGenesis)
				}
			}
		}
	}
	_ = agentCount

	// Build tree head for display.
	s, err := store.Open(cfg.PrimaryDir, key, nil)
	var treeSize uint64
	var treeRoot string
	var integrityStatus string
	if err != nil {
		integrityStatus = "FAIL: " + err.Error()
	} else {
		head := s.Head()
		treeSize = head.Size
		treeRoot = head.Root
		integrityStatus = "OK"
		_ = s.Close()
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("Machine ID    : %s\n", mid)
	fmt.Printf("Genesis       : %s\n", genesisStatus)
	fmt.Printf("Log entries   : %d\n", len(entries))
	fmt.Printf("Drift events  : %d\n", driftCount)
	fmt.Printf("Tree size     : %d\n", treeSize)
	fmt.Printf("Tree root     : %s\n", treeRoot)
	fmt.Printf("Integrity     : %s\n", integrityStatus)
	fmt.Printf("Log dir       : %s\n", cfg.PrimaryDir)
	if cfg.SGAILEnabled {
		fmt.Printf("SGAIL sync    : enabled (%s)\n", cfg.SGAILEndpoint)
	} else {
		fmt.Printf("SGAIL sync    : disabled (opt-in only)\n")
	}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		fmt.Printf("Last event    : [%s] %s / %s (%s)\n",
			last.Level, last.Source, last.Event,
			last.Timestamp.Format(time.RFC3339))
	}
	fmt.Println("─────────────────────────────────────────")
}

// ── watchdog ─────────────────────────────────────────────────────────────────
//
// The watchdog subprocess is spawned by `witness start` to handle SIGKILL,
// which the main process cannot catch. It polls the parent PID every 2 seconds.
// If the parent disappears unexpectedly it fires the death broadcast itself.

func cmdWatchdog() {
	// Args: witness watchdog <parent-pid> <primary-dir> <machine-id> [sgail-endpoint] [sgail-token]
	if len(os.Args) < 5 {
		os.Exit(1)
	}
	ppid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		os.Exit(1)
	}
	primaryDir := os.Args[3]
	mid := os.Args[4]

	var sgailEndpoint, sgailToken string
	if len(os.Args) >= 6 {
		sgailEndpoint = os.Args[5]
	}
	if len(os.Args) >= 7 {
		sgailToken = os.Args[6]
	}

	var sgailClient *sgail.Client
	if sgailEndpoint != "" {
		sgailClient = sgail.NewClient(sgailEndpoint, sgailToken)
	}

	broadcaster := death.New(primaryDir, mid, sgailClient)

	for {
		time.Sleep(2 * time.Second)
		parent, err := os.FindProcess(ppid)
		if err != nil {
			break
		}
		if err := parent.Signal(syscall.Signal(0)); err != nil {
			break
		}
	}

	logData, _ := os.ReadFile(filepath.Join(primaryDir, "witness.log"))
	genesisData, _ := os.ReadFile(filepath.Join(primaryDir, "genesis.enc"))
	broadcaster.Fire(logData, genesisData)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func spawnWatchdog(mid, primaryDir, sgailEndpoint, sgailToken string) {
	self, err := os.Executable()
	if err != nil {
		warn("could not resolve own path for watchdog: %v", err)
		return
	}
	args := []string{
		self, "watchdog",
		strconv.Itoa(os.Getpid()),
		primaryDir,
		mid,
		sgailEndpoint,
		sgailToken,
	}
	proc, err := os.StartProcess(self, args, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil}, // detach stdio
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		warn("could not start watchdog: %v", err)
		return
	}
	_ = proc.Release()
}

// ── soul ──────────────────────────────────────────────────────────────────────

func cmdSoul() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: witness soul <sign|verify> [--dev]")
		os.Exit(1)
	}
	devMode := false
	for _, arg := range os.Args[3:] {
		if arg == "--dev" {
			devMode = true
		}
	}
	switch os.Args[2] {
	case "sign":
		s := resolveSigner(devMode, witnessDir())
		if s == nil {
			fatal("no signer available; use --dev or build with -tags piv")
		}
		if err := soul.SignSoul(soul.Path(), s); err != nil {
			fatal("soul sign: %v", err)
		}
		if err := soul.AppendAllowlist(soul.AllowlistPath(), "operator", s.PublicKey()); err != nil {
			warn("could not update allowlist: %v", err)
		}
		fmt.Printf("[witness] Soul file signed: %s\n", soul.SigPath(soul.Path()))
		fmt.Printf("[witness] Signer public key added to allowlist: %s\n", soul.AllowlistPath())
	case "verify":
		allowlist, err := soul.LoadAllowlist(soul.AllowlistPath())
		if err != nil {
			fatal("load allowlist: %v", err)
		}
		if err := soul.VerifySoulSignature(soul.Path(), allowlist); err != nil {
			fmt.Fprintf(os.Stderr, "[witness] SOUL SIGNATURE INVALID: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[witness] Soul signature OK: %s\n", soul.Path())
	default:
		fmt.Fprintf(os.Stderr, "unknown soul subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

// ── migrate ───────────────────────────────────────────────────────────────────

func cmdMigrate() {
	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun 'witness init' first.", err)
	}
	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	// Determine v1 log source — default is the same primary dir (in-place migration).
	srcDir := cfg.PrimaryDir
	if len(os.Args) >= 3 {
		srcDir = os.Args[2]
	}

	s, err := store.Open(cfg.PrimaryDir, key, nil)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer s.Close()

	result, err := migrate.FromV1Log(srcDir, key, s)
	if err != nil {
		fatal("migrate: %v", err)
	}

	fmt.Printf("[witness] Migration complete.\n")
	fmt.Printf("  Source      : %s\n", result.LogPath)
	fmt.Printf("  Imported    : %d entries\n", result.Imported)
	if result.Skipped > 0 {
		fmt.Printf("  Skipped     : %d (could not decode)\n", result.Skipped)
	}
	fmt.Printf("  Boundary    : v1_import_boundary leaf appended\n")
}

// ── signer helpers ────────────────────────────────────────────────────────────

// witnessDir returns the ~/.witness directory path.
func witnessDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witness")
}

// resolveSigner returns the active Signer based on mode.
// Returns nil if no signer is available (MAC-only mode).
func resolveSigner(devMode bool, keyDir string) signer.Signer {
	if devMode {
		s, err := signer.NewDev(keyDir)
		if err != nil {
			fatal("dev signer: %v", err)
		}
		return s
	}
	s, err := signer.NewPIV()
	if err != nil {
		warn("hardware signer unavailable: %v — tree heads will use BLAKE3-MAC only; use --dev for software signing", err)
		return nil
	}
	return s
}

// checkSoulSignature verifies the soul file's detached ed25519 signature.
// In dev mode, a missing or invalid signature is a warning, not a fatal error.
// In production mode, a missing or invalid signature halts startup.
func checkSoulSignature(soulPath string, devMode bool) {
	allowlist, err := soul.LoadAllowlist(soul.AllowlistPath())
	if err != nil {
		if devMode {
			warn("soul allowlist unavailable: %v (continuing in dev mode)", err)
			return
		}
		fmt.Fprintf(os.Stderr, "\n  ╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "  ║  SOUL SIGNATURE VERIFICATION FAILED                          ║\n")
		fmt.Fprintf(os.Stderr, "  ║  %s\n", padRight("  "+err.Error(), 61)+"║")
		fmt.Fprintf(os.Stderr, "  ║  Run: witness soul sign --dev   (to sign with dev key)       ║\n")
		fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════════════════════════╝\n\n")
		os.Exit(1)
	}
	if err := soul.VerifySoulSignature(soulPath, allowlist); err != nil {
		if devMode {
			warn("soul signature invalid: %v (continuing in dev mode)", err)
			return
		}
		fmt.Fprintf(os.Stderr, "\n  ╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stderr, "  ║  SOUL SIGNATURE VERIFICATION FAILED — DAEMON WILL NOT START  ║\n")
		fmt.Fprintf(os.Stderr, "  ║  %s\n", padRight("  "+err.Error(), 61)+"║")
		fmt.Fprintf(os.Stderr, "  ║  Run: witness soul sign   to sign the soul file.             ║\n")
		fmt.Fprintf(os.Stderr, "  ╚══════════════════════════════════════════════════════════════╝\n\n")
		os.Exit(1)
	}
	fmt.Println("[witness] Soul signature verified.")
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	if len(s) > n {
		return s[:n]
	}
	return s
}

func mustWrite(path string, data []byte) {
	if err := os.WriteFile(path, data, 0600); err != nil {
		fatal("write %s: %v", path, err)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[witness] FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func warn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[witness] WARN: "+format+"\n", args...)
}
