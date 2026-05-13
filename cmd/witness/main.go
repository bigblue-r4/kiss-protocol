// witness — continuous machine-state witness client built on Pipelock.
//
// Commands:
//
//	witness init              Take genesis snapshot and initialize the witness log.
//	witness start             Start the witness daemon (blocks until signaled).
//	witness status            Print current status.
//	witness enable-sync       Enable opt-in SGAIL remote sync.
//	witness watchdog <args>   Internal watchdog subprocess — do not call directly.
//	witness version           Print version.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/anomaly"
	"github.com/bigblue-r4/kiss-protocol/internal/backup"
	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/death"
	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/genesis"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/sgail"
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
  witness init             Take genesis snapshot, initialize three-tier log storage
  witness start            Start the continuous witness daemon
  witness status           Show current witness status
  witness enable-sync      Configure opt-in SGAIL Labs remote sync
  witness version          Print version

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
		fmt.Println("  ║  The installer should have placed this file.                 ║")
		fmt.Println("  ║  If it is missing, re-run the USB installer.                 ║")
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

	// ── Store genesis in all three locations ──────────────────────────────

	// Primary
	if err := os.MkdirAll(cfg.PrimaryDir, 0700); err != nil {
		fatal("create primary dir: %v", err)
	}
	mustWrite(filepath.Join(cfg.PrimaryDir, "genesis.enc"), snapEnc)

	// Secondary
	if err := backup.WriteSecondary("genesis.enc", snapEnc); err != nil {
		warn("secondary backup: %v", err)
	}

	// Tertiary (path derived from machine identity — never stored in config)
	if err := backup.WriteTertiary(mid, "genesis.enc", snapEnc); err != nil {
		warn("tertiary backup: %v", err)
	}

	// ── Open the primary log and write genesis entry (entry zero) ─────────
	s, err := store.Open(cfg.PrimaryDir, key)
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
	fmt.Printf("  Primary    : %s\n", cfg.PrimaryDir)
	fmt.Printf("  Secondary  : %s\n", backup.SecondaryDir())
	fmt.Printf("  Tertiary   : [derived from machine identity — not stored]\n")
	fmt.Printf("\nNow install your AI agents, then run: witness start\n")
}

// ── start ─────────────────────────────────────────────────────────────────────

func cmdStart() {
	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v", err)
	}

	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

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

	// Open primary log.
	s, err := store.Open(cfg.PrimaryDir, key)
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

	// Build death broadcaster.
	tertiaryDir := backup.TertiaryDir(mid)
	_ = os.MkdirAll(tertiaryDir, 0700)
	broadcaster := death.New(
		cfg.PrimaryDir,
		backup.SecondaryDir(),
		tertiaryDir,
		mid,
		sgailClient,
	)

	// ── Pipelock integration ───────────────────────────────────────────────
	plCfg := pipelock.DefaultConfig(cfg.PrimaryDir)
	plRunner := pipelock.NewRunner(plCfg)
	plEvents := make(chan pipelock.AuditEvent, 256)
	plTailer := pipelock.NewTailer(plCfg.AuditLogPath(), plEvents)

	if err := plRunner.Start(); err != nil {
		warn("Pipelock unavailable: %v (agent events will not be forwarded)", err)
	} else {
		fmt.Printf("[witness] Pipelock proxy running → %s\n", plRunner.ProxyAddr())
		fmt.Printf("[witness] Set HTTPS_PROXY=%s HTTP_PROXY=%s in your agent environment.\n",
			plRunner.ProxyAddr(), plRunner.ProxyAddr())
		go plTailer.Run()
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

	driftTick := time.NewTicker(time.Duration(cfg.DriftIntervalSec) * time.Second)
	backupTick := time.NewTicker(5 * time.Minute)
	syncTick := time.NewTicker(time.Duration(cfg.SyncIntervalSec) * time.Second)
	defer driftTick.Stop()
	defer backupTick.Stop()
	defer syncTick.Stop()

	// fireDeath tears everything down and broadcasts, then returns.
	fireDeath := func(reason, detail string) {
		fmt.Printf("[witness] Death trigger: %s — broadcasting…\n", reason)
		_ = s.Append("DEATH", reason, "witness", map[string]string{"detail": detail})
		plTailer.Stop()
		plRunner.Stop()
		adet.Stop()
		_ = s.Close()
		logData, _ := os.ReadFile(filepath.Join(cfg.PrimaryDir, "witness.log"))
		broadcaster.Fire(logData, snapEncBytes)
		fmt.Printf("[witness] Death broadcast complete.\n")
	}

	for {
		select {

		// ── Pipelock audit events ──────────────────────────────────────────
		case evt := <-plEvents:
			level := strings.ToUpper(evt.Level())
			if level == "DEBUG" || level == "TRACE" {
				level = "INFO"
			}
			_ = s.Append(level, evt.EventName(), "pipelock", evt)

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

		// ── Periodic backup mirror ─────────────────────────────────────────
		case <-backupTick.C:
			mirrorToBackups(mid, cfg.PrimaryDir)

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

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("Machine ID    : %s\n", mid)
	fmt.Printf("Genesis       : %s\n", genesisStatus)
	fmt.Printf("Log entries   : %d\n", len(entries))
	fmt.Printf("Drift events  : %d\n", driftCount)
	fmt.Printf("Primary       : %s\n", cfg.PrimaryDir)
	fmt.Printf("Secondary     : %s\n", backup.SecondaryDir())
	fmt.Printf("Tertiary      : [derived — not displayed]\n")
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

	tertiaryDir := backup.TertiaryDir(mid)
	broadcaster := death.New(
		primaryDir,
		backup.SecondaryDir(),
		tertiaryDir,
		mid,
		sgailClient,
	)

	for {
		time.Sleep(2 * time.Second)
		parent, err := os.FindProcess(ppid)
		if err != nil {
			break // parent gone
		}
		// On Unix, FindProcess never fails; probe with signal 0.
		if err := parent.Signal(syscall.Signal(0)); err != nil {
			break // parent gone
		}
	}

	// Parent is gone — fire the death broadcast from the watchdog.
	logData, _ := os.ReadFile(filepath.Join(primaryDir, "witness.log"))
	genesisData, _ := os.ReadFile(filepath.Join(primaryDir, "genesis.enc"))
	broadcaster.Fire(logData, genesisData)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mirrorToBackups(mid, primaryDir string) {
	logData, err := os.ReadFile(filepath.Join(primaryDir, "witness.log"))
	if err != nil {
		return
	}
	genesisData, _ := os.ReadFile(filepath.Join(primaryDir, "genesis.enc"))

	_ = backup.WriteSecondary("witness.log", logData)
	_ = backup.WriteSecondary("genesis.enc", genesisData)
	_ = backup.WriteTertiary(mid, "witness.log", logData)
	_ = backup.WriteTertiary(mid, "genesis.enc", genesisData)
}

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
