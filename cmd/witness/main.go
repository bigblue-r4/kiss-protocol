// witness — kiss-core: incorruptible local machine-state observer.
//
// The core witness handles only local concerns: soul verification, genesis
// snapshot, encrypted Merkle logging, drift detection, and transparency mirror
// push. It never initiates peer-to-peer connections, runs no UDP listeners,
// and has no remote sync client. Those functions belong to cmd/enforcer.
//
// Commands:
//
//	witness init              Take genesis snapshot and initialize the witness log.
//	witness start             Start the witness daemon (blocks until signaled).
//	witness status            Print current status.
//	witness verify            Walk the Merkle log and verify integrity.
//	witness prove <index>     Emit an inclusion proof for the leaf at index.
//	witness migrate           Import a v1 log into the v2 Merkle log (one-shot).
//	witness soul sign         Sign the soul file with the configured signer.
//	witness soul verify       Verify soul file signature against allowlist.
//	witness audit             Compare local Merkle log to transparency mirror.
//	witness watchdog <args>   Internal watchdog subprocess — do not call directly.
//	witness version           Print version.
package main

import (
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
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/migrate"
	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock"
	"github.com/bigblue-r4/kiss-protocol/internal/pipelock_bridge"
	"github.com/bigblue-r4/kiss-protocol/internal/sbh"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

const version = "3.2.2"

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
	case "watchdog":
		cmdWatchdog()
	case "version", "--version", "-v":
		fmt.Println("SGAIL Labs Harborlight witness v" + version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `SGAIL Labs Harborlight witness v%s (kiss-core)

Usage:
  witness init                    Take genesis snapshot, initialize Merkle log
  witness start [--dev]           Start the continuous witness daemon
  witness status                  Show current witness status
  witness verify                  Walk Merkle log and verify integrity
  witness prove <index>           Emit inclusion proof for leaf at index
  witness migrate [src-dir]       Import v1 log into v2 Merkle log (one-shot)
  witness soul sign [--dev]       Sign the soul file with the configured signer
  witness soul verify             Verify soul file signature against allowlist
  witness audit [--max-lag N]     Compare local Merkle log to transparency mirror
  witness version                 Print version

Peer mesh and enforcement: run 'enforcer --help'
`, version)
}

// ── init ─────────────────────────────────────────────────────────────────────

func cmdInit() {
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

	fmt.Println("[witness] Taking genesis snapshot…")
	// Fold the detected agents into the snapshot before it is hashed so the
	// genesis hash covers them — otherwise `witness start` later recomputes a
	// different hash and rejects a valid genesis as tampered.
	snap, err := genesis.Take(mid, agents)
	if err != nil {
		fatal("genesis: %v", err)
	}
	if !snap.Verify() {
		fatal("genesis: integrity check failed immediately after creation")
	}

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

	if err := os.MkdirAll(cfg.PrimaryDir, 0700); err != nil {
		fatal("create primary dir: %v", err)
	}
	mustWrite(filepath.Join(cfg.PrimaryDir, "genesis.enc"), snapEnc)

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

	plCfg := pipelock.DefaultConfig(cfg.PrimaryDir)
	if err := plCfg.WriteConfig(); err != nil {
		warn("could not write pipelock config: %v (Pipelock integration disabled)", err)
	} else {
		fmt.Printf("  Pipelock   : config written → %s\n", plCfg.ConfigFile)
	}

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

	signerInst := resolveSigner(devMode, witnessDir())
	checkSoulSignature(soul.Path(), devMode)

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

	s, err := store.Open(cfg.PrimaryDir, key, signerInst)
	if err != nil {
		fatal("open store: %v", err)
	}

	broadcaster := death.New(cfg.PrimaryDir, mid)

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

	// ── SBH forge audit bridge ─────────────────────────────────────────────
	var sbhBridge *sbh.Bridge
	if cfg.SBHAuditPath != "" {
		sbhBridge = sbh.New(cfg.SBHAuditPath, s)
		sbhBridge.Start()
		fmt.Printf("[witness] SBH forge audit tailing → %s\n", cfg.SBHAuditPath)
	}

	// ── Anomaly detector ──────────────────────────────────────────────────
	anomalyCh := make(chan anomaly.Event, 8)
	adet := anomaly.New(cfg.PrimaryDir, 10*time.Second, anomalyCh)
	adet.Run()

	spawnWatchdog(mid, cfg.PrimaryDir)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	_ = s.Append("INFO", "daemon_start", "witness", map[string]interface{}{
		"pid":          os.Getpid(),
		"genesis_hash": snap.Hash,
		"pipelock":     plCfg.AuditLogPath(),
		"sbh_enabled":  cfg.SBHAuditPath != "",
	})

	fmt.Printf("[witness] Daemon started (PID %d)\n", os.Getpid())
	fmt.Printf("[witness] Genesis: %s\n", snap.Hash)

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
	tryPushMirror()

	driftTick := time.NewTicker(time.Duration(cfg.DriftIntervalSec) * time.Second)
	defer driftTick.Stop()

	fireDeath := func(reason, detail string) {
		fmt.Printf("[witness] Death trigger: %s — writing snapshot…\n", reason)
		_ = s.Append("DEATH", reason, "witness", map[string]string{"detail": detail})
		if sbhBridge != nil {
			sbhBridge.Stop()
		}
		bridge.Stop()
		adet.Stop()
		_ = s.Close()
		logData, _ := os.ReadFile(filepath.Join(cfg.PrimaryDir, "witness.log"))
		broadcaster.Fire(logData, snapEncBytes)
		fmt.Printf("[witness] Death snapshot written.\n")
	}

	// Unused context to satisfy consistent goroutine API.
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		select {
		case a := <-anomalyCh:
			_ = s.Append("WARN", string(a.Kind), "anomaly", a)
			warn("Anomaly detected: %s — %s", a.Kind, a.Detail)
			if a.Kind == anomaly.KindStorage {
				fireDeath(string(a.Kind), a.Detail)
				return
			}

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

		case sig := <-sigCh:
			fireDeath("signal_received", sig.String())
			return
		}
	}
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

	snapEncBytes, _ := os.ReadFile(filepath.Join(cfg.PrimaryDir, "genesis.enc"))
	genesisStatus := "unknown"
	if len(snapEncBytes) > 0 {
		if snapBytes, err := encrypt.Open(snapEncBytes, key); err == nil {
			if snap, err := genesis.Load(snapBytes); err == nil {
				if snap.Clean() {
					genesisStatus = "CLEAN"
				} else {
					genesisStatus = fmt.Sprintf("COMPROMISED (%d agents present at genesis)", len(snap.AgentsAtGenesis))
				}
			}
		}
	}

	s, err := store.Open(cfg.PrimaryDir, key, nil)
	var treeSize uint64
	var treeRoot string
	var prevRoot string
	var integrityStatus string
	if err != nil {
		integrityStatus = "FAIL: " + err.Error()
	} else {
		head := s.Head()
		treeSize = head.Size
		treeRoot = head.Root
		prevRoot = head.PrevRoot
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
	fmt.Printf("Prev root     : %s\n", prevRoot)
	fmt.Printf("Integrity     : %s\n", integrityStatus)
	fmt.Printf("Log dir       : %s\n", cfg.PrimaryDir)
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		fmt.Printf("Last event    : [%s] %s / %s (%s)\n",
			last.Level, last.Source, last.Event,
			last.Timestamp.Format(time.RFC3339))
	}
	fmt.Println("─────────────────────────────────────────")
}

// ── watchdog ─────────────────────────────────────────────────────────────────

func cmdWatchdog() {
	// Args: witness watchdog <parent-pid> <primary-dir> <machine-id>
	if len(os.Args) < 5 {
		os.Exit(1)
	}
	ppid, err := strconv.Atoi(os.Args[2])
	if err != nil {
		os.Exit(1)
	}
	primaryDir := os.Args[3]
	mid := os.Args[4]

	broadcaster := death.New(primaryDir, mid)

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

// ── helpers ───────────────────────────────────────────────────────────────────

func witnessDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witness")
}

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

func spawnWatchdog(mid, primaryDir string) {
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
	}
	proc, err := os.StartProcess(self, args, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		warn("could not start watchdog: %v", err)
		return
	}
	_ = proc.Release()
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
