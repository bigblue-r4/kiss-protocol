// witness-pd — SGAIL Labs Harborlight Firewall, Police Department Edition.
//
// Tamper-evident chain-of-custody evidence management for law enforcement.
// Separate release path; shares the core witness/store/encrypt stack.
//
// Usage:
//
//	witness-pd init [--department NAME] [--node NODE_ID]
//	witness-pd status [--json]
//	witness-pd intake  --case CASE --cat CATEGORY --desc DESC --actor ACTOR [--node NODE]
//	witness-pd transfer --item ID --from NODE --to NODE --actor ACTOR [--notes TEXT]
//	witness-pd hold set --item ID --reason TEXT --actor ACTOR
//	witness-pd hold release --item ID --actor ACTOR [--notes TEXT]
//	witness-pd export --case CASE --actor ACTOR [--sign]
//	witness-pd keygen
//	witness-pd version
package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/pd/evidence"
	pdexport "github.com/bigblue-r4/kiss-protocol/internal/pd/export"
	"github.com/bigblue-r4/kiss-protocol/internal/pd/roles"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
)

const version = "2.0.0"

// Config is persisted to ~/.witness-pd/config.json.
type Config struct {
	Department    string `json:"department"`
	NodeID        string `json:"node_id"`
	Port          int    `json:"port"`
	SigningKeyPub string `json:"signing_key_pub"`
	// SigningKeyPriv is never stored in config; pass via WITNESS_PD_SIGN_KEY env var.
}

// ── entry point ──────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	switch cmd {
	case "init":
		runInit()
	case "status":
		runStatus()
	case "intake":
		runIntake()
	case "transfer":
		runTransfer()
	case "hold":
		runHold()
	case "export":
		runExport()
	case "keygen":
		runKeygen()
	case "version", "--version", "-v":
		fmt.Printf("witness-pd %s (SGAIL Labs Harborlight PD Edition)\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

// ── commands ─────────────────────────────────────────────────────────────────

func runInit() {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dept := fs.String("department", "", "Department name (e.g. 'Honolulu PD')")
	nodeID := fs.String("node", "node-001", "Node identifier for this installation")
	_ = fs.Parse(os.Args[2:])

	dir := pdDir()
	primaryDir := filepath.Join(dir, "primary")

	if _, err := os.Stat(primaryDir); err == nil {
		fatal("already initialized at %s — remove that directory to reinitialize", dir)
	}

	// Install soul file.
	soulDst := filepath.Join(dir, "soul.toml")
	if err := installSoul(soulDst); err != nil {
		fatal("install soul: %v", err)
	}

	// Load and verify soul.
	s, err := soul.Load(soulDst)
	if err != nil {
		fatal("soul verification failed: %v\nDo not proceed.", err)
	}
	info("soul verified: %s v%s", s.Identity.AgentName, s.Identity.AgentVersion)

	// Derive key and open store.
	key, err := derivePDKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	pd, err := evidence.Open(primaryDir, key)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer pd.Close()

	if err := pd.AppendSystem("INFO", "pd/init", "witness-pd initialized"); err != nil {
		fatal("write genesis event: %v", err)
	}

	// Write config.
	cfg := Config{
		Department: *dept,
		NodeID:     *nodeID,
		Port:       8890,
	}
	if err := saveConfig(dir, cfg); err != nil {
		fatal("save config: %v", err)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║  SGAIL Labs Harborlight PD Edition initialized.           ║")
	fmt.Println("║                                                           ║")
	fmt.Printf("║  Node     : %-46s║\n", *nodeID)
	fmt.Printf("║  Data dir : %-46s║\n", dir)
	fmt.Println("║                                                           ║")
	fmt.Println("║  witness-pd status    — view current state                ║")
	fmt.Println("║  witness-pd status --json — machine-readable status       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
}

func runStatus() {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Output status as JSON")
	_ = fs.Parse(os.Args[2:])

	dir := pdDir()
	cfg, err := loadConfig(dir)
	if err != nil {
		fatal("not initialized — run: witness-pd init")
	}

	key, err := derivePDKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}

	soulPath := filepath.Join(dir, "soul.toml")
	soulStatus := "ok"
	if _, err := soul.Load(soulPath); err != nil {
		soulStatus = "failed"
	}

	pd, err := evidence.Open(filepath.Join(dir, "primary"), key)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer pd.Close()

	items := pd.GetItems("")
	holdCount := 0
	for _, it := range items {
		if it.LegalHold {
			holdCount++
		}
	}

	events, _ := pd.GetAllEvents()
	lastEvent := ""
	var lastEventAt *time.Time
	if len(events) > 0 {
		e := events[len(events)-1]
		lastEvent = e.Event
		t := e.Timestamp
		lastEventAt = &t
	}

	if *asJSON {
		out := map[string]interface{}{
			"node_id":     cfg.NodeID,
			"department":  cfg.Department,
			"version":     version,
			"soul":        soulStatus,
			"item_count":  len(items),
			"hold_count":  holdCount,
			"log_entries": len(events),
		}
		if lastEvent != "" && lastEventAt != nil {
			out["last_event"] = lastEvent
			out["last_event_at"] = lastEventAt.UTC().Format(time.RFC3339)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return
	}

	fmt.Println("─────────────────────────────────────────────────────")
	fmt.Printf("Witness PD Edition   v%s\n", version)
	fmt.Printf("Node ID      : %s\n", cfg.NodeID)
	fmt.Printf("Department   : %s\n", cfg.Department)
	fmt.Printf("Soul         : %s (%s)\n", soulPath, soulStatus)
	fmt.Printf("Items        : %d total / %d on legal hold\n", len(items), holdCount)
	fmt.Printf("Log entries  : %d\n", len(events))
	if lastEvent != "" && lastEventAt != nil {
		fmt.Printf("Last event   : [%s] %s\n", lastEventAt.Format(time.RFC3339), lastEvent)
	}
	fmt.Println("─────────────────────────────────────────────────────")
}

func runIntake() {
	fs := flag.NewFlagSet("intake", flag.ExitOnError)
	caseNum := fs.String("case", "", "Case number (required)")
	cat := fs.String("cat", "other", "Category: narcotics, firearms, digital_media, documents, other")
	desc := fs.String("desc", "", "Description (required)")
	actor := fs.String("actor", "", "Officer name (required)")
	node := fs.String("node", "", "Current node/location")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" || *desc == "" || *actor == "" {
		fmt.Fprintln(os.Stderr, "usage: witness-pd intake --case CASE --desc DESC --actor ACTOR [--cat CATEGORY] [--node NODE]")
		os.Exit(1)
	}

	pd, key := mustOpenStore()
	defer pd.Close()
	_ = key

	item := &evidence.Item{
		CaseNumber:  *caseNum,
		Description: *desc,
		Category:    *cat,
		CurrentNode: *node,
	}
	if err := pd.RecordIntake(item, *actor); err != nil {
		fatal("intake: %v", err)
	}
	fmt.Printf("Intake recorded: %s\n", item.ID)
	fmt.Printf("  Case   : %s\n", item.CaseNumber)
	fmt.Printf("  Desc   : %s\n", item.Description)
	fmt.Printf("  Actor  : %s\n", *actor)
}

func runTransfer() {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	itemID := fs.String("item", "", "Item ID (required)")
	from := fs.String("from", "", "From node (required)")
	to := fs.String("to", "", "To node (required)")
	actor := fs.String("actor", "", "Actor name (required)")
	notes := fs.String("notes", "", "Transfer notes")
	_ = fs.Parse(os.Args[2:])

	if *itemID == "" || *from == "" || *to == "" || *actor == "" {
		fmt.Fprintln(os.Stderr, "usage: witness-pd transfer --item ID --from NODE --to NODE --actor ACTOR [--notes TEXT]")
		os.Exit(1)
	}

	pd, _ := mustOpenStore()
	defer pd.Close()

	if err := pd.RecordTransfer(*itemID, *actor, *from, *to, *notes); err != nil {
		fatal("transfer: %v", err)
	}
	fmt.Printf("Transfer recorded: %s → %s (%s)\n", *from, *to, *itemID)
}

func runHold() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: witness-pd hold <set|release> [flags]")
		os.Exit(1)
	}
	sub := os.Args[2]
	switch sub {
	case "set":
		fs := flag.NewFlagSet("hold set", flag.ExitOnError)
		itemID := fs.String("item", "", "Item ID (required)")
		reason := fs.String("reason", "", "Hold reason (required)")
		actor := fs.String("actor", "", "Actor name (required)")
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" || *reason == "" || *actor == "" {
			fmt.Fprintln(os.Stderr, "usage: witness-pd hold set --item ID --reason TEXT --actor ACTOR")
			os.Exit(1)
		}
		pd, _ := mustOpenStore()
		defer pd.Close()
		if err := pd.SetLegalHold(*itemID, *actor, *reason); err != nil {
			fatal("hold set: %v", err)
		}
		fmt.Printf("Legal hold set: %s\n", *itemID)

	case "release":
		fs := flag.NewFlagSet("hold release", flag.ExitOnError)
		itemID := fs.String("item", "", "Item ID (required)")
		actor := fs.String("actor", "", "Actor name (required)")
		notes := fs.String("notes", "", "Release notes")
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" || *actor == "" {
			fmt.Fprintln(os.Stderr, "usage: witness-pd hold release --item ID --actor ACTOR [--notes TEXT]")
			os.Exit(1)
		}
		pd, _ := mustOpenStore()
		defer pd.Close()
		if err := pd.ReleaseLegalHold(*itemID, *actor, *notes); err != nil {
			fatal("hold release: %v", err)
		}
		fmt.Printf("Legal hold released: %s\n", *itemID)

	default:
		fmt.Fprintf(os.Stderr, "unknown hold subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runExport() {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	caseNum := fs.String("case", "", "Case number (required)")
	actor := fs.String("actor", "", "Actor name (required)")
	sign := fs.Bool("sign", false, "Sign bundle with WITNESS_PD_SIGN_KEY")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" || *actor == "" {
		fmt.Fprintln(os.Stderr, "usage: witness-pd export --case CASE --actor ACTOR [--sign]")
		os.Exit(1)
	}

	dir := pdDir()
	cfg, _ := loadConfig(dir)
	pd, _ := mustOpenStore()
	defer pd.Close()

	entries, err := pd.GetAllEvents()
	if err != nil {
		fatal("read events: %v", err)
	}

	bundle, err := pdexport.Generate(entries, *caseNum, cfg.Department, cfg.NodeID)
	if err != nil {
		fatal("generate bundle: %v", err)
	}

	if *sign {
		privKey := os.Getenv("WITNESS_PD_SIGN_KEY")
		if privKey == "" {
			fatal("--sign requires WITNESS_PD_SIGN_KEY env var (private key hex)")
		}
		if err := pdexport.Sign(bundle, privKey); err != nil {
			fatal("sign bundle: %v", err)
		}
	}

	exportDir := filepath.Join(dir, "exports")
	outPath := filepath.Join(exportDir, bundle.BundleID+".ndjson")
	if err := pdexport.WriteNDJSON(bundle, outPath); err != nil {
		fatal("write bundle: %v", err)
	}

	// Log the export event for each item in the case.
	items := pd.GetItems(*caseNum)
	for _, item := range items {
		_ = pd.RecordExport(item.ID, *actor, bundle.BundleID)
	}

	fmt.Printf("Export bundle: %s\n", bundle.BundleID)
	fmt.Printf("  Case        : %s\n", *caseNum)
	fmt.Printf("  Entries     : %d\n", bundle.EntryCount)
	fmt.Printf("  SHA-256     : %s\n", bundle.SHA256Chain)
	if bundle.Signature != "" {
		fmt.Printf("  Signed      : yes\n")
	}
	fmt.Printf("  Output      : %s\n", outPath)
}

func runKeygen() {
	pub, priv, err := pdexport.GenerateKeyPair()
	if err != nil {
		fatal("keygen: %v", err)
	}
	fmt.Println("Ed25519 signing key pair generated.")
	fmt.Println()
	fmt.Printf("Public key  (store in config): %s\n", pub)
	fmt.Println()
	fmt.Printf("Private key (keep secret, use as WITNESS_PD_SIGN_KEY):\n%s\n", priv)
	fmt.Println()
	fmt.Println("Never store the private key in config.json.")
	fmt.Println("Pass it as: export WITNESS_PD_SIGN_KEY=<private_key_hex>")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustOpenStore() (*evidence.PDStore, []byte) {
	dir := pdDir()
	if _, err := loadConfig(dir); err != nil {
		fatal("not initialized — run: witness-pd init")
	}
	key, err := derivePDKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	pd, err := evidence.Open(filepath.Join(dir, "primary"), key)
	if err != nil {
		fatal("open store: %v", err)
	}
	return pd, key
}

func pdDir() string {
	if d := os.Getenv("WITNESS_PD_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".witness-pd")
}

func derivePDKey(machineID string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(machineID),
		[]byte("witness-pd-kdf-salt-2026"),
		[]byte("witness-pd-aes256-gcm-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func installSoul(dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil // already present
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	// Try bundled payload first.
	exe, _ := os.Executable()
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "../../payload/pd/default-pd-soul.toml"),
		"payload/pd/default-pd-soul.toml",
	}
	for _, src := range candidates {
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		return os.WriteFile(dst, data, 0400)
	}
	return fmt.Errorf("default PD soul file not found — clone the repo and run init from it")
}

func loadConfig(dir string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

func saveConfig(dir string, cfg Config) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), data, 0600)
}

func info(format string, args ...interface{}) {
	fmt.Printf("[witness-pd] "+format+"\n", args...)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[witness-pd] FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `witness-pd %s — SGAIL Labs Harborlight PD Edition

Commands:
  init       [--department NAME] [--node ID]   Initialize PD store
  status     [--json]                           Show system status
  intake     --case C --desc D --actor A        Record evidence intake
  transfer   --item ID --from N --to N --actor  Transfer custody
  hold set   --item ID --reason R --actor A     Set legal hold
  hold release --item ID --actor A              Release legal hold
  export     --case C --actor A [--sign]        Generate court export bundle
  keygen                                        Generate Ed25519 signing key pair
  version                                       Show version

Environment:
  WITNESS_PD_SIGN_KEY Ed25519 private key hex for signing exports
  WITNESS_PD_DIR      Override data directory (default: ~/.witness-pd)

Dashboard replacement: witness-pd status --json

`, version)
	// Silence unused import warning at compile time — roles is used for future expansion.
	_ = roles.Can
}
