package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// cmdExport writes a self-verifying copy of the log: the signed head, every
// leaf hash, and the decrypted records matching the filter. It only reads the
// log, so it is safe while the daemon runs. With --pubkey it checks its own
// output before writing it.
//
// Usage: witness export [--since RFC3339] [--until RFC3339] [--source S]... [--out FILE] [--pubkey HEX]
func cmdExport() {
	pins, args := parseExportPins(os.Args[2:])
	var f store.Filter
	out := ""
	for i := 0; i < len(args); i++ {
		val := func() string {
			if i+1 >= len(args) {
				fatal("%s requires a value", args[i])
			}
			i++
			return args[i]
		}
		switch args[i] {
		case "--since", "--until":
			name := args[i]
			t, err := time.Parse(time.RFC3339Nano, val())
			if err != nil {
				fatal("%s: %v", name, err)
			}
			if name == "--since" {
				f.Since = t
			} else {
				f.Until = t
			}
		case "--source":
			f.Sources = append(f.Sources, val())
		case "--out":
			out = val()
		default:
			fatal("usage: witness export [--since RFC3339] [--until RFC3339] [--source S]... [--out FILE] [--pubkey HEX]")
		}
	}

	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun 'witness init' first.", err)
	}
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	x, err := store.ExportDir(cfg.PrimaryDir, key, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] EXPORT FAILED: %v\n", err)
		os.Exit(1)
	}
	if len(pins) > 0 {
		if _, err := store.VerifyExport(x, pins, nil); err != nil {
			fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
			os.Exit(1)
		}
	}
	data, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		fatal("encode: %v", err)
	}
	data = append(data, '\n')
	if out == "" {
		_, _ = os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(out, data, 0600); err != nil {
		fatal("write %s: %v", out, err)
	}
	fmt.Fprintf(os.Stderr, "exported %d of %d records, head size %d root %s → %s\n",
		len(x.Entries), len(x.LeafHashes), x.Head.Size, x.Head.Root, out)
}

// cmdVerifyExport checks an export with only public data, on any machine.
//
// Exit codes: 0 intact; 1 tampering, truncation, rewrite or wrong signer.
func cmdVerifyExport() {
	pins, args := parseExportPins(os.Args[2:])
	var file string
	var priors []store.TreeHead
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--prior" && i+1 < len(args):
			i++
			b, err := os.ReadFile(args[i])
			if err != nil {
				fatal("--prior: %v", err)
			}
			var h store.TreeHead
			if err := json.Unmarshal(b, &h); err != nil {
				fatal("--prior %s: %v", args[i], err)
			}
			priors = append(priors, h)
		case file == "" && len(args[i]) > 0 && args[i][0] != '-':
			file = args[i]
		default:
			fatal("usage: witness verify-export FILE --pubkey HEX [--prior HEADFILE]...")
		}
	}
	if file == "" {
		fatal("usage: witness verify-export FILE --pubkey HEX [--prior HEADFILE]...")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fatal("%v", err)
	}
	x, err := store.ReadExport(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}
	r, err := store.VerifyExport(x, pins, priors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK  leaves=%d  root=%s  entries_checked=%d  prior_heads_ok=%d\n", r.Size, r.Root, r.EntriesSeen, r.PriorsOK)
}

func parseExportPins(args []string) ([]ed25519.PublicKey, []string) {
	pins, rest, err := parseVerifierPins(args)
	if err != nil {
		fatal("%v", err)
	}
	return pins, rest
}
