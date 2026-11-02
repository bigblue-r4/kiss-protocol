package main

import (
	"fmt"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// cmdVerify walks the entire Merkle log and reports the first inconsistency.
// It only reads (store.OpenPinned), so it is safe while the daemon runs.
//
// Exit codes:
//
//	0 — log is intact
//	1 — tampering, truncation, or MAC failure detected
func cmdVerify() {
	pins, args := verifierPins(os.Args[2:])
	if len(args) != 0 {
		fatal("usage: witness verify [--pubkey HEX] [--pubkey-file PATH]")
	}
	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun 'witness init' first.", err)
	}
	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	s, err := store.OpenPinned(cfg.PrimaryDir, key, pins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()
	if u := s.Uncovered(); u.Bytes > 0 {
		fmt.Printf("NOTE  %d record(s), %d byte(s) after the signed head were not checked: written since the head was read, or an interrupted write (the witness moves that aside when it next starts)\n",
			u.Records, u.Bytes)
	}

	n, err := s.VerifyIntegrity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}

	head := s.Head()
	fmt.Printf("OK  leaves=%d  root=%s\n", n, head.Root)
}
