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
//
// Exit codes:
//
//	0 — log is intact
//	1 — tampering, truncation, or MAC failure detected
func cmdVerify() {
	mid := machid.Get()
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun 'witness init' first.", err)
	}
	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	s, err := store.Open(cfg.PrimaryDir, key, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()
	if r := s.Recovered(); r.Bytes > 0 {
		fmt.Printf("NOTE  the log ended in an interrupted write: %d byte(s) (%d uncommitted record(s)) moved to %s\n",
			r.Bytes, r.UncommittedRecords, r.QuarantineFile)
	}

	n, err := s.VerifyIntegrity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
		os.Exit(1)
	}

	head := s.Head()
	fmt.Printf("OK  leaves=%d  root=%s\n", n, head.Root)
}
