package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

const proveConsistencyUsage = "usage: witness prove-consistency --old-size N [--leaves FILE [--new-size N]] [--pubkey HEX]..."
const verifyConsistencyUsage = "usage: witness verify-consistency --old HEADFILE --new HEADFILE --proof FILE --pubkey HEX"

// cmdProveConsistency writes a consistency proof (JSON) from an earlier tree
// size to the current signed head. With --leaves it works from a mirror leaf
// feed instead of the local log, and needs no machine key or log access.
func cmdProveConsistency(args []string, stdout, stderr io.Writer) int {
	pins, rest, err := parseVerifierPins(args)
	if err != nil {
		fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
		return 2
	}
	fs := flag.NewFlagSet("prove-consistency", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oldSize := fs.Uint64("old-size", 0, "tree size of the earlier head")
	leavesPath := fs.String("leaves", "", "mirror leaf feed (consecutive 32-byte leaf hashes) instead of the local log")
	newSize := fs.Uint64("new-size", 0, "with --leaves: tree size of the newer head (default: the whole feed)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *oldSize == 0 || fs.NArg() != 0 || (*newSize != 0 && *leavesPath == "") {
		fmt.Fprintln(stderr, proveConsistencyUsage)
		return 2
	}

	var d store.ConsistencyDoc
	if *leavesPath != "" {
		f, err := os.Open(*leavesPath)
		if err != nil {
			fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
			return 2
		}
		leaves, err := mirror.ReadLeaves(f)
		_ = f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
			return 2
		}
		if *newSize != 0 {
			if *newSize > uint64(len(leaves)) {
				fmt.Fprintf(stderr, "prove-consistency: --new-size %d exceeds the feed (%d leaves)\n", *newSize, len(leaves))
				return 2
			}
			leaves = leaves[:*newSize]
		}
		d, err = store.ConsistencyFromLeaves(leaves, *oldSize)
		if err != nil {
			fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
			return 2
		}
	} else {
		if len(pins) == 0 {
			fmt.Fprintln(stderr, "NOTE  signer not pinned: pass --pubkey to check who signed this log")
		}
		cfg, err := config.Load(config.Path())
		if err != nil {
			fmt.Fprintf(stderr, "prove-consistency: load config: %v\n\nRun 'witness init' first.\n", err)
			return 2
		}
		key, err := encrypt.DeriveKey(machid.Get())
		if err != nil {
			fmt.Fprintf(stderr, "prove-consistency: derive key: %v\n", err)
			return 2
		}
		s, err := store.OpenPinned(cfg.PrimaryDir, key, pins)
		if err != nil {
			fmt.Fprintf(stderr, "[witness] INTEGRITY FAILURE: %v\n", err)
			return 1
		}
		defer s.Close()
		if d, err = s.ConsistencyProof(*oldSize); err != nil {
			fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
			return 2
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		fmt.Fprintf(stderr, "prove-consistency: %v\n", err)
		return 2
	}
	return 0
}

// cmdVerifyConsistency checks, off-host and with only public material, that a
// newer signed head extends an older one. Exit 0: consistent; 1: the log was
// rewritten, truncated or rolled back, or a head is not validly signed;
// 2: usage or unreadable input.
func cmdVerifyConsistency(args []string, stdout, stderr io.Writer) int {
	pins, rest, err := parseVerifierPins(args)
	if err != nil {
		fmt.Fprintf(stderr, "verify-consistency: %v\n", err)
		return 2
	}
	fs := flag.NewFlagSet("verify-consistency", flag.ContinueOnError)
	fs.SetOutput(stderr)
	oldPath := fs.String("old", "", "earlier signed tree head (tree-head.json)")
	newPath := fs.String("new", "", "newer signed tree head (tree-head.json)")
	proofPath := fs.String("proof", "", "consistency proof from 'witness prove-consistency'")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *oldPath == "" || *newPath == "" || *proofPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, verifyConsistencyUsage)
		return 2
	}
	if len(pins) == 0 {
		fmt.Fprintln(stderr, "verify-consistency: --pubkey is required: an unpinned head proves nothing")
		return 2
	}
	var oldHead, newHead store.TreeHead
	var d store.ConsistencyDoc
	for _, in := range []struct {
		path string
		v    any
	}{{*oldPath, &oldHead}, {*newPath, &newHead}, {*proofPath, &d}} {
		b, err := os.ReadFile(in.path)
		if err != nil {
			fmt.Fprintf(stderr, "verify-consistency: %v\n", err)
			return 2
		}
		if err := json.Unmarshal(b, in.v); err != nil {
			fmt.Fprintf(stderr, "verify-consistency: %s: %v\n", in.path, err)
			return 2
		}
	}
	if err := store.VerifyConsistency(oldHead, newHead, d, pins); err != nil {
		fmt.Fprintf(stderr, "verify-consistency: FAIL: %v\n", err)
		if errors.Is(err, store.ErrInconsistent) {
			fmt.Fprintln(stderr, "[witness] INTEGRITY FAILURE: the newer head does not extend the older one")
		}
		return 1
	}
	fmt.Fprintf(stdout, "verify-consistency: OK old_size=%d new_size=%d new_root=%s\n", oldHead.Size, newHead.Size, newHead.Root)
	return 0
}
