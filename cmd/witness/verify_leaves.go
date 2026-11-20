package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
)

// cmdVerifyLeaves checks that the first --size leaves of a leaf feed (a copy
// of a file mirror's leaves.bin) produce --root. Run off-host by a mirror
// puller that keeps its own copy of the feed: it appends new leaves to that
// copy and checks each signed head (whose signature it verifies itself)
// against it. Needs no key and no access to the log.
//
// Exit: 0 match, 1 mismatch (history differs from the leaves held), 2 usage/IO.
func cmdVerifyLeaves(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-leaves", flag.ContinueOnError)
	fs.SetOutput(stderr)
	leavesPath := fs.String("leaves", "", "leaf feed file (consecutive 32-byte leaf hashes)")
	size := fs.Uint64("size", 0, "tree size from the signed head")
	rootHex := fs.String("root", "", "hex Merkle root from the signed head")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *leavesPath == "" || *rootHex == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: witness verify-leaves --leaves FILE --size N --root HEX")
		return 2
	}
	raw, err := hex.DecodeString(*rootHex)
	if err != nil || len(raw) != 32 {
		fmt.Fprintln(stderr, "verify-leaves: --root must be 64 hex characters")
		return 2
	}
	var root [32]byte
	copy(root[:], raw)
	f, err := os.Open(*leavesPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify-leaves: %v\n", err)
		return 2
	}
	defer f.Close()
	leaves, err := mirror.ReadLeaves(f)
	if err != nil {
		fmt.Fprintf(stderr, "verify-leaves: %v\n", err)
		return 2
	}
	if err := mirror.VerifyLeafRoot(leaves, *size, root); err != nil {
		fmt.Fprintf(stderr, "verify-leaves: FAIL size=%d: %v\n", *size, err)
		if errors.Is(err, mirror.ErrLeafRootMismatch) {
			return 1
		}
		return 2
	}
	fmt.Fprintf(stdout, "verify-leaves: OK size=%d root=%s\n", *size, *rootHex)
	return 0
}
