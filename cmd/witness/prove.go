package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// cmdProve emits an inclusion proof for the leaf at the given 0-based index.
// A third party can verify the proof using only the tree head and the leaf hash.
//
// Usage: witness prove <index>
func cmdProve() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: witness prove <index>")
		os.Exit(1)
	}
	index, err := strconv.ParseUint(os.Args[2], 10, 64)
	if err != nil {
		fatal("invalid index %q: %v", os.Args[2], err)
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

	s, err := store.Open(cfg.PrimaryDir, key, nil)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer s.Close()

	proof, entry, err := s.InclusionProof(index)
	if err != nil {
		fatal("generate proof: %v", err)
	}

	head := s.Head()
	rootBytes, _ := hex.DecodeString(head.Root)
	var root [32]byte
	copy(root[:], rootBytes)

	entryBytes, _ := json.Marshal(entry)
	lh := merkle.HashLeaf(entryBytes)

	if err := merkle.Verify(root, lh, proof); err != nil {
		fatal("self-check failed: %v", err)
	}

	out := struct {
		TreeSize  uint64       `json:"tree_size"`
		TreeRoot  string       `json:"tree_root"`
		LeafIndex uint64       `json:"leaf_index"`
		LeafHash  string       `json:"leaf_hash"`
		Proof     merkle.Proof `json:"proof"`
		Entry     store.Entry  `json:"entry"`
	}{
		TreeSize:  head.Size,
		TreeRoot:  head.Root,
		LeafIndex: index,
		LeafHash:  hex.EncodeToString(lh[:]),
		Proof:     proof,
		Entry:     entry,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
