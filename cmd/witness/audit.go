package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// cmdAudit fetches the transparency mirror's tree head and compares it to the
// local Merkle log.
//
// Exit codes:
//
//	0 — local and mirror are consistent (or mirror is behind but not ahead)
//	1 — mirror disagrees: sizes match but roots differ, or mirror claims a
//	    larger log than local — investigate for possible tampering
//	2 — mirror unreachable, misconfigured, or returned unparseable data
func cmdAudit() {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v", err)
	}
	if cfg.MirrorURL == "" {
		fatal("no mirror_url configured.\n\nSet mirror_url in %s and restart.", config.Path())
	}

	m, err := mirror.Open(cfg.MirrorURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] FAIL  mirror open: %v\n", err)
		os.Exit(2)
	}

	mid := machid.Get()
	key, err := encrypt.DeriveKey(mid)
	if err != nil {
		fatal("derive key: %v", err)
	}

	s, err := store.Open(cfg.PrimaryDir, key, nil)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer s.Close()
	local := s.Head()

	raw, err := m.Fetch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[witness] FAIL  mirror unreachable: %v\n", err)
		os.Exit(2)
	}

	var remote store.TreeHead
	if err := json.Unmarshal(raw, &remote); err != nil {
		fmt.Fprintf(os.Stderr, "[witness] FAIL  mirror response unparseable: %v\n", err)
		os.Exit(2)
	}

	switch {
	case remote.Size > local.Size:
		// Mirror claims more entries than local — suspicious.
		fmt.Fprintf(os.Stderr,
			"[witness] FAIL  mirror disagrees: mirror claims %d leaves, local has %d\n",
			remote.Size, local.Size)
		os.Exit(1)

	case remote.Size < local.Size:
		// Mirror is behind — push may be pending. Not an error.
		fmt.Printf("[witness] WARN  mirror is %d leaf(ves) behind local (push may be pending)\n",
			local.Size-remote.Size)
		fmt.Printf("               local  size=%-6d root=%s\n", local.Size, local.Root)
		fmt.Printf("               mirror size=%-6d root=%s\n", remote.Size, remote.Root)
		os.Exit(0)

	default:
		// Same size — roots must match.
		if local.Root != remote.Root {
			fmt.Fprintf(os.Stderr,
				"[witness] FAIL  mirror disagrees: size=%d but root mismatch\n"+
					"               local  root=%s\n"+
					"               mirror root=%s\n",
				local.Size, local.Root, remote.Root)
			os.Exit(1)
		}
		fmt.Printf("[witness] OK    leaves=%-6d root=%s\n", local.Size, local.Root)
	}
}
