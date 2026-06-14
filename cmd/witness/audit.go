package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/mirror"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// defaultMaxLag is the number of leaves the mirror may trail the local log
// before the audit treats it as a warning (exit 2) rather than pass (exit 0).
// S3 and HTTP mirrors are eventually consistent; a small lag is expected under
// continuous drift ticks. Set to 0 to disable the check (legacy behaviour).
const defaultMaxLag = 10

// cmdAudit fetches the transparency mirror's tree head and compares it to the
// local Merkle log.
//
// Exit codes:
//
//	0  — local and mirror agree (or mirror is behind within tolerance)
//	1  — mirror disagrees: sizes match but roots differ, or mirror claims a
//	     larger log than local — hard failure, investigate for tampering
//	2  — mirror unreachable/misconfigured, OR mirror lags beyond --max-lag
//
// Flags:
//
//	--max-lag N  Override the maximum tolerated lag (leaves). Default: 10.
//	             Pass 0 to disable lag checking.
func cmdAudit() {
	maxLag := uint64(defaultMaxLag)
	for i := 2; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--max-lag" {
			v, err := strconv.ParseUint(os.Args[i+1], 10, 64)
			if err != nil {
				fatal("--max-lag: %v", err)
			}
			maxLag = v
		}
	}

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

	// Retry once after a short delay to absorb S3/CDN propagation lag.
	raw, fetchErr := m.Fetch()
	if fetchErr != nil {
		time.Sleep(2 * time.Second)
		raw, fetchErr = m.Fetch()
	}
	if fetchErr != nil {
		fmt.Fprintf(os.Stderr, "[witness] FAIL  mirror unreachable: %v\n", fetchErr)
		os.Exit(2)
	}

	var remote store.TreeHead
	if err := json.Unmarshal(raw, &remote); err != nil {
		fmt.Fprintf(os.Stderr, "[witness] FAIL  mirror response unparseable: %v\n", err)
		os.Exit(2)
	}

	switch {
	case remote.Size > local.Size:
		// Mirror claims more entries than local — impossible in an append-only log
		// unless the local copy was truncated. Hard failure.
		fmt.Fprintf(os.Stderr,
			"[witness] FAIL  mirror disagrees: mirror claims %d leaves, local has %d\n",
			remote.Size, local.Size)
		os.Exit(1)

	case remote.Size == local.Size:
		// Same size — roots must match exactly.
		if local.Root != remote.Root {
			fmt.Fprintf(os.Stderr,
				"[witness] FAIL  mirror disagrees: size=%d but root mismatch\n"+
					"               local  root=%s\n"+
					"               mirror root=%s\n",
				local.Size, local.Root, remote.Root)
			os.Exit(1)
		}
		// Chain check: if the remote carries a PrevRoot we can verify the mirror's
		// head is correctly linked to the previous state we trust.
		if remote.PrevRoot != "" && local.PrevRoot != "" && remote.PrevRoot != local.PrevRoot {
			fmt.Fprintf(os.Stderr,
				"[witness] WARN  chain discontinuity: roots match but prev_root differs\n"+
					"               local  prev_root=%s\n"+
					"               mirror prev_root=%s\n",
				local.PrevRoot, remote.PrevRoot)
		}
		fmt.Printf("[witness] OK    leaves=%-6d root=%s\n", local.Size, local.Root)

	default:
		// Mirror is behind local. Check lag tolerance.
		lag := local.Size - remote.Size
		if maxLag > 0 && lag > maxLag {
			fmt.Fprintf(os.Stderr,
				"[witness] WARN  mirror lag %d exceeds max-lag %d — push may be stalled\n"+
					"               local  size=%-6d root=%s\n"+
					"               mirror size=%-6d root=%s\n",
				lag, maxLag, local.Size, local.Root, remote.Size, remote.Root)
			os.Exit(2)
		}
		fmt.Printf("[witness] WARN  mirror is %d leaf(ves) behind local (eventual consistency lag)\n",
			lag)
		fmt.Printf("               local  size=%-6d root=%s\n", local.Size, local.Root)
		fmt.Printf("               mirror size=%-6d root=%s\n", remote.Size, remote.Root)
		os.Exit(0)
	}
}
