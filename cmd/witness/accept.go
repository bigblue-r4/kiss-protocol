package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/accept"
	"github.com/bigblue-r4/kiss-protocol/internal/config"
	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

const acceptUsage = `usage: witness accept <command>

Approve known drift so it is no longer listed on every drift check. An
approval pins exact values (a path with its current hash, or a process name);
a later change to the same file is reported again. Approvals are recorded in
the witness log and need a separate operator key (not the witness's own).

  list                          Active approvals, then the latest unapproved drift (numbered)
  request (--all | --item N[,N...]) --reason TEXT (--key KEYFILE | --out FILE)
                                Approve items from the latest drift. With --key: sign and
                                submit. With --out: write an unsigned request to sign elsewhere.
  revoke ID --reason TEXT (--key KEYFILE | --out FILE)
                                Withdraw an approval
  sign --key KEYFILE FILE       Sign a request file in place (works on any machine)
  submit FILE                   Hand a signed request to the running witness and wait for it
  keygen --out KEYFILE          Make an operator key; prints the line for trust/operators.txt

Run list/request/revoke/submit as the witness user (sudo -H -u witness ...).
`

func cmdAccept() {
	if len(os.Args) < 3 {
		fmt.Fprint(os.Stderr, acceptUsage)
		os.Exit(1)
	}
	sub, args := os.Args[2], os.Args[3:]
	switch sub {
	case "list":
		acceptList()
	case "request":
		acceptRequest(args)
	case "revoke":
		acceptRevoke(args)
	case "sign":
		acceptSign(args)
	case "submit":
		if len(args) != 1 {
			fatal("usage: witness accept submit FILE")
		}
		r, err := accept.ReadFile(args[0])
		if err != nil {
			fatal("%v", err)
		}
		acceptSubmit(r)
	case "keygen":
		f := parseAcceptFlags(args, "--out")
		if f.vals["--out"] == "" {
			fatal("usage: witness accept keygen --out KEYFILE")
		}
		pub, err := accept.Keygen(f.vals["--out"])
		if err != nil {
			fatal("keygen: %v", err)
		}
		fmt.Printf("Operator key written to %s (keep it off the witnessed machine).\n", f.vals["--out"])
		fmt.Printf("Add this line to %s on the witnessed machine:\n\n", "<witness home>/.witness/trust/operators.txt")
		fmt.Printf("operator %s\n", hex.EncodeToString(pub))
	default:
		fmt.Fprint(os.Stderr, acceptUsage)
		os.Exit(1)
	}
}

type acceptFlags struct {
	vals map[string]string
	all  bool
	pos  []string
}

// parseAcceptFlags reads the value flags named in valued, plus --all, and
// keeps the rest as positional arguments.
func parseAcceptFlags(args []string, valued ...string) acceptFlags {
	f := acceptFlags{vals: map[string]string{}}
	isValued := map[string]bool{}
	for _, v := range valued {
		isValued[v] = true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--all":
			f.all = true
		case isValued[a]:
			if i+1 >= len(args) {
				fatal("%s requires a value", a)
			}
			i++
			f.vals[a] = args[i]
		case strings.HasPrefix(a, "--"):
			fatal("unknown flag %s\n\n%s", a, acceptUsage)
		default:
			f.pos = append(f.pos, a)
		}
	}
	return f
}

// acceptLog reads the witness log and config (read-only; safe while the
// daemon runs).
func acceptLog() (*config.Config, []store.Entry) {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun as the witness user (sudo -H -u witness ...).", err)
	}
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	entries, err := store.ReadAll(cfg.PrimaryDir, key)
	if err != nil {
		fatal("read log: %v", err)
	}
	return cfg, entries
}

func recordedApprovals(entries []store.Entry) *accept.Set {
	p := accept.Policy{MachineID: machid.Get(), AnySigner: true}
	if ops, err := soul.LoadAllowlist(accept.OperatorsPath(witnessDir())); err == nil {
		p.Operators = ops
	}
	set, _ := accept.Replay(entries, p)
	return set
}

func latestDrift(entries []store.Entry) (store.Entry, []drift.Change, bool) {
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Source == "drift" && e.Event == "drift_detected" {
			var ch []drift.Change
			if err := json.Unmarshal(e.Data, &ch); err == nil {
				return e, ch, true
			}
		}
	}
	return store.Entry{}, nil, false
}

func describeChange(c drift.Change) string {
	switch c.Type {
	case "new_process":
		return fmt.Sprintf("new_process  %s", c.Process)
	case "file_removed":
		return fmt.Sprintf("file_removed %s", c.Path)
	default:
		n := c.New
		if len(n) > 12 {
			n = n[:12] + "…"
		}
		return fmt.Sprintf("%-12s %s → %s", c.Type, c.Path, n)
	}
}

func acceptList() {
	_, entries := acceptLog()
	set := recordedApprovals(entries)
	list := set.Approvals()
	fmt.Printf("Active approvals: %d\n", len(list))
	for _, a := range list {
		fmt.Printf("\n  %s  %s  by %s\n  reason: %s\n", a.ID, a.Created, a.Label, a.Reason)
		for _, c := range a.Changes {
			fmt.Printf("    %s\n", describeChange(c))
		}
	}
	e, changes, ok := latestDrift(entries)
	if !ok {
		fmt.Println("\nNo unapproved drift recorded.")
		return
	}
	// The latest entry was written before any newer approval; drop what is
	// approved now so the numbers match what 'request' will use.
	changes, _ = set.Filter(changes)
	fmt.Printf("\nLatest drift (seq %d, %s), unapproved: %d\n", e.Seq, e.Timestamp.Format(time.RFC3339), len(changes))
	for i, c := range changes {
		fmt.Printf("  %2d  %s\n", i+1, describeChange(c))
	}
}

func acceptRequest(args []string) {
	f := parseAcceptFlags(args, "--item", "--reason", "--key", "--out")
	if f.all == (f.vals["--item"] != "") || len(f.pos) != 0 {
		fatal("request needs exactly one of --all or --item N[,N...]\n\n%s", acceptUsage)
	}
	_, entries := acceptLog()
	_, changes, ok := latestDrift(entries)
	if !ok {
		fatal("no drift recorded; nothing to approve")
	}
	changes, _ = recordedApprovals(entries).Filter(changes)
	if len(changes) == 0 {
		fatal("every change in the latest drift is already approved")
	}
	picked := changes
	if !f.all {
		picked = nil
		for _, s := range strings.Split(f.vals["--item"], ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < 1 || n > len(changes) {
				fatal("--item %q: pick numbers 1–%d from 'witness accept list'", s, len(changes))
			}
			picked = append(picked, changes[n-1])
		}
	}
	r, err := accept.NewAccept(machid.Get(), f.vals["--reason"], picked)
	if err != nil {
		fatal("%v", err)
	}
	for _, c := range picked {
		fmt.Printf("  approve  %s\n", describeChange(c))
	}
	finishRequest(r, f)
}

func acceptRevoke(args []string) {
	f := parseAcceptFlags(args, "--reason", "--key", "--out")
	if len(f.pos) != 1 {
		fatal("usage: witness accept revoke ID --reason TEXT (--key KEYFILE | --out FILE)")
	}
	r, err := accept.NewRevoke(machid.Get(), f.vals["--reason"], f.pos[0])
	if err != nil {
		fatal("%v", err)
	}
	finishRequest(r, f)
}

// finishRequest signs and submits r (--key) or writes it unsigned (--out).
func finishRequest(r *accept.Request, f acceptFlags) {
	keyFile, out := f.vals["--key"], f.vals["--out"]
	if (keyFile == "") == (out == "") {
		fatal("give exactly one of --key KEYFILE (sign and submit now) or --out FILE (sign elsewhere)")
	}
	if out != "" {
		if err := r.WriteFile(out); err != nil {
			fatal("write %s: %v", out, err)
		}
		fmt.Printf("Unsigned request %s written to %s.\nSign it: witness accept sign --key KEYFILE %s\nThen, back here: witness accept submit %s\n",
			r.ID, out, filepath.Base(out), filepath.Base(out))
		return
	}
	priv, err := accept.LoadKey(keyFile)
	if err != nil {
		fatal("operator key: %v", err)
	}
	if err := r.Sign(priv); err != nil {
		fatal("sign: %v", err)
	}
	acceptSubmit(r)
}

func acceptSign(args []string) {
	f := parseAcceptFlags(args, "--key")
	if f.vals["--key"] == "" || len(f.pos) != 1 {
		fatal("usage: witness accept sign --key KEYFILE FILE")
	}
	r, err := accept.ReadFile(f.pos[0])
	if err != nil {
		fatal("%v", err)
	}
	priv, err := accept.LoadKey(f.vals["--key"])
	if err != nil {
		fatal("operator key: %v", err)
	}
	if err := r.Sign(priv); err != nil {
		fatal("sign: %v", err)
	}
	if err := r.WriteFile(f.pos[0]); err != nil {
		fatal("write: %v", err)
	}
	fmt.Printf("Signed %s request %s (%s) by %s\n", r.Kind, r.ID, r.Reason, r.Signer)
	for _, c := range r.Changes {
		fmt.Printf("  %s\n", describeChange(c))
	}
}

// acceptSubmit spools r and waits for the daemon to record the outcome.
func acceptSubmit(r *accept.Request) {
	cfg, err := config.Load(config.Path())
	if err != nil {
		fatal("load config: %v\n\nRun as the witness user (sudo -H -u witness ...).", err)
	}
	path, err := accept.Submit(cfg.PrimaryDir, r)
	if err != nil {
		fatal("submit: %v", err)
	}
	fmt.Printf("Submitted %s; waiting for the witness (next drift check)…\n", filepath.Base(path))
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	deadline := time.Now().Add(time.Duration(cfg.DriftIntervalSec)*time.Second*2 + 10*time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		entries, err := store.ReadAll(cfg.PrimaryDir, key)
		if err != nil {
			continue
		}
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			if e.Source != accept.Source {
				continue
			}
			var d struct {
				ID    string `json:"id"`
				Error string `json:"error"`
			}
			if json.Unmarshal(e.Data, &d) != nil || d.ID != r.ID {
				continue
			}
			if e.Event == accept.EventRejected {
				fatal("REJECTED (seq %d): %s", e.Seq, d.Error)
			}
			fmt.Printf("Recorded: %s (seq %d), id %s\n", e.Event, e.Seq, r.ID)
			return
		}
	}
	fatal("no answer from the witness yet; the request stays in %s. Is the daemon running?", path)
}
