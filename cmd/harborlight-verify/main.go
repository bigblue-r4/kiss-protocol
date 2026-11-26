// Command harborlight-verify is the standalone pilot verifier. It needs only
// public material and keys the evaluator pins; it never needs a private key.
//
// Exit status: 0 VERIFIED, 1 FAILED, 3 UNVERIFIABLE, 2 usage error.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/internal/pilot/verify"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, " ") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

const usageText = `usage: harborlight-verify --source DIR|URL --log-key VKEY|@FILE
                          --witness-key VKEY|@FILE [--witness-key ...]
                          [--operator-witness-key VKEY|@FILE]...
                          [--quorum N] [--max-age 10m] [--state FILE]
                          [--operator-witness NAME]... [--report FILE.html] [--json FILE]
                          [--rekor-key FILE.pem --anchor-key FILE.pem [--rekor-url URL]]

With --rekor-key and --anchor-key (PEM public keys: the Rekor log's, and the
log's anchoring key), the log's latest Rekor anchor must exist and match the
records. That check is offline. Add --rekor-url URL to also search that Rekor
for every anchor made with the anchoring key and check each one (online).

Keys must come from a channel you trust, never from the log's own files.
Exit status: 0 VERIFIED, 1 FAILED, 3 UNVERIFIABLE, 2 usage.
`

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harborlight-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	source := fs.String("source", "", "public directory or URL")
	logKey := fs.String("log-key", "", "pinned log verifier key, or @file")
	quorum := fs.Int("quorum", 1, "fresh witness cosignatures required (at least 1)")
	maxAge := fs.Duration("max-age", 10*time.Minute, "newest acceptable cosignature age")
	state := fs.String("state", "", "file holding the last checkpoint you verified (rollback and rewrite detection)")
	report := fs.String("report", "", "write an HTML report here")
	jsonOut := fs.String("json", "", "write the JSON result here")
	rekorKey := fs.String("rekor-key", "", "pinned Rekor log public key (PEM file)")
	anchorKey := fs.String("anchor-key", "", "pinned anchoring public key of this log (PEM file)")
	rekorURL := fs.String("rekor-url", "", "with the Rekor pins: search this Rekor for every anchor (online)")
	var wkeys, opKeys, opRun multi
	fs.Var(&wkeys, "witness-key", "pinned witness verifier key, or @file (repeatable)")
	fs.Var(&opKeys, "operator-witness-key", "like --witness-key, for a witness run by the log operator (disclosed as not independent)")
	fs.Var(&opRun, "operator-witness", "name of a witness run by the log operator (disclosed; repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" || *logKey == "" || len(wkeys)+len(opKeys) == 0 || *quorum < 1 || *maxAge <= 0 {
		fmt.Fprint(stderr, usageText)
		fmt.Fprintln(stderr, "\n--source, --log-key and at least one --witness-key are required; --quorum must be at least 1.")
		return 2
	}
	lk, err := readKeys(*logKey)
	if err != nil || len(lk) != 1 {
		fmt.Fprintln(stderr, "--log-key: want exactly one key:", err)
		return 2
	}
	o := verify.Options{Source: *source, LogKey: lk[0], Quorum: *quorum, MaxAge: *maxAge, StatePath: *state, OperatorControlled: map[string]bool{}}
	for i, w := range append(append([]string(nil), wkeys...), opKeys...) {
		ks, err := readKeys(w)
		if err != nil {
			fmt.Fprintln(stderr, "--witness-key:", err)
			return 2
		}
		for _, k := range ks {
			ck, err := checkpoint.ParseCosignerKey(k)
			if err != nil {
				fmt.Fprintln(stderr, "--witness-key:", err)
				return 2
			}
			o.WitnessKeys = append(o.WitnessKeys, ck)
			if i >= len(wkeys) {
				opRun = append(opRun, ck.Name)
			}
		}
	}
	if *quorum > len(o.WitnessKeys) {
		fmt.Fprintln(stderr, "--quorum is larger than the number of witness keys")
		return 2
	}
	for _, n := range opRun {
		o.OperatorControlled[n] = true
	}
	if (*rekorKey == "") != (*anchorKey == "") {
		fmt.Fprintln(stderr, "--rekor-key and --anchor-key go together")
		return 2
	}
	if *rekorURL != "" && *rekorKey == "" {
		fmt.Fprintln(stderr, "--rekor-url needs --rekor-key and --anchor-key")
		return 2
	}
	o.RekorURL = *rekorURL
	if *rekorKey != "" {
		for _, p := range []struct {
			flag, path string
			dst        **ecdsa.PublicKey
		}{{"--rekor-key", *rekorKey, &o.RekorKey}, {"--anchor-key", *anchorKey, &o.AnchorKey}} {
			b, err := os.ReadFile(p.path)
			if err == nil {
				*p.dst, err = rekor.ParsePublicKey(b)
			}
			if err != nil {
				fmt.Fprintln(stderr, p.flag+":", err)
				return 2
			}
		}
	}
	r := verify.Run(context.Background(), o)
	fmt.Fprintf(stdout, "%s: %s\n", r.Overall, r.Summary)
	for _, c := range r.Checks {
		fmt.Fprintf(stdout, "  %-12s %s: %s\n", c.Status, c.Title, c.Detail)
		if c.Warning != "" {
			fmt.Fprintf(stdout, "  %-12s   note: %s\n", "", c.Warning)
		}
	}
	if *report != "" {
		if err := writeFile(*report, r.WriteHTML); err != nil {
			fmt.Fprintln(stderr, "report:", err)
			return 2
		}
	}
	if *jsonOut != "" {
		if err := writeFile(*jsonOut, r.WriteJSON); err != nil {
			fmt.Fprintln(stderr, "json:", err)
			return 2
		}
	}
	switch r.Overall {
	case verify.Verified:
		return 0
	case verify.Failed:
		return 1
	default:
		return 3
	}
}

func readKeys(arg string) ([]string, error) {
	if !strings.HasPrefix(arg, "@") {
		return []string{arg}, nil
	}
	f, err := os.Open(arg[1:])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

func writeFile(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
