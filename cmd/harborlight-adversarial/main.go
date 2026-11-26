// Command harborlight-adversarial runs the pilot's adversarial regression
// suite and prints, for each attack, the expected and the actual verifier
// result. Exit status 0 means every case matched.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/adversarial"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("harborlight-adversarial", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.String("json", "", "write results as JSON to this file")
	keep := fs.String("keep", "", "build the cases in this directory and keep it (default: a temporary directory, removed)")
	if fs.Parse(args) != nil {
		return 2
	}
	dir := *keep
	if dir == "" {
		d, err := os.MkdirTemp("", "harborlight-adversarial-")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		defer os.RemoveAll(d)
		dir = d
	}
	out, err := adversarial.Run(dir)
	if err != nil {
		fmt.Fprintln(stderr, "suite error:", err)
		return 2
	}
	failed := 0
	fmt.Fprintf(stdout, "%-4s %-32s %-13s %-13s %s\n", "", "case", "expected", "got", "attack")
	for _, o := range out {
		mark := "ok"
		if !o.Pass {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(stdout, "%-4s %-32s %-13s %-13s %s\n", mark, o.ID, o.Expect, o.Got, o.Attack)
		if !o.Pass {
			fmt.Fprintf(stdout, "     verifier said: %s\n", o.Summary)
		}
	}
	fmt.Fprintf(stdout, "\n%d of %d cases matched the expected result.\n", len(out)-failed, len(out))
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}
