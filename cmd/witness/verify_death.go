package main

import (
	"flag"
	"os"

	"github.com/bigblue-r4/kiss-protocol/internal/death"
)

func cmdVerifyDeath() {
	flags := flag.NewFlagSet("verify-death", flag.ExitOnError)
	log := flags.String("log", "", "read-only encrypted log to verify captured hashes against")
	_ = flags.Parse(os.Args[2:])
	if flags.NArg() != 1 {
		fatal("usage: witness verify-death [--log FILE] <primary-dir>")
	}
	if err := death.Verify(flags.Arg(0), *log, os.Stdout); err != nil {
		fatal("%v", err)
	}
}
