package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

// demoInit creates, once, every key and config file the local demo needs:
// the log key, a witness key in the format omniwitness reads, the adapter
// token and the witness's log list. It never overwrites a file, so running
// it again is harmless. Demo only: all keys are software keys on one host.
func demoInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("demo-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "key directory")
	logOrigin := fs.String("log-origin", "pilot.example/demo-log", "log origin")
	witnessName := fs.String("witness-name", "pilot.example/demo-witness", "witness name")
	if fs.Parse(args) != nil || *dir == "" {
		fmt.Fprintln(stderr, "usage: harborlight-log demo-init --dir DIR [--log-origin O] [--witness-name N]")
		return 2
	}
	p := func(n string) string { return filepath.Join(*dir, n) }
	if _, err := os.Stat(p("log.key")); err == nil {
		fmt.Fprintln(stdout, "demo keys already present in", *dir)
		return 0
	}
	if err := checkpoint.ValidName(*logOrigin); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := checkpoint.ValidName(*witnessName); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	lsk, lvk, err := note.GenerateKey(rand.Reader, *logOrigin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	wsk, wvk, err := note.GenerateKey(rand.Reader, *witnessName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	// The witness signs cosignature/v1 with its Ed25519 key; verifiers pin
	// the same public key under signature type 0x04.
	raw, err := base64.StdEncoding.DecodeString(strings.SplitN(wvk, "+", 3)[2])
	if err != nil || len(raw) != 33 {
		fmt.Fprintln(stderr, "unexpected witness key encoding")
		return 1
	}
	wpub := checkpoint.NewCosignerKey(*witnessName, raw[1:]).String()
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	files := []struct {
		name, body string
		mode       os.FileMode
	}{
		{"witness.sec", wsk, 0o600},
		{"witness.pub", wpub + "\n", 0o644},
		{"adapter.token", base64.RawURLEncoding.EncodeToString(tok) + "\n", 0o600},
		{"witness-logs.yaml", fmt.Sprintf("Logs:\n  - Origin: %s\n    PublicKey: %s\n    URL: http://unused.invalid/\n", *logOrigin, lvk), 0o644},
		{"log.key.pub", lvk + "\n", 0o644},
		{"log.key", lsk + "\n", 0o600}, // last: its presence means the set is complete
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	for _, f := range files {
		h, err := os.OpenFile(p(f.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(stderr, "%s exists but log.key does not: a previous demo-init was interrupted; clear %s and run again\n", f.name, *dir)
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_, werr := h.WriteString(f.body)
		if cerr := h.Close(); werr != nil || cerr != nil {
			fmt.Fprintln(stderr, "writing", f.name, werr, cerr)
			return 1
		}
	}
	fmt.Fprintf(stdout, "demo keys written to %s\nlog key:     %s\nwitness key: %s\n", *dir, lvk, wpub)
	return 0
}
