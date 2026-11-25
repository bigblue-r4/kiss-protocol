// Command poc-verify checks Proof-of-Control Evidence tokens (JSON rendering)
// with the clean-room verifier in pkg/pocverify.
//
//	poc-verify --pubkey HEX TOKEN.json...   exit 0 all valid, 1 any rejected, 2 usage/IO
//	poc-verify --vectors DIR                run an upstream vectors/manifest.json
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bigblue-r4/kiss-protocol/pkg/pocverify"
)

type keyList []ed25519.PublicKey

func (k *keyList) String() string { return fmt.Sprint(len(*k), " keys") }
func (k *keyList) Set(s string) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return fmt.Errorf("want a 32-byte Ed25519 public key in hex")
	}
	*k = append(*k, b)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("poc-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var keys keyList
	fs.Var(&keys, "pubkey", "trusted signer key, hex (repeatable)")
	vectors := fs.String("vectors", "", "run every vector listed in DIR/manifest.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *vectors != "" {
		if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "poc-verify: --vectors takes no token files")
			return 2
		}
		return runVectors(*vectors, stdout, stderr)
	}
	if fs.NArg() == 0 || len(keys) == 0 {
		fmt.Fprintln(stderr, "usage: poc-verify --pubkey HEX TOKEN.json...  |  poc-verify --vectors DIR")
		return 2
	}
	rc := 0
	for _, f := range fs.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(stderr, "poc-verify: %v\n", err)
			return 2
		}
		r := pocverify.Verify(b, keys)
		if r.OK() {
			fmt.Fprintf(stdout, "VALID     %s\n", f)
		} else {
			fmt.Fprintf(stdout, "REJECTED  %s  [%s] %s\n", f, r.Code, r.Detail)
			rc = 1
		}
		for _, n := range r.Notes {
			fmt.Fprintf(stdout, "          note: %s\n", n)
		}
	}
	return rc
}

type manifest struct {
	PublicKey string `json:"public_key"`
	Positive  []struct {
		File string `json:"file"`
	} `json:"positive"`
	Negative []struct {
		File       string `json:"file"`
		ExpectCode string `json:"expect_code"`
	} `json:"negative"`
	Canonical []struct {
		File   string `json:"file"`
		SHA256 string `json:"canonical_sha256"`
	} `json:"canonical"`
}

func runVectors(dir string, stdout, stderr io.Writer) int {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		fmt.Fprintf(stderr, "poc-verify: %v\n", err)
		return 2
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintf(stderr, "poc-verify: manifest: %v\n", err)
		return 2
	}
	var keys keyList
	if err := keys.Set(m.PublicKey); err != nil {
		fmt.Fprintf(stderr, "poc-verify: manifest public_key: %v\n", err)
		return 2
	}
	pass, fail := 0, 0
	line := func(ok bool, file, msg string) {
		mark := "ok  "
		if ok {
			pass++
		} else {
			mark = "FAIL"
			fail++
		}
		fmt.Fprintf(stdout, "  %s  %-45s %s\n", mark, file, msg)
	}
	readFile := func(f string) ([]byte, bool) {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			line(false, f, err.Error())
			return nil, false
		}
		return b, true
	}
	fmt.Fprintln(stdout, "Positive vectors (must validate)")
	for _, v := range m.Positive {
		if b, ok := readFile(v.File); ok {
			r := pocverify.Verify(b, keys)
			if r.OK() {
				line(true, v.File, "valid")
			} else {
				line(false, v.File, "rejected: "+r.Code+": "+r.Detail)
			}
		}
	}
	fmt.Fprintln(stdout, "Negative vectors (must be rejected for the stated reason)")
	for _, v := range m.Negative {
		if b, ok := readFile(v.File); ok {
			r := pocverify.Verify(b, keys)
			line(r.Code == v.ExpectCode, v.File, fmt.Sprintf("rejected: %s (expected %s)", orValid(r.Code), v.ExpectCode))
		}
	}
	fmt.Fprintln(stdout, "Canonical-form vectors (published digest must be reproduced)")
	for _, v := range m.Canonical {
		if b, ok := readFile(v.File); ok {
			val, err := pocverify.Parse(b)
			var c []byte
			if err == nil {
				c, err = pocverify.Canonical(val)
			}
			if err != nil {
				line(false, v.File, err.Error())
				continue
			}
			sum := sha256.Sum256(c)
			line(hex.EncodeToString(sum[:]) == v.SHA256, v.File, "sha256 "+hex.EncodeToString(sum[:8])+"…")
		}
	}
	fmt.Fprintf(stdout, "\n%d passed, %d failed\n", pass, fail)
	if fail > 0 {
		return 1
	}
	return 0
}

func orValid(code string) string {
	if code == "" {
		return "VALID"
	}
	return code
}
