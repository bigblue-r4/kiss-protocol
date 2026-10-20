package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseVerifierPins(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	file := filepath.Join(t.TempDir(), "signers.txt")
	if err := os.WriteFile(file, []byte("# trusted keys\nold "+a+"\nnew "+b+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pins, rest, err := parseVerifierPins([]string{"3", "--pubkey", a, "--pubkey=" + b, "--pubkey-file", file, "--max-lag", "50"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 4 || hex.EncodeToString(pins[0]) != a || hex.EncodeToString(pins[1]) != b || hex.EncodeToString(pins[2]) != a || hex.EncodeToString(pins[3]) != b {
		t.Fatalf("pins: %x", pins)
	}
	if !reflect.DeepEqual(rest, []string{"3", "--max-lag", "50"}) {
		t.Fatal(rest)
	}
	pins, rest, err = parseVerifierPins([]string{"0"})
	if err != nil || len(pins) != 0 || !reflect.DeepEqual(rest, []string{"0"}) {
		t.Fatalf("%v %v %v", pins, rest, err)
	}
}

func TestParseVerifierPinsErrors(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	bad := filepath.Join(t.TempDir(), "bad")
	for file, data := range map[string]string{empty: "# no keys\n", bad: "bad xyz\n"} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"--pubkey"}, {"--pubkey-file"}, {"--pubkey", "zz"}, {"--pubkey", "ab"},
		{"--pubkey", strings.Repeat("ab", 33)}, {"--pubkey="},
		{"--pubkey-file", filepath.Join(t.TempDir(), "missing")}, {"--pubkey-file", empty}, {"--pubkey-file", bad},
	} {
		if _, _, err := parseVerifierPins(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
