package main

import (
	"encoding/hex"
	"os"
	"os/exec"
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

func TestRequireVerifierPins(t *testing.T) {
	key := strings.Repeat("ab", 32)
	for _, args := range [][]string{
		{"--require-pins"}, {"--require-pins=false"}, {"--require-pins=true"},
		{"--require-pins", "--pubkey", "invalid"},
	} {
		if _, _, err := parseVerifierPins(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	file := filepath.Join(t.TempDir(), "signers")
	if err := os.WriteFile(file, []byte("trusted "+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--require-pins", "--pubkey", key, "0"},
		{"0", "--pubkey=" + key, "--require-pins"},
		{"--require-pins", "--pubkey-file", file, "0"},
	} {
		pins, rest, err := parseVerifierPins(args)
		if err != nil || len(pins) != 1 || !reflect.DeepEqual(rest, []string{"0"}) {
			t.Fatalf("%v: pins=%v rest=%v err=%v", args, pins, rest, err)
		}
	}
}

// Exercise real command dispatch: strict verification must reject missing trust
// configuration before trying to load local state or contact a mirror.
func TestRequirePinsCLI(t *testing.T) {
	if os.Getenv("WITNESS_REQUIRE_PINS_TEST_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				return
			}
		}
		os.Exit(2)
	}
	for _, command := range []string{"verify", "prove", "audit"} {
		t.Run(command, func(t *testing.T) {
			args := []string{"-test.run=^TestRequirePinsCLI$", "--", command, "--require-pins"}
			if command == "prove" {
				args = append(args, "0")
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "WITNESS_REQUIRE_PINS_TEST_HELPER=1")
			output, err := cmd.CombinedOutput()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 || !strings.Contains(string(output), "--require-pins requires a trusted") {
				t.Fatalf("expected missing-trust failure, got %v: %s", err, output)
			}
		})
	}
}
