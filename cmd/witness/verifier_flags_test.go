package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
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

// Run the packaged service's actual command against a signed local log and
// matching mirror. Substitute only deployment paths, not its security flags.
func TestPackagedAuditCommand(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".witness")
	primary := filepath.Join(state, "primary")
	mirror := filepath.Join(home, "mirror")
	if err := os.MkdirAll(mirror, 0700); err != nil {
		t.Fatal(err)
	}
	signingKey, err := signer.NewSoftware(filepath.Join(home, "signer"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		t.Fatal(err)
	}
	log, err := store.Open(primary, key, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append("INFO", "test audit", "test", nil); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	head, err := os.ReadFile(filepath.Join(primary, "tree-head.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirror, "tree-head.json"), head, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := json.Marshal(map[string]any{"primary_dir": primary, "mirror_url": "file://" + filepath.ToSlash(mirror)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "config.json"), cfg, 0600); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile("../../packaging/systemd/witness-audit.service")
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	for _, line := range strings.Split(string(unit), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			args = strings.Fields(strings.TrimPrefix(line, "ExecStart="))[1:]
		}
	}
	if len(args) == 0 {
		t.Fatal("audit service has no command")
	}
	pinFile := filepath.Join(home, "trusted-signers.txt")
	for i := range args {
		if args[i] == "/etc/witness/trusted-signers.txt" {
			args[i] = pinFile
		}
	}
	trusted := "trusted " + hex.EncodeToString(signingKey.PublicKey()) + "\n"
	for _, tc := range []struct {
		name, pins, want string
		missing          bool
		code             int
	}{
		{name: "trusted", pins: trusted, want: "OK", code: 0},
		{name: "missing", missing: true, want: "--pubkey-file", code: 1},
		{name: "empty", pins: "# no trust roots\n", want: "requires a trusted", code: 1},
		{name: "untrusted", pins: "other " + strings.Repeat("ab", 32) + "\n", want: "INTEGRITY FAILURE", code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missing {
				if err := os.Remove(pinFile); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(pinFile, []byte(tc.pins), 0600); err != nil {
				t.Fatal(err)
			}
			cliArgs := append([]string{"-test.run=^TestRequirePinsCLI$", "--"}, args...)
			cmd := exec.Command(os.Args[0], cliArgs...)
			cmd.Env = append(os.Environ(), "WITNESS_REQUIRE_PINS_TEST_HELPER=1", "HOME="+home)
			output, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				exitErr, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				code = exitErr.ExitCode()
			}
			if code != tc.code || !strings.Contains(string(output), tc.want) {
				t.Fatalf("exit=%d want=%d: %s", code, tc.code, output)
			}
		})
	}
}
