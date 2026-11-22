package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInitHelpDoesNotInitialize(t *testing.T) {
	if os.Getenv("WITNESS_INIT_HELP_TEST_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				return
			}
		}
		os.Exit(2)
	}
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			home := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestInitHelpDoesNotInitialize$", "--", "init", flag)
			cmd.Env = append(os.Environ(), "WITNESS_INIT_HELP_TEST_HELPER=1", "HOME="+home)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("help failed: %v %s", err, output)
			}
			text := string(output)
			if !strings.Contains(text, "same user as the witness daemon") || strings.Contains(text, "Loading soul") {
				t.Fatalf("not safe init help: %s", output)
			}
			files, err := os.ReadDir(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 0 {
				t.Fatalf("help wrote state: %v", files)
			}
		})
	}
}
