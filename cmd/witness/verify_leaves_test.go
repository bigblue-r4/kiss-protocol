package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/merkle"
)

func TestCmdVerifyLeaves(t *testing.T) {
	var leaves [][32]byte
	var raw []byte
	for i := 0; i < 9; i++ {
		l := merkle.HashLeaf([]byte{byte(i)})
		leaves = append(leaves, l)
		raw = append(raw, l[:]...)
	}
	path := filepath.Join(t.TempDir(), "leaves.bin")
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	root7 := merkle.Root(leaves[:7])
	good := hex.EncodeToString(root7[:])
	bad := hex.EncodeToString(make([]byte, 32))

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"prefix matches", []string{"--leaves", path, "--size", "7", "--root", good}, 0},
		{"wrong root", []string{"--leaves", path, "--size", "7", "--root", bad}, 1},
		{"wrong size", []string{"--leaves", path, "--size", "8", "--root", good}, 1},
		{"feed too short", []string{"--leaves", path, "--size", "10", "--root", good}, 2},
		{"missing file", []string{"--leaves", path + ".x", "--size", "7", "--root", good}, 2},
		{"bad root hex", []string{"--leaves", path, "--size", "7", "--root", "zz"}, 2},
		{"no args", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := cmdVerifyLeaves(tc.args, &out, &errb); got != tc.want {
				t.Fatalf("exit %d, want %d (stderr %q)", got, tc.want, errb.String())
			}
		})
	}
}
