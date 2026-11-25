package main

import (
	"bytes"
	"strings"
	"testing"
)

const vecDir = "../../pkg/pocverify/testdata/upstream-54a7bc6"

func TestRunVectors(t *testing.T) {
	var out, errb bytes.Buffer
	rc := run([]string{"--vectors", vecDir}, &out, &errb)
	// modify-bound.json is rejected on purpose (upstream #170), so the run
	// reports exactly one failure until upstream regenerates that vector.
	if rc != 1 || !strings.Contains(out.String(), "16 passed, 1 failed") ||
		!strings.Contains(out.String(), "FAIL  positive/modify-bound.json") {
		t.Fatalf("rc=%d\n%s%s", rc, out.String(), errb.String())
	}
}

func TestRunTokens(t *testing.T) {
	key := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	for _, tc := range []struct {
		args []string
		rc   int
	}{
		{[]string{"--pubkey", key, vecDir + "/positive/allow-read.json"}, 0},
		{[]string{"--pubkey", key, vecDir + "/positive/allow-read.json", vecDir + "/negative/bad-signature.json"}, 1},
		{[]string{vecDir + "/positive/allow-read.json"}, 2},
		{[]string{"--pubkey", "zz", vecDir + "/positive/allow-read.json"}, 2},
		{[]string{"--pubkey", key, vecDir + "/nope.json"}, 2},
		{[]string{"--vectors", vecDir, "x.json"}, 2},
	} {
		var out, errb bytes.Buffer
		if rc := run(tc.args, &out, &errb); rc != tc.rc {
			t.Errorf("%v: rc=%d want %d\n%s%s", tc.args, rc, tc.rc, out.String(), errb.String())
		}
	}
}
