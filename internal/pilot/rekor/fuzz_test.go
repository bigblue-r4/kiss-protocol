package rekor_test

import (
	"encoding/json"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
)

// FuzzVerifyEntry: arbitrary Rekor responses never panic and are never
// accepted unless they verify under the pinned key.
func FuzzVerifyEntry(f *testing.F) {
	uuid, raw := loadF(f)
	f.Add(uuid, []byte(raw))
	f.Add(uuid, []byte(`{}`))
	f.Add("00", []byte(`{"body":"","verification":{"inclusionProof":{"checkpoint":"a - b\n1\nAA==\n\n— a AAAAAAA=\n"}}}`))
	k, err := rekor.ParsePublicKey(pubF(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, u string, b []byte) {
		e, body, _, err := rekor.VerifyEntry(u, json.RawMessage(b), k)
		if err == nil && (e == nil || len(body) == 0) {
			t.Fatal("accepted with no entry")
		}
	})
}
