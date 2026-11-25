package checkpoint_test

import (
	"testing"

	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// FuzzOpen feeds untrusted notes and witness bodies to the parsers and the
// verifiers. They must never panic, and a note they accept must round-trip
// its checkpoint body.
func FuzzOpen(f *testing.F) {
	f.Add([]byte("pilot.example/log\n3\n" + "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" + "\n\n— pilot.example/log AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
	f.Add([]byte("old 0\n\no\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— o AAAAAAAA\n"))
	key := checkpoint.NewCosignerKey("w", make([]byte, 32))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if s, err := checkpoint.Open(raw); err == nil {
			if string(s.Checkpoint.Text()) != string(s.Text) {
				t.Fatalf("accepted body does not round-trip: %q", s.Text)
			}
			_ = s.VerifyLog("o+00000000+AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			_ = s.Cosignatures([]checkpoint.CosignerKey{key})
		}
		if _, proof, signed, err := checkpoint.ParseAddCheckpointBody(raw); err == nil {
			if len(proof) > checkpoint.MaxProofLines {
				t.Fatal("proof longer than the limit accepted")
			}
			_, _ = checkpoint.Open(signed)
		}
		_, _ = checkpoint.ParseCosignerKey(string(raw))
		_ = tlog.Hash{}
	})
}
