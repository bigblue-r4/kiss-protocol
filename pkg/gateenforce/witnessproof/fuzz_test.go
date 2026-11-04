package witnessproof

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// FuzzVerify feeds attacker-shaped evidence (any index, size, entry and proof
// length) to Verify. It must never panic: the evidence arrives in a token.
func FuzzVerify(f *testing.F) {
	h := strings.Repeat("ab", 32)
	f.Add(uint64(2), uint64(5), `{"source":"gate","event":"gate_request","data":{"action_hash":"x"}}`, 3)
	f.Add(uint64(0), uint64(1), `{}`, 0)
	f.Add(uint64(4), uint64(5), ``, 1)
	f.Add(uint64(1<<63), uint64(1<<63+1), `{"seq":1}`, 64)
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, index, size uint64, entry string, nproof int) {
		if nproof < 0 || nproof > 70 {
			return
		}
		proof := make([]string, nproof)
		for i := range proof {
			proof[i] = h
		}
		w := proto.Witnessed{Head: proto.WitnessHead{Size: size, Root: h, Sig: strings.Repeat("cd", 64), SignerKey: strings.Repeat("00", 32)},
			LeafIndex: index, Entry: entry, Proof: proof}
		_ = Verify(w, h, []ed25519.PublicKey{pub})
		// Past the signature check too: the structural checks must hold alone.
		if index < size {
			_ = auditPathLen(index, size)
		}
	})
}
