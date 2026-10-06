//go:build poc_c07

package poc_c07

import (
	"os"
	"strings"
	"testing"
)

// ── 7.4.1 trust-assumption disclosure ───────────────────────────────────────

func readThreatModel(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/threat-model.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The parties and roots that must be trusted are published.
func TestC07_7_4_1_TrustRootsAndAssumptionsArePublished(t *testing.T) {
	tm := readThreatModel(t)
	for _, want := range []string{"## Trust Roots", "## Operational Assumptions", "## Non-Goals", "signers.txt", "mirror"} {
		if !strings.Contains(tm, want) {
			t.Fatalf("docs/threat-model.md no longer discloses %q", want)
		}
	}
}

// Probe: C7.4.1 also wants every hardware element and mathematical assumption
// per mechanism. The disclosure names none of the primitives the evidence
// rests on, nor that the MAC/encryption key derives from /etc/machine-id.
func TestC07_7_4_1_Probe_MathematicalAssumptionsAreDisclosed(t *testing.T) {
	tm := strings.ToLower(readThreatModel(t))
	var missing []string
	for _, a := range []string{"blake3", "ed25519", "aes-256-gcm", "hkdf", "machine-id"} {
		if !strings.Contains(tm, a) {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("docs/threat-model.md does not disclose: %v", missing)
	}
}
