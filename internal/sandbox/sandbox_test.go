//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestNoEffectiveCapabilities asserts that the process holds no effective Linux
// capabilities. Under the hardened systemd unit (CapabilityBoundingSet=) this
// is always true. When run directly as a non-root user it is also always true.
//
// Skip conditions:
//   - Running as root (UID 0): capabilities are meaningful there and the test
//     would produce a false failure outside of a namespace.
//   - WITNESS_TEST_SKIP_CAPS=1: opt-out for environments where /proc is
//     unavailable (e.g. some container setups without procfs).
func TestNoEffectiveCapabilities(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: running as root — CapEff check not meaningful without namespace isolation")
	}
	if os.Getenv("WITNESS_TEST_SKIP_CAPS") == "1" {
		t.Skip("skipping: WITNESS_TEST_SKIP_CAPS=1")
	}

	capEff, err := readCapEff()
	if err != nil {
		t.Fatalf("read CapEff from /proc/self/status: %v", err)
	}
	if capEff != 0 {
		t.Errorf("CapEff = 0x%016x, want 0 — process must not hold any Linux capabilities", capEff)
		t.Log("If running under the hardened systemd unit, check that CapabilityBoundingSet= is set.")
	}
}

// TestNoAmbientCapabilities asserts that the process holds no ambient
// capabilities (CapAmb). Ambient caps survive exec and are an escalation vector.
func TestNoAmbientCapabilities(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: running as root")
	}
	if os.Getenv("WITNESS_TEST_SKIP_CAPS") == "1" {
		t.Skip("skipping: WITNESS_TEST_SKIP_CAPS=1")
	}

	capAmb, err := readProcStatusField("CapAmb")
	if err != nil {
		t.Fatalf("read CapAmb: %v", err)
	}
	if capAmb != 0 {
		t.Errorf("CapAmb = 0x%016x, want 0 — ambient capabilities must be empty", capAmb)
	}
}

// TestNoPRSetNoNewPrivs checks that the process has NoNewPrivs set, meaning
// it cannot gain new capabilities through exec (setuid binaries, etc.).
// Under the systemd unit this is enforced by NoNewPrivileges=true.
func TestNoPRSetNoNewPrivs(t *testing.T) {
	if os.Getenv("WITNESS_TEST_SKIP_CAPS") == "1" {
		t.Skip("skipping: WITNESS_TEST_SKIP_CAPS=1")
	}
	// Read NoNewPrivs from /proc/self/status (Linux 4.10+).
	val, err := readProcStatusField("NoNewPrivs")
	if err != nil {
		// Older kernels don't expose this field — treat as inconclusive.
		t.Skipf("NoNewPrivs not in /proc/self/status (kernel < 4.10?): %v", err)
	}
	// Under the systemd unit with NoNewPrivileges=true this should be 1.
	// In regular test runs it's typically 0, so we only enforce this when
	// the daemon is explicitly running under the hardened unit.
	if os.Getenv("WITNESS_HARDENED") != "1" {
		t.Skipf("NoNewPrivs=%d — set WITNESS_HARDENED=1 to enforce this check", val)
	}
	if val != 1 {
		t.Errorf("NoNewPrivs = %d, want 1 — set NoNewPrivileges=true in the systemd unit", val)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func readCapEff() (uint64, error) {
	return readProcStatusField("CapEff")
}

func readProcStatusField(field string) (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prefix := field + ":"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		hexVal := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		return strconv.ParseUint(hexVal, 16, 64)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("field %q not found in /proc/self/status", field)
}
