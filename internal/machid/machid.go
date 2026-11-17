// Package machid provides a stable, unique machine identifier.
package machid

import (
	"os"
	"os/exec"
	"strings"

	"github.com/bigblue-r4/kiss-protocol/internal/hashutil"
)

// Get returns a stable unique identifier for this machine.
// Priority: /etc/machine-id (Linux) → IOPlatformUUID (macOS) → hostname hash.
func Get() string {
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					return parts[3]
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	return hashutil.SHA256Hex([]byte("witness-fallback:" + hostname))
}
