// Package sandbox documents the runtime privilege posture of the Witness daemon.
// Actual capability dropping and syscall filtering is performed by the
// systemd unit (packaging/systemd/witness.service). This package contains
// tests that verify the process-level invariants hold when the daemon runs
// under that unit or in any other confined environment.
package sandbox
