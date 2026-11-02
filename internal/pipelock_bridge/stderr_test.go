package pipelock_bridge

import "testing"

// Captured from pipelock v3.5.0's stderr on the OptiPlex test box,
// 2026-10-31 (witness log seq 4917–4943), in the order it was written.
func TestStderrLevelsRealStartup(t *testing.T) {
	cases := []struct{ line, want string }{
		{"Pipelock stopped.", "INFO"},
		{"WARNING: tls_interception: TLS interception is disabled while the forward proxy accepts CONNECT tunnels.", "WARN"},
		{"  Receipts: ERROR - chain could not be resumed: reading existing evidence file evidence-proxy-196.jsonl: parsing evidence tail entry: line 1", "ERROR"},
		{"            Receipt emission is DISABLED until resolved. If the flight-recorder", "ERROR"},
		{"            signing key was rotated, the prior chain is sealed under the old key;", "ERROR"},
		{"            a corrupt or tampered evidence tail fails closed. Inspect the evidence", "ERROR"},
		{"            directory and the configured signing_key_path.", "ERROR"},
		{"  Receipts: v2 proxy_decision dual-emit enabled", "INFO"},
		{"  Recorder: /var/lib/witness/.witness/primary/pipelock-evidence (flight recorder enabled)", "INFO"},
		{"WARNING: running outside a container - consider using Docker/Podman for network isolation", "WARN"},
		{"Pipelock v0.0.0-dev.20260901.gca05ed06f360 starting", "INFO"},
		{"  Check:  mode=audit listeners=fetch=127.0.0.1:8889,forward=enabled allowlist=0 dlp_patterns=65 checks=19 entropy=on; run `pipelock explain` to see why a request was blocked", "INFO"},
		{"  Mode:   audit", "INFO"},
		{"  Listen: 127.0.0.1:8889", "INFO"},
		{"  Fetch:  http://127.0.0.1:8889/fetch?url=<url>", "INFO"},
		{"  Health: http://127.0.0.1:8889/health", "INFO"},
		{"  Stats:  http://127.0.0.1:8889/stats", "INFO"},
		{"  Proxy:  HTTP/HTTPS forward proxy enabled (CONNECT + absolute-URI)", "INFO"},
		{"  Config: /var/lib/witness/.witness/primary/pipelock.yaml (hot-reload enabled, SIGHUP to reload)", "INFO"},
	}
	c := &stderrLevels{}
	for _, tc := range cases {
		if got := c.level(tc.line); got != tc.want {
			t.Errorf("level(%q) = %s, want %s", tc.line, got, tc.want)
		}
	}
}

// Lines that are not part of the known banner must never be quieted.
func TestStderrLevelsUnknownStaysLoud(t *testing.T) {
	cases := []struct{ line, want string }{
		{`Error: loading config: yaml: line 3: mapping values are not allowed`, "ERROR"},
		{`panic: runtime error: invalid memory address or nil pointer dereference`, "ERROR"},
		{`goroutine 1 [running]:`, "WARN"},
		{`fatal error: concurrent map writes`, "ERROR"},
		{`something pipelock has never printed before`, "WARN"},
		{`  lowercase: not a banner field`, "WARN"},
		{`  Listen: bind: ERROR address already in use`, "ERROR"},
	}
	for _, tc := range cases {
		c := &stderrLevels{}
		if got := c.level(tc.line); got != tc.want {
			t.Errorf("level(%q) = %s, want %s", tc.line, got, tc.want)
		}
	}
}

// A deeply indented line takes the level of the line it continues, so a
// continued banner field stays INFO and a continued warning stays WARN.
func TestStderrLevelsContinuationInherits(t *testing.T) {
	c := &stderrLevels{}
	c.level("WARNING: something to look at")
	if got := c.level("        more detail about it"); got != "WARN" {
		t.Errorf("continuation of WARN = %s, want WARN", got)
	}
	c.level("  Mode:   audit")
	if got := c.level("        continued field"); got != "INFO" {
		t.Errorf("continuation of INFO = %s, want INFO", got)
	}
	// An ERROR inside a continuation is never lowered.
	if got := c.level("        but ERROR here"); got != "ERROR" {
		t.Errorf("ERROR in continuation = %s, want ERROR", got)
	}
}
