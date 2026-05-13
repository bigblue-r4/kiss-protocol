#!/usr/bin/env bash
# install.sh — SGAIL Labs Harborlight Firewall installer
#
# Installs Pipelock, then the witness CLI, then runs genesis init.
# Requires: Go 1.21+, git, curl
# Run as root or with sudo for full three-tier backup support.
#
# Usage:
#   ./install.sh                        # local install
#   ./install.sh --sgail https://...    # with SGAIL endpoint

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
#  INSTALL ORDER MATTERS.
#
#  This script must run on a CLEAN machine BEFORE any AI agent is installed.
#  The genesis snapshot it creates is the cryptographic proof that the witness
#  was established before any agent had access.
#
#  Correct order:
#    1. Clean OS install
#    2. Run this script  ← you are here
#    3. Install Claude Code, OpenClaw, or any other agent
#    4. witness start
#
#  If agents are already installed, the genesis will be marked COMPROMISED
#  and you will be asked to confirm before proceeding.
# ══════════════════════════════════════════════════════════════════════════════

PIPELOCK_REPO="github.com/luckyPipewrench/pipelock/cmd/pipelock@latest"
WITNESS_REPO="github.com/bigblue-r4/kiss-protocol/cmd/witness"

INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

SGAIL_ENDPOINT=""

# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sgail)
            SGAIL_ENDPOINT="$2"
            shift 2
            ;;
        *)
            echo "Unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────
info()  { echo "[install] $*"; }
warn()  { echo "[install] WARN: $*" >&2; }
fatal() { echo "[install] FATAL: $*" >&2; exit 1; }

require() {
    command -v "$1" &>/dev/null || fatal "'$1' is required but not installed."
}

# ── Preflight ────────────────────────────────────────────────────────────────
info "Checking prerequisites…"
require go
require git

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED="1.22"
if [[ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -1)" != "$REQUIRED" ]]; then
    fatal "Go $REQUIRED+ required (found $GO_VERSION)"
fi

# ── Step 1: Install Pipelock ─────────────────────────────────────────────────
info "Installing Pipelock…"
if command -v pipelock &>/dev/null; then
    info "Pipelock already installed: $(pipelock version 2>/dev/null || echo 'unknown version')"
else
    GOBIN="$INSTALL_DIR" go install "$PIPELOCK_REPO" \
        || fatal "Failed to install Pipelock. Check your internet connection and Go setup."
    info "Pipelock installed → $INSTALL_DIR/pipelock"
fi

# ── Step 2: Build and install witness CLI ────────────────────────────────────
info "Building SGAIL Labs Harborlight Firewall witness CLI…"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If we're running from the repo, build locally.
if [[ -f "$SCRIPT_DIR/go.mod" ]]; then
    cd "$SCRIPT_DIR"
    go mod tidy
    go build -trimpath -ldflags="-s -w" -o witness ./cmd/witness
    install -m 0755 witness "$INSTALL_DIR/witness"
    rm -f witness
    info "witness CLI built from source → $INSTALL_DIR/witness"
else
    # Fall back to go install from the module registry.
    GOBIN="$INSTALL_DIR" go install "${WITNESS_REPO}@latest" \
        || fatal "Failed to install witness CLI."
    info "witness CLI installed → $INSTALL_DIR/witness"
fi

# ── Step 3: Install soul file ────────────────────────────────────────────────
SOUL_DST="$HOME/.witness/soul.toml"
if [[ -f "$SOUL_DST" ]]; then
    info "Soul file already present — skipping."
else
    mkdir -p "$HOME/.witness"
    # Prefer bundled copy from repo; fall back to fetching from GitHub.
    if [[ -f "$SCRIPT_DIR/payload/witness/default-soul.toml" ]]; then
        cp "$SCRIPT_DIR/payload/witness/default-soul.toml" "$SOUL_DST"
        chmod 0400 "$SOUL_DST"
        info "Soul file installed → $SOUL_DST"
    else
        SOUL_URL="https://raw.githubusercontent.com/bigblue-r4/kiss-protocol/main/payload/witness/default-soul.toml"
        info "Fetching default soul file from GitHub…"
        curl -fsSL "$SOUL_URL" -o "$SOUL_DST" \
            || fatal "Could not fetch soul file. Clone the repo and run install.sh from it."
        chmod 0400 "$SOUL_DST"
        info "Soul file installed → $SOUL_DST"
    fi
fi

# ── Step 4: Genesis init ─────────────────────────────────────────────────────
info "Initializing witness (genesis snapshot)…"
"$INSTALL_DIR/witness" init

# ── Step 5: Optional SGAIL configuration ─────────────────────────────────────
if [[ -n "$SGAIL_ENDPOINT" ]]; then
    info "Configuring SGAIL sync → $SGAIL_ENDPOINT"
    SGAIL_ARGS=(--endpoint "$SGAIL_ENDPOINT")
    if [[ -n "${WITNESS_SGAIL_TOKEN:-}" ]]; then
        SGAIL_ARGS+=(--token "$WITNESS_SGAIL_TOKEN")
    fi
    "$INSTALL_DIR/witness" enable-sync "${SGAIL_ARGS[@]}"
fi

# ── Step 6: Install systemd service (Linux only) ─────────────────────────────
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &>/dev/null; then
    info "Installing systemd service…"
    cat > "$SYSTEMD_DIR/witness.service" <<'SERVICE'
[Unit]
Description=SGAIL Labs Harborlight Firewall — machine-state continuous monitor
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/witness start
Restart=on-failure
RestartSec=5s
# The watchdog subprocess handles SIGKILL; give the main process time for death broadcast.
TimeoutStopSec=15s
# Tighten the environment — the service should not inherit user tokens.
Environment=HOME=/root
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
SERVICE

    # Watchdog gets its own service so it can outlive the main service.
    cat > "$SYSTEMD_DIR/witness-watchdog.service" <<'SERVICE'
[Unit]
Description=SGAIL Labs Harborlight Firewall Watchdog
After=witness.service
BindsTo=witness.service

[Service]
Type=simple
# The main 'witness start' spawns the watchdog itself; this unit is a safety net
# that ensures the watchdog is restarted if it dies independently.
ExecStart=/bin/sleep infinity
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable witness.service
    systemctl start  witness.service
    info "Systemd service enabled and started."
    info "Check status: systemctl status witness"

elif [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: launchd
    PLIST="$HOME/Library/LaunchAgents/ai.sgail.harborlight.witness.plist"
    info "Installing launchd agent → $PLIST"
    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>ai.sgail.harborlight.witness</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/witness</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/tmp/witness.out</string>
    <key>StandardErrorPath</key> <string>/tmp/witness.err</string>
</dict>
</plist>
PLIST
    launchctl load "$PLIST"
    info "launchd agent loaded."
else
    warn "Could not detect init system. Start the daemon manually: witness start"
fi

# ── Step 7: Install desktop file ─────────────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]]; then
    DESKTOP_SRC="$SCRIPT_DIR/witness.desktop"
    if [[ -f "$DESKTOP_SRC" ]]; then
        # System-wide (requires root)
        if [[ -d "/usr/share/applications" ]] && [[ -w "/usr/share/applications" ]]; then
            cp "$DESKTOP_SRC" /usr/share/applications/witness.desktop
            info "Desktop file installed → /usr/share/applications/witness.desktop"
        fi
        # Per-user
        USER_APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
        mkdir -p "$USER_APPS"
        cp "$DESKTOP_SRC" "$USER_APPS/witness.desktop"
        # Copy to desktop if it exists
        if [[ -d "$HOME/Desktop" ]]; then
            cp "$DESKTOP_SRC" "$HOME/Desktop/witness.desktop"
            chmod +x "$HOME/Desktop/witness.desktop"
            info "Desktop shortcut created → $HOME/Desktop/witness.desktop"
        fi
        command -v update-desktop-database &>/dev/null && update-desktop-database "$USER_APPS" 2>/dev/null || true
        info "Desktop entry installed → $USER_APPS/witness.desktop"
    fi
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  SGAIL Labs Harborlight Firewall installed.               ║"
echo "║                                                           ║"
echo "║  witness status        — view current state               ║"
echo "║  witness enable-sync   — opt in to SGAIL Labs sync        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
