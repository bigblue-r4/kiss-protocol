#!/usr/bin/env bash
# install.sh — SGAIL Labs Harborlight Firewall installer
#
# Installs Pipelock, then the witness CLI, then runs genesis init.
# Requires: Go 1.21+, git, curl
# Run as root or with sudo for full three-tier backup support.
#
# Usage:
#   sudo ./install.sh                   # Linux: hardened service under its own user
#   ./install.sh                        # macOS

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


# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
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

# ── Step 3: Bundled files (soul, hardened unit) ──────────────────────────────
RAW="https://raw.githubusercontent.com/bigblue-r4/kiss-protocol/main"
fetch_if_missing() {   # $1 = path in this repo; prints a local path to it
    if [[ -f "$SCRIPT_DIR/$1" ]]; then echo "$SCRIPT_DIR/$1"; return; fi
    local tmp; tmp=$(mktemp)
    curl -fsSL "$RAW/$1" -o "$tmp" || fatal "Could not fetch $1. Clone the repo and run install.sh from it."
    echo "$tmp"
}
SOUL_SRC=$(fetch_if_missing payload/witness/default-soul.toml)

# ── Step 4: Set up and start the witness ─────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &>/dev/null; then
    [[ "$(id -u)" -eq 0 ]] || fatal "Run with sudo: the witness service runs under its own 'witness' user."
    info "Setting up the hardened witness service…"
    UNIT_SRC=$(fetch_if_missing packaging/systemd/witness.service)
    # shellcheck source=packaging/witness-service.sh
    source "$(fetch_if_missing packaging/witness-service.sh)"
    witness_service_setup "$INSTALL_DIR/witness" "$SOUL_SRC" "$UNIT_SRC" start
    info "Check status: systemctl status witness"

elif [[ "$(uname -s)" == "Darwin" ]]; then
    mkdir -p "$HOME/.witness"
    if [[ ! -f "$HOME/.witness/soul.toml" ]]; then
        cp "$SOUL_SRC" "$HOME/.witness/soul.toml" && chmod 0400 "$HOME/.witness/soul.toml"
    fi
    if [[ -f "$HOME/.witness/primary/genesis.enc" ]]; then
        info "Genesis already taken on this machine — kept."
    else
        "$INSTALL_DIR/witness" init
    fi
    PLIST_SRC="$SCRIPT_DIR/packaging/launchd/ai.sgail.harborlight.witness.plist"
    PLIST_DST="/Library/LaunchDaemons/ai.sgail.harborlight.witness.plist"
    if [[ -f "$PLIST_SRC" ]]; then
        info "Installing hardened launchd daemon → $PLIST_DST"
        mkdir -p /var/log/witness
        cp "$PLIST_SRC" "$PLIST_DST"
        chmod 0644 "$PLIST_DST"
        chown root:wheel "$PLIST_DST"
        launchctl load -w "$PLIST_DST"
        info "LaunchDaemon loaded."
    else
        warn "packaging/launchd plist not found — service not installed."
    fi
else
    warn "Could not detect init system. Start the daemon manually: witness start"
fi

# ── Step 8: Install desktop file ─────────────────────────────────────────────
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
echo "╚═══════════════════════════════════════════════════════════╝"
