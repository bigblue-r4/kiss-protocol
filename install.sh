#!/usr/bin/env bash
# install.sh — SGAIL Labs Harborlight Firewall installer
#
# Installs Pipelock, then the witness CLI, then runs genesis init.
# Requires: Go version declared in the co-located go.mod; git for build VCS stamping.
# Run as root or with sudo for full three-tier backup support.
#
# Usage:
#   sudo ./install.sh                   # Linux: hardened service under its own user
#   ./install.sh                        # macOS
#   ./install.sh --pipelock-version v3.8.0  # exact release override

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

PIPELOCK_VERSION="${PIPELOCK_VERSION-v3.8.0}"
PIPELOCK_REPO="github.com/luckyPipewrench/pipelock/cmd/pipelock"

INSTALL_DIR="/usr/local/bin"


# ── Parse args ──────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pipelock-version)
            [[ $# -ge 2 ]] || { echo '--pipelock-version requires vX.Y.Z' >&2; exit 1; }
            PIPELOCK_VERSION=$2
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

# Reject moving refs and malformed overrides before any installation side effects.
[[ "$PIPELOCK_VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || \
    fatal "Pipelock version must be an exact vX.Y.Z release (not latest or a branch)."

# Only complete, operator-selected checkouts/source bundles are supported.
# Release blob signatures do not cover the helper/unit/soul, so a standalone
# script cannot authenticate them. Refuse before installing even Pipelock.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for bundled in go.mod go.sum cmd/witness/main.go payload/witness/default-soul.toml \
    packaging/witness-service.sh packaging/systemd/witness.service \
    packaging/launchd/ai.sgail.harborlight.witness.plist; do
    [[ -f "$SCRIPT_DIR/$bundled" ]] || fatal \
        "Missing co-located $bundled; run install.sh from a clone or release bundle. Standalone downloads are not verified."
done

# ── Preflight ────────────────────────────────────────────────────────────────
info "Checking prerequisites…"
require go
require git  # go build records VCS metadata when installing from a Git checkout.

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED=$(awk '$1 == "go" {print $2; exit}' "$SCRIPT_DIR/go.mod")
[[ "$REQUIRED" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || fatal "Missing or invalid Go version in go.mod."
if [[ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -1)" != "$REQUIRED" ]]; then
    fatal "Go $REQUIRED+ required (found $GO_VERSION)"
fi

# ── Step 1: Install Pipelock ─────────────────────────────────────────────────
info "Installing Pipelock…"
if command -v pipelock &>/dev/null; then
    INSTALLED_PIPELOCK=$(pipelock version 2>/dev/null || true)
    INSTALLED_VERSION=unknown
    if [[ "$INSTALLED_PIPELOCK" =~ (^|[[:space:]])v?([0-9]+\.[0-9]+\.[0-9]+)($|[[:space:]]) ]]; then
        INSTALLED_VERSION="v${BASH_REMATCH[2]}"
    fi
    info "Pipelock already installed: ${INSTALLED_PIPELOCK:-unknown version} (pinned $PIPELOCK_VERSION; skipping install)"
    if [[ "$INSTALLED_VERSION" != "$PIPELOCK_VERSION" ]]; then
        warn "Installed Pipelock $INSTALLED_VERSION does not match pinned $PIPELOCK_VERSION; keeping the existing binary."
    fi
else
    GOBIN="$INSTALL_DIR" go install "${PIPELOCK_REPO}@${PIPELOCK_VERSION}" \
        || fatal "Failed to install Pipelock. Check your internet connection and Go setup."
    info "Pipelock installed → $INSTALL_DIR/pipelock"
fi

# ── Step 2: Build and install witness CLI ────────────────────────────────────
info "Building SGAIL Labs Harborlight Firewall witness CLI…"

# Build this checkout's revision; never combine a registry @latest witness
# with packaging downloaded from main. Do not rewrite the selected module files.
cd "$SCRIPT_DIR"
go build -mod=readonly -trimpath -ldflags="-s -w" -o witness ./cmd/witness
install -m 0755 witness "$INSTALL_DIR/witness"
rm -f witness
info "witness CLI built from co-located source → $INSTALL_DIR/witness"
SOUL_SRC="$SCRIPT_DIR/payload/witness/default-soul.toml"

# ── Step 4: Set up and start the witness ─────────────────────────────────────
if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl &>/dev/null; then
    [[ "$(id -u)" -eq 0 ]] || fatal "Run with sudo: the witness service runs under its own 'witness' user."
    info "Setting up the hardened witness service…"
    UNIT_SRC="$SCRIPT_DIR/packaging/systemd/witness.service"
    # shellcheck source=packaging/witness-service.sh
    source "$SCRIPT_DIR/packaging/witness-service.sh"
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
