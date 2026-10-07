#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  SGAIL LABS HARBORLIGHT FIREWALL — USB SETUP SCRIPT
#  Run this on a CLEAN machine BEFORE installing any AI agents.
#
#  Usage:
#    sudo bash usb-setup.sh
#    sudo bash usb-setup.sh --offline   (uses bundled source from USB)
#
#  What it does:
#    1. Installs system dependencies (Go, git, build tools)
#    2. Installs Pipelock
#    3. Installs the SGAIL Labs Harborlight Firewall witness CLI
#    4. Runs genesis init (captures clean machine state)
#    5. Installs the hardened systemd service (runs as user 'witness') + desktop shortcuts
#
#  IMPORTANT: Step 4 must happen before any AI agent is installed.
#  This script enforces that order.
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
GO_VERSION="1.22.3"
GO_ARCH="linux-amd64"
GO_URL="https://go.dev/dl/go${GO_VERSION}.${GO_ARCH}.tar.gz"

PIPELOCK_REPO="github.com/luckyPipewrench/pipelock/cmd/pipelock@latest"
WITNESS_REPO="https://github.com/bigblue-r4/kiss-protocol.git"
WITNESS_SUBDIR="."

INSTALL_BIN="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
DESKTOP_DIR=""          # resolved later
OFFLINE=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --offline) OFFLINE=true; shift ;;
        *)         echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[setup] WARN:${NC} $*"; }
fatal() { echo -e "${RED}[setup] FATAL:${NC} $*" >&2; exit 1; }
hr()    { echo -e "${BOLD}────────────────────────────────────────────────────${NC}"; }

# Must run as root
[[ $EUID -eq 0 ]] || fatal "Run as root: sudo bash $0"

# Resolve real user (not root) for desktop/home dir setup
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
REAL_HOME=$(eval echo "~$REAL_USER")

hr
echo -e "${BOLD}  SGAIL LABS HARBORLIGHT FIREWALL SETUP${NC}"
echo    "  Machine-state witness. Install before any AI agent."
hr
echo

# ── Step 0: OS check ─────────────────────────────────────────────────────────
info "Checking OS…"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "Detected: $PRETTY_NAME"
else
    warn "Cannot detect OS. Proceeding anyway."
fi

# ── Step 1: System dependencies ──────────────────────────────────────────────
info "Installing system dependencies…"
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq git curl build-essential ca-certificates
elif command -v dnf &>/dev/null; then
    dnf install -y -q git curl gcc make ca-certificates
elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm git curl base-devel
else
    warn "Unknown package manager — ensure git, curl, gcc are installed."
fi

# ── Step 2: Install Go ────────────────────────────────────────────────────────
install_go() {
    info "Installing Go ${GO_VERSION}…"
    curl -fsSL "$GO_URL" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go   "$INSTALL_BIN/go"
    ln -sf /usr/local/go/bin/gofmt "$INSTALL_BIN/gofmt"
    info "Go $(go version) installed."
}

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    REQUIRED_GO="1.21"
    if [[ "$(printf '%s\n' "$REQUIRED_GO" "$CURRENT_GO" | sort -V | head -1)" != "$REQUIRED_GO" ]]; then
        warn "Go $CURRENT_GO is too old (need $REQUIRED_GO+). Upgrading…"
        install_go
    else
        info "Go $CURRENT_GO already installed."
    fi
else
    install_go
fi

export PATH="/usr/local/go/bin:$PATH"

# ── Step 3: Install Pipelock ──────────────────────────────────────────────────
info "Installing Pipelock…"
if command -v pipelock &>/dev/null; then
    info "Pipelock already present: $(pipelock version 2>/dev/null || echo 'installed')"
else
    if [[ "$OFFLINE" == "true" ]]; then
        # Build from USB-bundled source
        USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -d "$USB_DIR/pipelock" ]]; then
            info "Building Pipelock from USB bundle…"
            cd "$USB_DIR/pipelock"
            GOBIN="$INSTALL_BIN" go install ./cmd/pipelock/
            cd -
        else
            warn "Offline mode: no pipelock/ directory on USB. Skipping Pipelock."
        fi
    else
        GOBIN="$INSTALL_BIN" go install "$PIPELOCK_REPO" \
            || warn "Pipelock install failed — continuing without it."
    fi
fi

# ── Step 4: Get witness source ────────────────────────────────────────────────
info "Getting SGAIL Labs Harborlight Firewall source…"
BUILD_DIR="/tmp/witness-build-$$"
mkdir -p "$BUILD_DIR"
trap 'rm -rf "$BUILD_DIR"' EXIT

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$OFFLINE" == "true" ]] || [[ -f "$USB_DIR/go.mod" ]]; then
    # Running from inside the repo (USB has the source)
    info "Using local source from USB…"
    cp -r "$USB_DIR" "$BUILD_DIR/harborlight-firewall"
    WITNESS_SRC="$BUILD_DIR/harborlight-firewall"
elif [[ -d "$USB_DIR/../go.mod" ]]; then
    cp -r "$USB_DIR/.." "$BUILD_DIR/harborlight-firewall"
    WITNESS_SRC="$BUILD_DIR/harborlight-firewall"
else
    # Pull from GitHub
    info "Cloning from GitHub…"
    git clone --depth=1 "$WITNESS_REPO" "$BUILD_DIR/kiss-protocol"
    WITNESS_SRC="$BUILD_DIR/kiss-protocol/$WITNESS_SUBDIR"
fi

# ── Step 5: Build and install witness ─────────────────────────────────────────
info "Building witness…"
cd "$WITNESS_SRC"
go mod tidy
go build -trimpath -ldflags="-s -w" -o "$INSTALL_BIN/witness" ./cmd/witness/
cd -
info "witness installed → $INSTALL_BIN/witness"

# ── Step 6: Genesis init ──────────────────────────────────────────────────────
hr
echo
echo -e "${BOLD}  TAKING GENESIS SNAPSHOT${NC}"
echo    "  This captures the machine state BEFORE any AI agent is installed."
echo    "  This is the cryptographic baseline everything is measured against."
echo
hr
echo

# shellcheck source=packaging/witness-service.sh
source "$WITNESS_SRC/packaging/witness-service.sh"
witness_service_setup "$INSTALL_BIN/witness" \
    "$WITNESS_SRC/payload/witness/default-soul.toml" \
    "$WITNESS_SRC/packaging/systemd/witness.service"

# ── Step 9: Desktop shortcut ──────────────────────────────────────────────────
DESKTOP_DIR="$REAL_HOME/Desktop"
if [[ -d "$DESKTOP_DIR" ]]; then
    info "Creating desktop folder…"
    DEST="$DESKTOP_DIR/SGAIL Labs Harborlight Firewall"
    mkdir -p "$DEST"

    cat > "$DEST/▶ Start Witness.sh" <<'SH'
#!/bin/bash
echo "Starting SGAIL Labs Harborlight Firewall witness service..."
sudo systemctl start witness && systemctl --no-pager status witness | head -5
read -r -p "Press Enter to close..."
SH

    cat > "$DEST/📊 Status.sh" <<'SH'
#!/bin/bash
echo "════════════════════════════════════"
echo "  SGAIL HARBORLIGHT STATUS"
echo "════════════════════════════════════"
sudo -u witness env HOME=/var/lib/witness /usr/local/bin/witness status
echo
echo "Press Enter to close..."
read
SH

    cat > "$DEST/⏹ Stop Witness.sh" <<'SH'
#!/bin/bash
sudo systemctl stop witness && echo "Witness stopped (the stop is recorded in its log)." || echo "Not running."
sleep 2
SH

    cat > "$DEST/📁 Show Config.sh" <<'SH'
#!/bin/bash
# The witness's files belong to its own user; this shows the config read-only.
echo "Config: /var/lib/witness/.witness/config.json"
sudo cat /var/lib/witness/.witness/config.json
echo
read -r -p "Press Enter to close..."
SH

    cat > "$DEST/README.txt" <<README
SGAIL LABS HARBORLIGHT FIREWALL
═══════════════════════════════
Install before any AI agent. Always.

Order:
  1. Clean OS
  2. This script (witness init)
  3. Install agents (Claude, etc.)
  4. sudo systemctl start witness

Project: https://github.com/bigblue-r4/kiss-protocol
README

    chmod +x "$DEST/"*.sh
    chown -R "$REAL_USER:$REAL_USER" "$DEST"
    info "Desktop folder created → $DEST"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo
hr
echo -e "${BOLD}  SETUP COMPLETE${NC}"
hr
echo
echo "  Genesis has been taken. This machine is now the baseline."
echo
echo -e "  ${YELLOW}NEXT STEPS:${NC}"
echo    "    1. Install your AI agents (Claude Code, etc.)"
echo    "    2. Start the witness daemon:"
echo    "         sudo systemctl start witness"
echo    "    3. Set \"mirror_url\" in /var/lib/witness/.witness/config.json (see docs/mirror-setup.md);"
echo    "       until then every start records CRITICAL mirror_not_configured."
echo
echo    "  sudo -u witness env HOME=/var/lib/witness witness status   — genesis trust level + log"
echo
hr
