#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  SGAIL LABS HARBORLIGHT FIREWALL — USB SETUP SCRIPT
#  Run this on a CLEAN machine BEFORE installing any AI agents.
#
#  Usage:
#    sudo bash usb-setup.sh
#    sudo bash usb-setup.sh --sgail https://your-server-ip:8443
#    sudo bash usb-setup.sh --offline   (uses bundled source from USB)
#
#  What it does:
#    1. Installs system dependencies (Go, git, build tools)
#    2. Installs Pipelock
#    3. Installs the SGAIL Labs Harborlight Firewall witness CLI
#    4. Runs genesis init (captures clean machine state)
#    5. Installs systemd service + desktop shortcut
#    6. Optionally configures SGAIL remote sync
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
SGAIL_ENDPOINT=""
OFFLINE=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sgail)   SGAIL_ENDPOINT="$2"; shift 2 ;;
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
rm -rf "$BUILD_DIR"

# ── Step 6: Genesis init ──────────────────────────────────────────────────────
hr
echo
echo -e "${BOLD}  TAKING GENESIS SNAPSHOT${NC}"
echo    "  This captures the machine state BEFORE any AI agent is installed."
echo    "  This is the cryptographic baseline everything is measured against."
echo
hr
echo

"$INSTALL_BIN/witness" init

# ── Step 7: Optional SGAIL sync config ────────────────────────────────────────
if [[ -n "$SGAIL_ENDPOINT" ]]; then
    info "Configuring SGAIL sync → $SGAIL_ENDPOINT"
    "$INSTALL_BIN/witness" enable-sync \
        --endpoint "$SGAIL_ENDPOINT" \
        ${WITNESS_SGAIL_TOKEN:+--token "$WITNESS_SGAIL_TOKEN"}
fi

# ── Step 8: Systemd service ───────────────────────────────────────────────────
info "Installing systemd service…"
cat > "$SYSTEMD_DIR/witness.service" <<SERVICE
[Unit]
Description=SGAIL Labs Harborlight Firewall — machine-state monitor (install before AI agents)
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/witness start
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable witness.service
info "Systemd service installed and enabled (will start on next boot)."
info "To start now: systemctl start witness"

# ── Step 9: Desktop shortcut ──────────────────────────────────────────────────
DESKTOP_DIR="$REAL_HOME/Desktop"
if [[ -d "$DESKTOP_DIR" ]]; then
    info "Creating desktop folder…"
    DEST="$DESKTOP_DIR/SGAIL Labs Harborlight Firewall"
    mkdir -p "$DEST"

    cat > "$DEST/▶ Start Witness.sh" <<'SH'
#!/bin/bash
echo "Starting SGAIL Labs Harborlight Firewall witness daemon..."
witness start
SH

    cat > "$DEST/📊 Status.sh" <<'SH'
#!/bin/bash
echo "════════════════════════════════════"
echo "  SGAIL HARBORLIGHT STATUS"
echo "════════════════════════════════════"
witness status
echo
echo "Press Enter to close..."
read
SH

    cat > "$DEST/⏹ Stop Witness.sh" <<'SH'
#!/bin/bash
pkill -TERM witness 2>/dev/null && echo "Shutdown signal sent — death broadcast fired." || echo "Not running."
sleep 1
SH

    cat > "$DEST/📁 Open Config.sh" <<SH
#!/bin/bash
xdg-open /home/$REAL_USER/.witness 2>/dev/null || nautilus /home/$REAL_USER/.witness 2>/dev/null || true
SH

    cat > "$DEST/README.txt" <<README
SGAIL LABS HARBORLIGHT FIREWALL
═══════════════════════════════
Install before any AI agent. Always.

Order:
  1. Clean OS
  2. This script (witness init)
  3. Install agents (Claude, etc.)
  4. witness start

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
echo    "         systemctl start witness"
echo    "         — or —"
echo    "         witness start"
echo
if [[ -n "$SGAIL_ENDPOINT" ]]; then
echo    "    3. Remote sync configured → $SGAIL_ENDPOINT"
fi
echo    "  witness status   — check genesis trust level + log"
echo    "  witness start    — start continuous monitoring"
echo
hr
