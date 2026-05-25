#!/usr/bin/env bash
# =============================================================================
# _core.sh — Shared installer logic for Witness + Pipelock
# Sourced by install.command (Mac) and install.sh (Linux)
# OFFLINE ONLY — zero network calls, ever
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payload"
VERIFY_FILE="$SCRIPT_DIR/VERIFY.txt"

TOOLS=("witness" "pipelock")
DEFAULT_INSTALL_DIR="$HOME/.local/bin"
SYSTEM_INSTALL_DIR="/usr/local/bin"
INSTALL_DIR=""

LOG_FILE="/tmp/sgail-harborlight-install-$(date +%Y%m%d-%H%M%S).log"

# ── Logging ───────────────────────────────────────────────────────────────────
log()  { echo -e "$*" | tee -a "$LOG_FILE"; }
info() { log "${CYAN}  →${RESET} $*"; }
ok()   { log "${GREEN}  ✓${RESET} $*"; }
warn() { log "${YELLOW}  ⚠${RESET} $*"; }
fail() { log "${RED}  ✗ ERROR:${RESET} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e "${BOLD}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║  SGAIL LABS HARBORLIGHT FIREWALL         ║"
  echo "  ║     Witness  +  Pipelock                 ║"
  echo "  ║     Offline Install — No Internet Needed ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${RESET}"
}

# ── Detect OS + Arch ──────────────────────────────────────────────────────────
detect_platform() {
  OS=""
  ARCH=""

  case "$(uname -s)" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    *)      fail "Unsupported OS: $(uname -s). Only macOS and Linux are supported." ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) fail "Unsupported architecture: $(uname -m)." ;;
  esac

  PLATFORM="${OS}-${ARCH}"
  info "Detected platform: ${BOLD}$PLATFORM${RESET}"
}

# ── Verify checksums ──────────────────────────────────────────────────────────
verify_checksums() {
  info "Verifying payload integrity..."

  [[ -f "$VERIFY_FILE" ]] || fail "VERIFY.txt not found. USB may be corrupted or incomplete."

  FAIL_COUNT=0
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    expected_hash=$(echo "$line" | awk '{print $1}')
    rel_path=$(echo "$line" | awk '{print $2}')
    full_path="$SCRIPT_DIR/$rel_path"

    if [[ ! -f "$full_path" ]]; then
      warn "Missing file: $rel_path"
      (( FAIL_COUNT++ )) || true
      continue
    fi

    if command -v sha256sum &>/dev/null; then
      actual_hash=$(sha256sum "$full_path" | awk '{print $1}')
    elif command -v shasum &>/dev/null; then
      actual_hash=$(shasum -a 256 "$full_path" | awk '{print $1}')
    else
      fail "No SHA256 tool found (sha256sum or shasum). Cannot verify integrity."
    fi

    if [[ "$actual_hash" != "$expected_hash" ]]; then
      warn "CHECKSUM MISMATCH: $rel_path"
      warn "  Expected: $expected_hash"
      warn "  Got:      $actual_hash"
      (( FAIL_COUNT++ )) || true
    fi
  done < "$VERIFY_FILE"

  if [[ $FAIL_COUNT -gt 0 ]]; then
    fail "$FAIL_COUNT file(s) failed integrity check. Do not install from this USB. Re-copy from your build machine."
  fi

  ok "All payload files verified."
}

# ── Prompt install location ───────────────────────────────────────────────────
choose_install_dir() {
  echo ""
  echo -e "${BOLD}Where should the tools be installed?${RESET}"
  echo "  [1] User only  → $HOME/.local/bin  (no sudo needed)  ← default"
  echo "  [2] System     → /usr/local/bin    (requires sudo)"
  echo ""
  read -rp "  Choice [1]: " choice
  choice="${choice:-1}"

  case "$choice" in
    1) INSTALL_DIR="$DEFAULT_INSTALL_DIR" ;;
    2) INSTALL_DIR="$SYSTEM_INSTALL_DIR"
       if ! sudo -v 2>/dev/null; then
         fail "sudo access required for system-wide install. Run as a user with sudo privileges."
       fi ;;
    *) warn "Invalid choice, defaulting to user install."
       INSTALL_DIR="$DEFAULT_INSTALL_DIR" ;;
  esac

  info "Install location: ${BOLD}$INSTALL_DIR${RESET}"
}

# ── Main install prompt ───────────────────────────────────────────────────────
confirm_install() {
  echo ""
  echo -e "${BOLD}  This will install:${RESET}"
  for tool in "${TOOLS[@]}"; do
    echo "    • $tool"
  done
  echo ""
  read -rp "  Install Witness and Pipelock? [Y/n]: " answer
  answer="${answer:-Y}"
  case "$answer" in
    [Yy]*) ;;
    *) log "Installation cancelled."; exit 0 ;;
  esac
}

# ── Install a single tool ─────────────────────────────────────────────────────
install_tool() {
  local tool="$1"
  local binary_src="$PAYLOAD_DIR/$tool/${tool}-${PLATFORM}"
  local binary_dst="$INSTALL_DIR/$tool"
  local config_src="$PAYLOAD_DIR/$tool/default-config.toml"
  local config_dir="$HOME/.$tool"
  local config_dst="$config_dir/config.toml"

  # ── Check binary exists for this platform
  if [[ ! -f "$binary_src" ]]; then
    fail "No binary found for $tool on $PLATFORM at: $binary_src\nCheck your payload bundle includes this platform."
  fi

  # ── Create install dir
  if [[ "$INSTALL_DIR" == "$DEFAULT_INSTALL_DIR" ]]; then
    mkdir -p "$INSTALL_DIR"
  else
    sudo mkdir -p "$INSTALL_DIR"
  fi

  # ── Copy binary
  if [[ "$INSTALL_DIR" == "$DEFAULT_INSTALL_DIR" ]]; then
    cp "$binary_src" "$binary_dst"
    chmod +x "$binary_dst"
  else
    sudo cp "$binary_src" "$binary_dst"
    sudo chmod +x "$binary_dst"
  fi
  ok "Installed binary: $binary_dst"

  # ── Create config dir (never overwrite existing config)
  mkdir -p "$config_dir"
  if [[ -f "$config_dst" ]]; then
    warn "Config already exists, skipping: $config_dst"
  else
    if [[ -f "$config_src" ]]; then
      cp "$config_src" "$config_dst"
      ok "Created default config: $config_dst"
    else
      warn "No default config found for $tool, skipping config creation."
    fi
  fi

  # ── Witness-specific: install soul file
  if [[ "$tool" == "witness" ]]; then
    local soul_src="$PAYLOAD_DIR/witness/default-soul.toml"
    local soul_dst="$config_dir/soul.toml"
    if [[ -f "$soul_dst" ]]; then
      warn "Soul file already exists, skipping: $soul_dst"
    elif [[ -f "$soul_src" ]]; then
      cp "$soul_src" "$soul_dst"
      ok "Installed soul file: $soul_dst"
    fi
  fi
}

# ── Add to PATH ───────────────────────────────────────────────────────────────
update_path() {
  if [[ "$INSTALL_DIR" == "$SYSTEM_INSTALL_DIR" ]]; then
    # System bin is almost always already in PATH
    return
  fi

  local path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
  local added=false

  for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile"; do
    if [[ -f "$rc" ]] && ! grep -q ".local/bin" "$rc" 2>/dev/null; then
      echo "" >> "$rc"
      echo "# Added by SGAIL Labs Harborlight installer" >> "$rc"
      echo "$path_line" >> "$rc"
      ok "Added ~/.local/bin to PATH in $rc"
      added=true
    fi
  done

  if [[ "$added" == false ]]; then
    info "~/.local/bin already in PATH (or no shell rc files found)."
  fi

  # Make available in this session too
  export PATH="$HOME/.local/bin:$PATH"
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${GREEN}${BOLD}  ══════════════════════════════════════${RESET}"
  echo -e "${GREEN}${BOLD}    Files installed. Integrity verified.${RESET}"
  echo -e "${GREEN}${BOLD}  ══════════════════════════════════════${RESET}"
  echo ""
  for tool in "${TOOLS[@]}"; do
    echo -e "    ${GREEN}✓${RESET} $tool  →  $INSTALL_DIR/$tool"
  done
  echo ""
  info "Full install log saved to: $LOG_FILE"
  echo ""
  echo "  ── NEXT STEP ───────────────────────────────"
  echo "  Before using Witness, you must initialize it:"
  echo ""
  echo "    witness init"
  echo ""
  echo "  This creates your agent's identity on this"
  echo "  machine. Run it once, deliberately."
  echo "  Do not skip it. Do not run it twice."
  echo "  ────────────────────────────────────────────"
  echo ""
}

# ── Dedicated system user ─────────────────────────────────────────────────────
# Creates a locked-down system account for the witness daemon.
# Linux: witness / no shell / home /var/lib/witness
# macOS: _witness (underscore prefix follows Apple convention)
create_witness_user() {
  if [[ "$OS" == "linux" ]]; then
    if id witness &>/dev/null 2>&1; then
      info "System user 'witness' already exists."
      return
    fi
    if ! sudo useradd \
        --system \
        --no-create-home \
        --home-dir /var/lib/witness \
        --shell /bin/false \
        --comment "SGAIL Harborlight Witness daemon" \
        witness 2>/dev/null; then
      warn "Could not create system user 'witness' — continuing without dedicated user."
      return
    fi
    sudo mkdir -p /var/lib/witness
    sudo chown witness:witness /var/lib/witness
    sudo chmod 0700 /var/lib/witness
    ok "Created system user 'witness' (home: /var/lib/witness)"

  elif [[ "$OS" == "macos" ]]; then
    if dscl . -read /Users/_witness &>/dev/null 2>&1; then
      info "System user '_witness' already exists."
      return
    fi
    # Find an unused UID in the 400-499 range (Apple reserved system range)
    local uid=450
    while dscl . -search /Users UniqueID "$uid" 2>/dev/null | grep -q UniqueID; do
      (( uid++ ))
    done
    sudo dscl . -create /Groups/_witness
    sudo dscl . -create /Groups/_witness PrimaryGroupID "$uid"
    sudo dscl . -create /Groups/_witness RealName "SGAIL Harborlight Witness"

    sudo dscl . -create /Users/_witness
    sudo dscl . -create /Users/_witness UniqueID "$uid"
    sudo dscl . -create /Users/_witness PrimaryGroupID "$uid"
    sudo dscl . -create /Users/_witness UserShell /usr/bin/false
    sudo dscl . -create /Users/_witness RealName "SGAIL Harborlight Witness"
    sudo dscl . -create /Users/_witness NFSHomeDirectory /var/lib/witness
    sudo dscl . -create /Users/_witness IsHidden 1

    sudo mkdir -p /var/lib/witness
    sudo chown _witness:_witness /var/lib/witness
    sudo chmod 0700 /var/lib/witness
    ok "Created system user '_witness' (UID $uid, home: /var/lib/witness)"
  fi
}

# ── Service unit installation ─────────────────────────────────────────────────
install_service_unit() {
  if [[ "$OS" == "linux" ]] && command -v systemctl &>/dev/null; then
    local unit_src="$SCRIPT_DIR/packaging/systemd/witness.service"
    local unit_dst="/etc/systemd/system/witness.service"

    if [[ ! -f "$unit_src" ]]; then
      warn "Hardened unit not found at $unit_src — falling back to inline service."
      install_service_unit_inline_linux
      return
    fi

    sudo mkdir -p /etc/witness
    sudo cp "$unit_src" "$unit_dst"
    sudo chmod 0644 "$unit_dst"
    sudo systemctl daemon-reload
    sudo systemctl enable witness.service
    sudo systemctl start  witness.service
    ok "Systemd service enabled and started (hardened unit)."
    info "Check status: systemctl status witness"

  elif [[ "$OS" == "macos" ]]; then
    local plist_src="$SCRIPT_DIR/packaging/launchd/ai.sgail.harborlight.witness.plist"
    local plist_dst="/Library/LaunchDaemons/ai.sgail.harborlight.witness.plist"

    if [[ ! -f "$plist_src" ]]; then
      warn "Hardened plist not found at $plist_src — skipping service install."
      return
    fi

    sudo mkdir -p /var/log/witness
    sudo chown _witness:_witness /var/log/witness 2>/dev/null || true
    sudo cp "$plist_src" "$plist_dst"
    sudo chmod 0644 "$plist_dst"
    sudo chown root:wheel "$plist_dst"
    sudo launchctl load -w "$plist_dst"
    ok "LaunchDaemon loaded: $plist_dst"
  else
    warn "Could not detect init system. Start the daemon manually: witness start"
  fi
}

install_service_unit_inline_linux() {
  # Fallback: write a minimal (non-hardened) unit when packaging/ dir is absent.
  sudo tee /etc/systemd/system/witness.service > /dev/null <<'SERVICE'
[Unit]
Description=SGAIL Labs Harborlight Witness
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/witness start
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE
  sudo systemctl daemon-reload
  sudo systemctl enable witness.service
  sudo systemctl start  witness.service
  warn "Installed minimal (non-hardened) systemd unit. Re-run from the full package for full hardening."
}

# ── Master run sequence ───────────────────────────────────────────────────────
run_installer() {
  print_banner
  detect_platform
  verify_checksums
  confirm_install
  choose_install_dir

  echo ""
  info "Installing tools..."

  for tool in "${TOOLS[@]}"; do
    info "Installing $tool..."
    install_tool "$tool"
  done

  update_path

  echo ""
  info "Setting up system user and service..."
  create_witness_user
  install_service_unit

  print_summary
}
