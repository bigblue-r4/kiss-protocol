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

LOG_FILE="/tmp/harborlight-install-$(date +%Y%m%d-%H%M%S).log"

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
  echo "  ║        HARBORLIGHT INSTALLER             ║"
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
    x86_64|amd64) ARCH="x86_64" ;;
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
      echo "# Added by Harborlight installer" >> "$rc"
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
  print_summary
}
